use std::ffi::{OsStr, OsString};
use std::fs::{File, TryLockError};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rand::{TryRng, rngs::SysRng};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::platform::secure_files::PrivateDirectory;

#[cfg(test)]
#[path = "file_commit_tests.rs"]
mod commit_tests;

pub const STORE_VERSION: u64 = 2;
pub const MAX_STORE_BYTES: u64 = 64 * 1024 * 1024;

pub struct Store {
    path: PathBuf,
    timeout: Duration,
}

pub struct LockedStore {
    directory: PrivateDirectory,
    name: OsString,
    _lock: File,
}

struct PendingWrite<'a> {
    directory: &'a PrivateDirectory,
    name: &'a OsStr,
    pending: bool,
}

impl PendingWrite<'_> {
    fn cleanup(&mut self) -> Result<()> {
        if self.pending {
            match self.directory.remove(self.name) {
                Ok(()) => (),
                Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => (),
                Err(error) => return Err(error),
            }
            self.pending = false;
        }
        Ok(())
    }
}

impl Drop for PendingWrite<'_> {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

pub fn random_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    SysRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| Error::protocol("Operating-system randomness is unavailable"))?;
    Ok(hex::encode(bytes))
}

pub fn read_bounded(file: &File, maximum: u64) -> Result<Zeroizing<Vec<u8>>> {
    if file.metadata()?.len() > maximum {
        return Err(Error::Corrupt(
            "Saved file exceeds its size limit".to_owned(),
        ));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    Read::take(file, maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(Error::Corrupt(
            "Saved file exceeds its size limit".to_owned(),
        ));
    }
    Ok(bytes)
}

impl Store {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            timeout: Duration::from_secs(10),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Diagnostic snapshot only: never use this to authorize a mutation or usable settings.
    pub(super) fn diagnostic_bytes(&self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| Error::invalid("Store needs a parent directory"))?;
        let name = self
            .path
            .file_name()
            .ok_or_else(|| Error::invalid("Store needs a filename"))?;
        let directory = PrivateDirectory::open(parent)?;
        read_private_bytes(&directory, name)
    }

    pub fn lock(&self) -> Result<LockedStore> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| Error::invalid("Store needs a parent directory"))?;
        let name = self
            .path
            .file_name()
            .ok_or_else(|| Error::invalid("Store needs a filename"))?
            .to_owned();
        let directory = PrivateDirectory::ensure(parent)?;
        let mut sidecar = name.clone();
        sidecar.push(".lock");
        let lock = match directory.open_private(&sidecar, true) {
            Ok(file) => file,
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                directory.open_private(&sidecar, false)?
            }
            Err(error) => return Err(error),
        };
        let deadline = Instant::now() + self.timeout;
        loop {
            match lock.try_lock() {
                Ok(()) => break,
                Err(TryLockError::Error(error)) => return Err(error.into()),
                Err(TryLockError::WouldBlock) if Instant::now() >= deadline => {
                    return Err(Error::Busy(
                        "Saved-data lock; retry when the other operation finishes".into(),
                    ));
                }
                Err(TryLockError::WouldBlock) => {
                    // File locks have no portable readiness event. Retry only inside the deadline.
                    std::thread::sleep(
                        Duration::from_millis(25)
                            .min(deadline.saturating_duration_since(Instant::now())),
                    );
                }
            }
        }
        Ok(LockedStore {
            directory,
            name,
            _lock: lock,
        })
    }
}

fn retryable_replace(error: &std::io::Error) -> bool {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{ERROR_LOCK_VIOLATION, ERROR_SHARING_VIOLATION};
        if matches!(error.raw_os_error(), Some(code) if code == ERROR_SHARING_VIOLATION as i32 || code == ERROR_LOCK_VIOLATION as i32)
        {
            return true;
        }
    }
    error.kind() == std::io::ErrorKind::PermissionDenied
}

fn read_private_bytes(
    directory: &PrivateDirectory,
    name: &OsStr,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    match directory.open_private(name, false) {
        Ok(file) => Ok(Some(read_bounded(&file, MAX_STORE_BYTES)?)),
        Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

pub(super) fn decode_document<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let value = super::document_json::parse(bytes)
        .map_err(|_| Error::Corrupt("Saved file is not valid UTF-8 JSON".into()))?;
    let object = value
        .as_object()
        .ok_or_else(|| Error::Corrupt("Saved document is not an object".into()))?;
    let version = object.get("version").and_then(Value::as_u64);
    if let Some(version) = version.filter(|version| *version > STORE_VERSION) {
        return Err(Error::Corrupt(format!(
            "Saved format version {version} is newer than supported version {STORE_VERSION}; preserve the file"
        )));
    }
    if version != Some(STORE_VERSION) {
        return Err(Error::Corrupt(
            "Saved format is unsupported; do not reset a newer file".into(),
        ));
    }
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "version" | "data"))
    {
        return Err(Error::Corrupt(
            "Saved envelope has unsupported fields".into(),
        ));
    }
    let data = object
        .get("data")
        .ok_or_else(|| Error::Corrupt("Saved document has no data".into()))?;
    serde_json::from_value(data.clone())
        .map_err(|_| Error::Corrupt("Saved data has an invalid structure".into()))
}

impl LockedStore {
    pub fn bytes(&self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        read_private_bytes(&self.directory, &self.name)
    }

    pub fn load<T: DeserializeOwned>(&self) -> Result<Option<T>> {
        self.bytes()?
            .map(|bytes| decode_document(&bytes))
            .transpose()
    }

    pub fn save<T: Serialize>(&self, data: &T) -> Result<()> {
        let data = serde_json::to_value(data)?;
        let payload = Zeroizing::new(serde_json::to_vec(
            &serde_json::json!({"version": STORE_VERSION, "data": data}),
        )?);
        self.write_bytes(&payload)
    }

    pub fn write_bytes(&self, payload: &[u8]) -> Result<()> {
        self.write_bytes_with_replace(payload, |directory, from, to| directory.replace(from, to))
    }

    pub(super) fn write_bytes_with_replace(
        &self,
        payload: &[u8],
        replace: impl FnMut(&PrivateDirectory, &OsStr, &OsStr) -> Result<()>,
    ) -> Result<()> {
        self.write_bytes_with_replace_and_wait(payload, replace, std::thread::sleep)
    }

    fn write_bytes_with_replace_and_wait(
        &self,
        payload: &[u8],
        mut replace: impl FnMut(&PrivateDirectory, &OsStr, &OsStr) -> Result<()>,
        mut wait: impl FnMut(Duration),
    ) -> Result<()> {
        if payload.len() as u64 > MAX_STORE_BYTES {
            return Err(Error::invalid("Saved data exceeds its size limit"));
        }
        let temporary = OsString::from(format!(".mb-{}.tmp", random_id()?));
        let mut stage = PendingWrite {
            directory: &self.directory,
            name: &temporary,
            pending: false,
        };
        // Declared after the guard so an unwind closes the writer before Windows cleanup.
        let mut file = self.directory.open_private(&temporary, true)?;
        stage.pending = true;
        let result = (|| {
            file.write_all(payload)?;
            file.flush()?;
            file.sync_all()?;
            drop(file);
            for attempt in 0..5 {
                match replace(&self.directory, &temporary, &self.name) {
                    Ok(()) => break,
                    Err(Error::Io(error)) if attempt < 4 && retryable_replace(&error) => {
                        wait(Duration::from_millis(50 * (attempt + 1)));
                    }
                    Err(error) => return Err(error),
                }
            }
            stage.pending = false;
            self.directory.sync().map(|_| ())
        })();
        if result.is_err() && stage.cleanup().is_err() {
            return Err(Error::Corrupt(
                "Saved-data commit and staging cleanup failed; preserve the saved files and inspect them before retrying".into(),
            ));
        }
        result
    }

    pub fn preserve(&self) -> Result<OsString> {
        self.preserve_with_write(|file, bytes| {
            file.write_all(bytes)?;
            Ok(())
        })
    }

    fn preserve_with_write(
        &self,
        write: impl FnOnce(&mut File, &[u8]) -> Result<()>,
    ) -> Result<OsString> {
        use sha2::{Digest, Sha256};

        let bytes = self
            .bytes()?
            .ok_or_else(|| Error::invalid("No saved file to preserve"))?;
        let mut base = self.name.clone();
        base.push(format!(".corrupt-{}", hex::encode(Sha256::digest(&*bytes))));
        let mut write = Some(write);
        for attempt in 0..32 {
            let mut backup = base.clone();
            if attempt != 0 {
                backup.push(format!("-{attempt}"));
            }
            match self.directory.open_private(&backup, true) {
                Ok(mut file) => {
                    let writer = write.take().ok_or_else(|| {
                        Error::Corrupt("Recovery writer was already consumed".into())
                    })?;
                    let result = writer(&mut file, &bytes).and_then(|()| {
                        file.flush()?;
                        file.sync_all()?;
                        Ok(())
                    });
                    if let Err(error) = result {
                        drop(file);
                        if self.directory.remove(&backup).is_err() {
                            return Err(Error::Corrupt(
                                "Recovery copy write failed and its incomplete file could not be removed; original saved data was not changed".into(),
                            ));
                        }
                        return Err(error);
                    }
                }
                Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let file = self.directory.open_private(&backup, false)?;
                    if read_bounded(&file, MAX_STORE_BYTES)?.as_slice() != bytes.as_slice() {
                        continue;
                    }
                    file.sync_all()?;
                }
                Err(error) => return Err(error),
            }
            self.directory.sync().map(|_| ())?;
            return Ok(backup);
        }
        Err(Error::Corrupt(
            "Recovery copy names are occupied; original saved data was not changed".into(),
        ))
    }

    pub fn remove(&self) -> Result<()> {
        match self.directory.remove(OsStr::new(&self.name)) {
            Ok(()) => self.directory.sync().map(|_| ()),
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}
