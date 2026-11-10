use std::ffi::{OsStr, OsString};
use std::fs::{File, TryLockError};
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::platform::secure_files::OutputDirectory;

pub struct Claim {
    pub directory: OutputDirectory,
    pub name: OsString,
    pub path: PathBuf,
    _lock: File,
}

impl Claim {
    pub fn acquire(
        destination: &Path,
        overwrite: bool,
        resumable: impl Fn(&Path) -> Result<bool>,
    ) -> Result<Self> {
        let destination = if destination.is_absolute() {
            destination.to_owned()
        } else {
            std::env::current_dir()?.join(destination)
        };
        let parent = destination
            .parent()
            .ok_or_else(|| Error::invalid("Destination has no parent"))?;
        let name = destination
            .file_name()
            .ok_or_else(|| Error::invalid("Destination has no filename"))?;
        let directory = OutputDirectory::ensure(parent)?;
        for counter in 0..10_000u32 {
            let candidate = if counter == 0 {
                name.to_owned()
            } else {
                let stem = destination.file_stem().unwrap_or(name).to_string_lossy();
                let extension = destination
                    .extension()
                    .map(|v| format!(".{}", v.to_string_lossy()))
                    .unwrap_or_default();
                OsString::from(format!("{stem} ({counter}){extension}"))
            };
            let path = parent.join(&candidate);
            let mut sidecar = candidate.clone();
            sidecar.push(".mbclaim");
            let lock = match directory.open_file(&sidecar, true) {
                Ok(file) => file,
                Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    directory.open_file(&sidecar, false)?
                }
                Err(error) => return Err(error),
            };
            match lock.try_lock() {
                Ok(()) => (),
                Err(TryLockError::WouldBlock) if overwrite || resumable(&path)? => {
                    return Err(Error::Busy("Destination transfer".into()));
                }
                Err(TryLockError::WouldBlock) => continue,
                Err(TryLockError::Error(error)) => return Err(error.into()),
            }
            match directory.open_read(&candidate) {
                Ok(_) if !overwrite && !resumable(&path)? => continue,
                Ok(_) => (),
                Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => (),
                Err(error) => return Err(error),
            }
            return Ok(Self {
                directory,
                name: candidate,
                path,
                _lock: lock,
            });
        }
        Err(Error::Busy("Destination filenames".into()))
    }

    pub fn open(&self, resume: bool) -> Result<File> {
        if resume {
            self.directory.open_file(&self.name, false)
        } else {
            self.directory.open_file(&self.name, true)
        }
    }

    pub fn temporary_name(&self) -> Result<OsString> {
        Ok(OsString::from(format!(
            ".mb-{}.tmp",
            crate::storage::files::random_id()?
        )))
    }

    pub fn publish(&self, temporary: &OsStr, overwrite: bool) -> Result<()> {
        self.directory.publish(temporary, &self.name, overwrite)
    }
}
// Sidecars stay named after release; unlinking permits two owners of different inodes.
