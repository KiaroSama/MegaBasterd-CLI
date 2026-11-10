use std::collections::VecDeque;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use rand::{TryRng, rngs::SysRng};
use serde_json::json;
use sha2::{Digest, Sha256};
use url::Url;
use zeroize::Zeroizing;

use super::{
    control::{Control, RateLimiter},
    planner::filename,
    upload_chunk::{ChunkRequest, Delivery},
};
use crate::crypto::{chunks, keys, wire};
use crate::error::{Error, Result, poisoned};
use crate::platform::secure_files::{OutputDirectory, file_identity};
use crate::protocol::{
    api::string,
    cloud::{Cloud, first_handle},
    uploads::registration_request,
};
use crate::storage::{
    files::{LockedStore, Store},
    transfer_state::{States, TransferState},
    vault::Vault,
};
use crate::terminal::progress::Progress;

pub struct Uploaded {
    pub handle: String,
    pub name: String,
    pub size: u64,
    pub raw_key: Zeroizing<Vec<u8>>,
    receipt: PathBuf,
    receipt_source: String,
    _lease: Option<LockedStore>,
    _operation: Option<LockedStore>,
}

impl Uploaded {
    /// Fence optional media/share/hooks and reporting across queue or local completion failures.
    pub fn finalize(&self, callback: impl FnOnce() -> Result<()>) -> Result<()> {
        let ownership = self.receipt.with_extension("finalization");
        let _ownership = Store::new(ownership).with_timeout(Duration::ZERO).lock()?;
        let states = States::new(&self.receipt);
        let mut state = states
            .load()?
            .ok_or_else(|| Error::Corrupt("Confirmed upload receipt is missing".into()))?;
        if state.registered_handle.as_deref() != Some(self.handle.as_str())
            || state.source_hash != self.receipt_source
            || state.size != self.size
        {
            return Err(Error::Corrupt(
                "Upload finalization receipt identity changed".into(),
            ));
        }
        if state.finalization_completed {
            return Ok(());
        }
        if state.finalization_started {
            return Err(Error::AmbiguousMutation("upload"));
        }
        state.finalization_started = true;
        state
            .snapshot()
            .and_then(|snapshot| states.save(&snapshot))
            .map_err(|_| Error::AmbiguousMutation("upload"))?;
        if let Err(error) = callback() {
            return Err(if matches!(error, Error::Canceled) {
                Error::Canceled
            } else {
                Error::AmbiguousMutation("upload")
            });
        }
        state.finalization_completed = true;
        state
            .snapshot()
            .and_then(|snapshot| states.save(&snapshot))
            .map_err(|_| Error::AmbiguousMutation("upload"))
    }

    pub fn acknowledge(&self) -> Result<()> {
        States::new(&self.receipt).clear()
    }
}

pub fn confirmed_receipt(
    state: &TransferState,
    material: &[u8],
    name: &str,
    path: &Path,
) -> Result<Uploaded> {
    state.validate()?;
    if material.len() != 24 || state.key_hash != hex::encode(Sha256::digest(&material[..16])) {
        return Err(Error::Corrupt(
            "Upload receipt key identity is invalid".into(),
        ));
    }
    let handle = state
        .registered_handle
        .clone()
        .ok_or(Error::AmbiguousMutation("upload"))?;
    let macs = state.completed.values().copied().collect::<Vec<_>>();
    let mac = chunks::condense_mac(&chunks::combine_chunk_macs(&macs, &material[..16])?)?;
    let raw_key = Zeroizing::new(wire::a32_to_bytes(&keys::pack_file_key(
        &material[..16],
        &material[16..],
        &mac,
    )?));
    Ok(Uploaded {
        handle,
        name: name.to_owned(),
        size: state.size,
        raw_key,
        receipt: path.to_owned(),
        receipt_source: state.source_hash.clone(),
        _lease: None,
        _operation: None,
    })
}

pub fn source_hash(file: &mut File, control: &Control) -> Result<String> {
    let before = file.metadata()?;
    if !before.is_file() {
        return Err(Error::invalid("Upload source is not a regular file"));
    }
    file.seek(SeekFrom::Start(0))?;
    let digest = super::upload_identity::digest(file, control)?;
    let after = file.metadata()?;
    if before.len() != after.len() || before.modified()? != after.modified()? {
        return Err(Error::integrity("Source changed while hashing"));
    }
    Ok(format!(
        "{}:{}:{}:{}",
        file_identity(file)?,
        before.len(),
        before
            .modified()?
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error::invalid("Source modification timestamp is invalid"))?
            .as_nanos(),
        hex::encode(digest)
    ))
}

fn upload_url(cloud: &mut Cloud, size: u64) -> Result<String> {
    let result = cloud.api.request(json!({"a":"u","s":size}), &[])?;
    let raw = string(&result, "p")?;
    let url = Url::parse(raw).map_err(|_| Error::protocol("Upload slot URL is invalid"))?;
    crate::protocol::transport::safe_target(&url)?;
    let host = url.host_str().unwrap_or("").trim_end_matches('.');
    if !(host == "mega.nz"
        || host.ends_with(".mega.nz")
        || host == "mega.co.nz"
        || host.ends_with(".mega.co.nz"))
    {
        return Err(Error::protocol("Upload slot is not on a MEGA storage host"));
    }
    Ok(raw.to_owned())
}

struct Shared {
    file: File,
    state: TransferState,
    done: u64,
    error: Option<Error>,
    expired: bool,
}

impl Shared {
    fn accept(
        &mut self,
        chunk: chunks::Chunk,
        mac: [u8; 16],
        token: Option<String>,
        states: &States,
    ) -> Result<u64> {
        if self.state.size > 0 {
            self.state.completed.insert(chunk.index, mac);
        }
        self.done += chunk.size;
        if self.state.completion_token.is_none() {
            self.state.completion_token = token;
        }
        states.save(&self.state.snapshot()?)?;
        Ok(self.done)
    }
}

#[cfg(test)]
#[path = "upload_acceptance_tests.rs"]
mod acceptance_tests;

pub fn upload(
    cloud: &mut Cloud,
    source: &Path,
    target: &str,
    rename: Option<&str>,
    workers: u32,
    state_directory: &Path,
    vault: &Vault,
    resume: bool,
    operation: Option<&str>,
    limiter: &RateLimiter,
    progress: &Progress,
    item: usize,
    control: &Control,
) -> Result<Uploaded> {
    if !(1..=64).contains(&workers) {
        return Err(Error::invalid("Upload workers must be between 1 and 64"));
    }
    control.checkpoint()?;
    let parent = source
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let source_dir = OutputDirectory::open(parent)?;
    let source_name = source
        .file_name()
        .ok_or_else(|| Error::invalid("Upload source has no filename"))?;
    let mut file = source_dir.open_read(source_name)?;
    let size = file.metadata()?.len();
    chunks::chunk_count(size)?;
    let source_address = std::fs::canonicalize(source)?;
    let name = filename(rename.unwrap_or(&source_name.to_string_lossy()));
    let binding = serde_json::to_string(&json!([
        source_address.to_string_lossy(),
        cloud.session.email.to_lowercase(),
        cloud.session.user_handle,
        target,
        name,
        operation
    ]))?;
    let operation =
        super::upload_operation::bind(state_directory, operation, &source_address, &binding)?;
    let state_name = hex::encode(Sha256::digest(binding.as_bytes()));
    let state_path = state_directory.join(format!("{state_name}.json"));
    let lease = Store::new(state_directory.join(format!("{state_name}.lease")))
        .with_timeout(Duration::ZERO)
        .lock()?;
    let states = States::new(&state_path);
    let identity = source_hash(&mut file, control)?;
    let mut material = Zeroizing::new([0u8; 24]);
    SysRng
        .try_fill_bytes(&mut *material)
        .map_err(|_| Error::protocol("Operating-system randomness is unavailable"))?;
    let mut state = TransferState::new("upload", &binding, &state_path, size, &material[..16])?;
    state.source_identity = Some(identity.clone());
    let context = format!("upload:{state_name}");
    if let Some(previous) = states.load()? {
        if previous.kind != "upload"
            || previous.source_hash != state.source_hash
            || previous.destination != state.destination
        {
            return Err(Error::Corrupt(
                "Interrupted upload state belongs to another transfer".into(),
            ));
        }
        if previous.registration_started && previous.registered_handle.is_none() {
            return Err(Error::AmbiguousMutation("upload"));
        }
        let sealed = previous
            .sealed_upload_key
            .as_deref()
            .ok_or_else(|| Error::Corrupt("Upload state has no sealed key".into()))?;
        let key = vault.open(sealed, context.as_bytes())?;
        if key.len() != 24 {
            return Err(Error::Corrupt("Upload state key has invalid width".into()));
        }
        if previous.key_hash != hex::encode(Sha256::digest(&key[..16])) {
            return Err(Error::Corrupt(
                "Upload state key identity is invalid".into(),
            ));
        }
        let unchanged =
            previous.source_identity.as_deref() == Some(&identity) && previous.size == size;
        if !unchanged && previous.registered_handle.is_some() {
            return Err(Error::Corrupt("Registered upload belongs to changed content; preserve its receipt and check the remote outcome before retrying".into()));
        }
        if previous.registered_handle.is_some() || (resume && unchanged) {
            material.copy_from_slice(&key);
            state = previous;
        } else {
            control.checkpoint()?;
            states.discard_unregistered_upload(&previous)?;
        }
    }
    if state.sealed_upload_key.is_none() {
        state.upload_url = Some(upload_url(cloud, size)?);
        state.sealed_upload_key = Some(vault.seal(&*material, context.as_bytes())?);
        states.save(&state.snapshot()?)?;
    }
    if state.registered_handle.is_some() {
        progress.update(item, size, true)?;
        progress.transferred(item)?;
        let mut uploaded = confirmed_receipt(&state, &*material, &name, &state_path)?;
        uploaded._lease = Some(lease);
        uploaded._operation = operation;
        return Ok(uploaded);
    }
    for refresh in 0..2 {
        let endpoint = state
            .upload_url
            .as_deref()
            .ok_or_else(|| Error::Corrupt("Upload state has no slot URL".into()))?
            .to_owned();
        let mut all: Vec<_> = chunks::iter_chunks(size)?.collect();
        if size == 0 {
            all.push(chunks::Chunk {
                index: 0,
                offset: 0,
                size: 0,
            });
        }
        let done = all
            .iter()
            .filter(|c| state.completed.contains_key(&c.index))
            .map(|c| c.size)
            .sum();
        progress.update(item, done, true)?;
        let pending = Mutex::new(VecDeque::from(
            all.iter()
                .filter(|c| {
                    if size == 0 {
                        state.completion_token.is_none()
                    } else {
                        !state.completed.contains_key(&c.index)
                    }
                })
                .copied()
                .collect::<Vec<_>>(),
        ));
        let shared = Mutex::new(Shared {
            file,
            state,
            done,
            error: None,
            expired: false,
        });
        let transport = cloud.api.transport.clone();
        std::thread::scope(|scope| {
            let mut threads = Vec::new();
            for _ in 0..workers {
                threads.push(scope.spawn(|| {
                    let run = || -> Result<()> {
                        loop {
                            control.checkpoint()?;
                            {
                                let s = shared.lock().map_err(poisoned)?;
                                if s.error.is_some() || s.expired {
                                    return Ok(());
                                }
                            }
                            let Some(chunk) = pending.lock().map_err(poisoned)?.pop_front() else {
                                return Ok(());
                            };
                            let mut plain = Zeroizing::new(vec![0u8; chunk.size as usize]);
                            {
                                let mut s = shared.lock().map_err(poisoned)?;
                                s.file.seek(SeekFrom::Start(chunk.offset))?;
                                s.file.read_exact(&mut plain)?;
                            }
                            let mac = chunks::chunk_mac(&plain, &material[..16], &material[16..])?;
                            let encrypted = wire::ctr_crypt_at_offset(
                                &material[..16],
                                &material[16..],
                                chunk.offset,
                                &plain,
                            )?;
                            let token = match (ChunkRequest {
                                transport: &transport,
                                endpoint: &endpoint,
                                offset: chunk.offset,
                                final_chunk: chunk.end()? == size,
                                ciphertext: &encrypted,
                                limiter,
                                control,
                            })
                            .send()?
                            {
                                Delivery::Accepted(token) => token,
                                Delivery::Expired => {
                                    shared.lock().map_err(poisoned)?.expired = true;
                                    return Ok(());
                                }
                            };
                            let completed = shared
                                .lock()
                                .map_err(poisoned)?
                                .accept(chunk, mac, token, &states)?;
                            progress.update(item, completed, false)?;
                        }
                    };
                    if let Err(error) = run() {
                        if let Ok(mut s) = shared.lock() {
                            if s.error.is_none() {
                                s.error = Some(error);
                            }
                        }
                    }
                }));
            }
            for thread in threads {
                if thread.join().is_err() {
                    if let Ok(mut state) = shared.lock() {
                        if state.error.is_none() {
                            state.error = Some(Error::protocol("Upload worker was interrupted"));
                        }
                    }
                }
            }
        });
        let s = shared.into_inner().map_err(poisoned)?;
        file = s.file;
        state = s.state;
        states.save(&state.snapshot()?)?;
        if let Some(error) = s.error {
            return Err(error);
        }
        if s.expired {
            if refresh == 1 {
                return Err(Error::protocol(
                    "Upload slot expired again after refresh; state was preserved",
                ));
            }
            state.upload_url = Some(upload_url(cloud, size)?);
            state.completed.clear();
            state.completion_token = None;
            states.save(&state.snapshot()?)?;
            continue;
        }
        break;
    }
    let unchanged = (|| {
        if source_hash(&mut file, control)? != identity {
            return Err(Error::integrity(
                "Local file changed while it was being uploaded; no remote node was registered",
            ));
        }
        let mut current = match source_dir.open_read(source_name) {
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::integrity(
                    "Local file disappeared during upload; no remote node was registered",
                ));
            }
            result => result?,
        };
        if file_identity(&current)? != file_identity(&file)?
            || source_hash(&mut current, control)? != identity
        {
            return Err(Error::integrity(
                "Local file changed while it was being uploaded; its source path was replaced",
            ));
        }
        Ok(())
    })();
    if let Err(error) = unchanged {
        if matches!(&error, Error::Integrity(_)) {
            states.discard_unregistered_upload(&state)?;
        }
        return Err(error);
    }
    let macs: Vec<_> = chunks::iter_chunks(size)?
        .map(|chunk| {
            state
                .completed
                .get(&chunk.index)
                .copied()
                .ok_or_else(|| Error::integrity("Upload is missing a completed chunk MAC"))
        })
        .collect::<Result<_>>()?;
    let mac = chunks::condense_mac(&chunks::combine_chunk_macs(&macs, &material[..16])?)?;
    let raw_key = Zeroizing::new(wire::a32_to_bytes(&keys::pack_file_key(
        &material[..16],
        &material[16..],
        &mac,
    )?));
    let token = state
        .completion_token
        .as_deref()
        .ok_or_else(|| Error::protocol("Upload completed without a final token"))?;
    let request = registration_request(
        target,
        &name,
        token,
        &material[..16],
        &raw_key,
        &cloud.session.master_key,
    )?;
    state.registration_started = true;
    states.save(&state.snapshot()?)?;
    let registration = cloud.api.request(request, &[]);
    let result = match registration {
        Err(error @ Error::Mega { .. }) => {
            // A definitive server rejection did not register a node; retry remains safe.
            state.registration_started = false;
            states.save(&state.snapshot()?)?;
            return Err(error);
        }
        result => result?,
    };
    let handle = first_handle(&result).map_err(|_| Error::AmbiguousMutation("upload"))?;
    state.registered_handle = Some(handle.clone());
    // A local failure must leave the pre-send marker/receipt, never authorize another p mutation.
    state
        .snapshot()
        .and_then(|snapshot| states.save(&snapshot))
        .map_err(|_| Error::AmbiguousMutation("upload"))?;
    cloud.invalidate();
    progress
        .transferred(item)
        .map_err(|_| Error::AmbiguousMutation("upload"))?;
    Ok(Uploaded {
        handle,
        name,
        size,
        raw_key,
        receipt: state_path,
        receipt_source: state.source_hash.clone(),
        _lease: Some(lease),
        _operation: operation,
    })
}
