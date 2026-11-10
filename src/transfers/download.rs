use std::collections::VecDeque;
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use reqwest::{
    Method,
    header::{HeaderMap, HeaderValue, RANGE},
};
use sha2::{Digest, Sha256};
use url::Url;
use zeroize::Zeroizing;

use super::{
    claims::Claim,
    control::{Control, RateLimiter},
    verification,
};
use crate::crypto::{chunks, keys, wire};
use crate::error::{Error, Result, poisoned};
use crate::platform::secure_files::file_identity;
use crate::protocol::{
    api::Api,
    metadata::{self, FileInfo},
    ranges::{ByteRange, validate_response},
};
use crate::storage::{
    config::Config,
    transfer_state::{States, TransferState},
};
use crate::terminal::progress::{Progress, Status};

pub struct DownloadOptions {
    pub workers: u32,
    pub verify: bool,
    pub overwrite: bool,
    pub resume: bool,
    pub keep_state: bool,
    pub quota_wait: u64,
    pub quota_attempts: u32,
}

impl DownloadOptions {
    pub fn from_config(
        config: &Config,
        workers: Option<u32>,
        no_verify: bool,
        overwrite: bool,
    ) -> Result<Self> {
        let workers = workers.unwrap_or(config.max_workers);
        if !(1..=64).contains(&workers) {
            return Err(Error::invalid("Workers must be between 1 and 64"));
        }
        Ok(Self {
            workers,
            verify: config.verify_integrity && !no_verify,
            overwrite,
            resume: config.auto_resume,
            keep_state: config.keep_state_files_on_error,
            quota_wait: config.quota_wait_seconds,
            quota_attempts: config.quota_max_wait_loops,
        })
    }
}

#[cfg(test)]
#[path = "download_commit_tests.rs"]
mod commit_tests;
#[cfg(test)]
#[path = "download_open_tests.rs"]
mod open_tests;
#[cfg(test)]
#[path = "download_retry_tests.rs"]
mod retry_tests;
#[cfg(test)]
#[path = "download_space_tests.rs"]
mod space_tests;

fn state_path(directory: &Path, path: &Path) -> PathBuf {
    directory.join(format!(
        "{}.json",
        hex::encode(Sha256::digest(path.to_string_lossy().as_bytes()))
    ))
}

struct Shared {
    api: Api,
    info: FileInfo,
    generation: u64,
    file: File,
    state: TransferState,
    completed: u64,
    error: Option<Error>,
}

pub fn download(
    api: Api,
    info: FileInfo,
    destination: &Path,
    state_directory: &Path,
    options: &DownloadOptions,
    limiter: &RateLimiter,
    progress: &Progress,
    item: usize,
    control: &Control,
) -> Result<PathBuf> {
    download_with_space(
        api,
        info,
        destination,
        state_directory,
        options,
        limiter,
        progress,
        item,
        control,
        crate::platform::secure_files::OutputDirectory::available_space,
        crate::platform::secure_files::OutputDirectory::open_file,
    )
}

fn download_with_space(
    api: Api,
    info: FileInfo,
    destination: &Path,
    state_directory: &Path,
    options: &DownloadOptions,
    limiter: &RateLimiter,
    progress: &Progress,
    item: usize,
    control: &Control,
    available: impl FnOnce(&crate::platform::secure_files::OutputDirectory) -> Result<u64>,
    mut open: impl FnMut(
        &crate::platform::secure_files::OutputDirectory,
        &std::ffi::OsStr,
        bool,
    ) -> Result<File>,
) -> Result<PathBuf> {
    if !(1..=64).contains(&options.workers) {
        return Err(Error::invalid("Download workers must be between 1 and 64"));
    }
    control.checkpoint()?;
    chunks::chunk_count(info.size)?;
    let source_identity = info.source_identity()?;
    let claim = Claim::acquire(destination, options.overwrite, |path| {
        if !options.resume {
            return Ok(false);
        }
        let expected =
            TransferState::new("download", &source_identity, path, info.size, &info.raw_key)?;
        Ok(States::new(state_path(state_directory, path))
            .load()?
            .is_some_and(|state| state.compatible(&expected)))
    })?;
    let states = States::new(state_path(state_directory, &claim.path));
    let fresh = TransferState::new(
        "download",
        &source_identity,
        &claim.path,
        info.size,
        &info.raw_key,
    )?;
    let old = states.load()?;
    if old
        .as_ref()
        .is_some_and(|state| !options.resume || !state.compatible(&fresh))
    {
        return Err(Error::Corrupt(
            "Interrupted state was preserved; move it aside before starting another transfer"
                .into(),
        ));
    }
    let resume = old.is_some();
    if !resume {
        let free = available(&claim.directory)?;
        if free < info.size {
            return Err(Error::protocol(format!(
                "Not enough free space for download: need {} bytes, {free} available",
                info.size
            )));
        }
    }
    let mut state = old.unwrap_or(fresh);
    let key = keys::unpack_file_key(&wire::bytes_to_a32(&info.raw_key))?;
    let staging = if resume {
        std::ffi::OsString::from(
            state
                .staging_name
                .as_deref()
                .ok_or_else(|| Error::Corrupt("Download resume has no staging object".into()))?,
        )
    } else {
        claim.temporary_name()?
    };
    let mut file = match open(&claim.directory, &staging, !resume) {
        Ok(file) => file,
        Err(Error::Io(error)) if resume && error.kind() == std::io::ErrorKind::NotFound => {
            // Publication may have committed before state removal. Prove the exact published object.
            let mut published = open(&claim.directory, &claim.name, false)?;
            if state.staging_identity.as_deref() != Some(&file_identity(&published)?) {
                return Err(Error::integrity(
                    "Resume staging is missing and destination is an unrelated object",
                ));
            }
            verification::verify(&mut published, info.size, &key, control)?;
            states.clear()?;
            progress.status(item, Status::Complete)?;
            return Ok(claim.path.clone());
        }
        Err(error) => return Err(error),
    };
    let identity = file_identity(&file)?;
    if resume {
        if state.staging_identity.as_deref() != Some(&identity) {
            return Err(Error::integrity(
                "Resume staging file was replaced; both objects were preserved",
            ));
        }
        verification::validate_completed(
            &mut file,
            info.size,
            &key,
            &mut state.completed,
            control,
        )?;
    } else {
        // No final pathname is written until on-disk verification succeeds.
        state.staging_name = Some(staging.to_string_lossy().into_owned());
        state.staging_identity = Some(identity.clone());
        file.set_len(info.size)?;
        file.sync_all()?;
    }
    states.save(&state.snapshot()?)?;
    let all: Vec<_> = chunks::iter_chunks(info.size)?.collect();
    let done: u64 = all
        .iter()
        .filter(|chunk| state.completed.contains_key(&chunk.index))
        .map(|c| c.size)
        .sum();
    progress.update(item, done, true)?;
    let pending: Mutex<VecDeque<_>> = Mutex::new(
        all.into_iter()
            .filter(|c| !state.completed.contains_key(&c.index))
            .collect(),
    );
    let shared = Mutex::new(Shared {
        api,
        info,
        generation: 0,
        file,
        state,
        completed: done,
        error: None,
    });
    std::thread::scope(|scope| {
        let mut threads = Vec::new();
        for _ in 0..options.workers {
            threads.push(scope.spawn(|| {
                let run = || -> Result<()> {
                    loop {
                        control.checkpoint()?;
                        if shared.lock().map_err(poisoned)?.error.is_some() {
                            return Ok(());
                        }
                        let Some(chunk) = pending.lock().map_err(poisoned)?.pop_front() else {
                            return Ok(());
                        };
                        fetch_chunk(
                            chunk, &shared, &states, options, limiter, progress, item, control,
                        )?;
                    }
                };
                if let Err(error) = run() {
                    if let Ok(mut state) = shared.lock() {
                        if state.error.is_none() {
                            state.error = Some(error)
                        }
                    }
                }
            }));
        }
        for thread in threads {
            if thread.join().is_err() {
                if let Ok(mut state) = shared.lock() {
                    if state.error.is_none() {
                        state.error = Some(Error::protocol("Download worker was interrupted"));
                    }
                }
            }
        }
    });
    let mut shared = shared.into_inner().map_err(poisoned)?;
    shared.file.sync_all()?;
    states.save(&shared.state.snapshot()?)?;
    let finish = match shared.error.take() {
        Some(error) => Err(error),
        None => (|| {
            control.checkpoint()?;
            shared.state.require_complete()?;
            if options.verify {
                progress.status(item, Status::Verifying)?;
                verification::verify(&mut shared.file, shared.info.size, &key, control)?;
            }
            Ok(())
        })(),
    };
    if let Err(error) = finish {
        drop(shared.file);
        if !options.keep_state {
            let current = claim.directory.open_read(&staging)?;
            if file_identity(&current)? != identity {
                return Err(Error::integrity(
                    "Staging pathname changed; refusing error cleanup",
                ));
            }
            drop(current);
            claim.directory.remove_owned(&staging, &identity)?;
            states.clear()?;
        }
        return Err(error);
    }
    control.checkpoint()?;
    let current = claim.directory.open_read(&staging)?;
    if file_identity(&current)? != identity {
        return Err(Error::integrity(
            "Staging pathname changed before publication",
        ));
    }
    drop(current);
    drop(shared.file);
    claim.publish(&staging, options.overwrite)?;
    claim.directory.sync()?;
    states.clear()?;
    progress.status(item, Status::Complete)?;
    Ok(claim.path.clone())
}

fn commit_download_chunk(
    file: &mut File,
    state: &mut TransferState,
    chunk: chunks::Chunk,
    plain: &[u8],
    mac: [u8; 16],
    states: &States,
    sync: impl FnOnce(&File) -> std::io::Result<()>,
) -> Result<()> {
    file.seek(SeekFrom::Start(chunk.offset))?;
    file.write_all(plain)?;
    sync(file)?;
    state.completed.insert(chunk.index, mac);
    if state.completed.len().is_multiple_of(8) {
        states.save(&state.snapshot()?)?;
    }
    Ok(())
}

fn fetch_chunk(
    chunk: chunks::Chunk,
    shared: &Mutex<Shared>,
    states: &States,
    options: &DownloadOptions,
    limiter: &RateLimiter,
    progress: &Progress,
    item: usize,
    control: &Control,
) -> Result<()> {
    fetch_chunk_with_send(
        chunk,
        shared,
        states,
        options,
        limiter,
        progress,
        item,
        control,
        |transport, url, headers| transport.send(Method::GET, url, headers, None, false),
    )
}

fn fetch_chunk_with_send(
    chunk: chunks::Chunk,
    shared: &Mutex<Shared>,
    states: &States,
    options: &DownloadOptions,
    limiter: &RateLimiter,
    progress: &Progress,
    item: usize,
    control: &Control,
    mut send: impl FnMut(
        &crate::protocol::transport::Transport,
        Url,
        HeaderMap,
    ) -> Result<crate::protocol::transport::Reply>,
) -> Result<()> {
    let range = ByteRange {
        start: chunk.offset,
        end: chunk.end()? - 1,
    };
    let mut attempt = 0u32;
    while attempt < 5 {
        control.checkpoint()?;
        let (transport, url, generation, raw_key, size) = {
            let state = shared.lock().map_err(poisoned)?;
            (
                state.api.transport.clone(),
                state.info.url.clone(),
                state.generation,
                state.info.raw_key.clone(),
                state.info.size,
            )
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            RANGE,
            HeaderValue::from_str(&range.header())
                .map_err(|_| Error::protocol("Invalid chunk Range"))?,
        );
        let result = send(
            &transport,
            Url::parse(&url).map_err(|_| Error::protocol("CDN URL is invalid"))?,
            headers,
        );
        let mut reply = match result {
            Ok(reply) => reply,
            Err(_) if control.is_canceled() => return Err(Error::Canceled),
            Err(error) if attempt < 4 && error.retryable_network() => {
                control.wait(Duration::from_secs((2u64 << attempt).min(30)))?;
                attempt += 1;
                continue;
            }
            Err(error) => return Err(error),
        };
        let status = reply.response.status().as_u16();
        if matches!(status, 403 | 410 | 509) {
            drop(reply);
            control.checkpoint()?;
            if attempt == 4 {
                return Err(Error::Timeout);
            }
            let mut state = shared.lock().map_err(poisoned)?;
            if state.generation == generation {
                let info = state.info.clone();
                state.info.url = if matches!(&info.source, metadata::DownloadSource::Folder) {
                    let routing = state.api.transport.routing.clone();
                    super::quota::retry(options, &routing, control, || {
                        metadata::refresh(&mut state.api, &info)
                    })?
                } else {
                    metadata::refresh(&mut state.api, &info)?
                };
                state.generation += 1;
            }
            attempt += 1;
            continue;
        }
        if status >= 500 && attempt < 4 {
            let _ = reply.malformed();
            drop(reply);
            control.wait(Duration::from_secs((2u64 << attempt).min(30)))?;
            attempt += 1;
            continue;
        }
        let response = (|| {
            validate_response(status, reply.response.headers(), range, size)?;
            let ciphertext = reply.bytes(chunk.size)?;
            if ciphertext.len() as u64 != chunk.size {
                return Err(Error::protocol("CDN chunk body has the wrong byte length"));
            }
            Ok(ciphertext)
        })();
        let ciphertext = match response {
            Ok(bytes) => bytes,
            Err(error) => {
                control.checkpoint()?;
                let _ = reply.malformed();
                if attempt < 4 && error.retryable_network() {
                    drop(reply);
                    control.wait(Duration::from_secs((2u64 << attempt).min(30)))?;
                    attempt += 1;
                    continue;
                }
                return Err(error);
            }
        };
        limiter.acquire(ciphertext.len(), control)?;
        let key = keys::unpack_file_key(&wire::bytes_to_a32(&raw_key))?;
        let plain = Zeroizing::new(wire::ctr_crypt_at_offset(
            key.aes_key.as_slice(),
            &key.nonce,
            chunk.offset,
            &ciphertext,
        )?);
        let mac = chunks::chunk_mac(&plain, key.aes_key.as_slice(), &key.nonce)?;
        reply.credit()?;
        let completed = {
            let mut state = shared.lock().map_err(poisoned)?;
            let Shared {
                file,
                state,
                completed,
                ..
            } = &mut *state;
            commit_download_chunk(file, state, chunk, &plain, mac, states, File::sync_data)?;
            *completed += chunk.size;
            *completed
        };
        progress.update(item, completed, false)?;
        return Ok(());
    }
    Err(Error::Timeout)
}
