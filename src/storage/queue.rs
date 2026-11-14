// SPDX-License-Identifier: GPL-3.0-or-later
//! Fresh native queue. Transactions reload; execution claims retain a separate OS lock.
use std::{
    collections::HashSet,
    ffi::OsString,
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use chrono::{DateTime, Utc};
use rand::{TryRng, rngs::SysRng};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::files::{LockedStore, STORE_VERSION, Store, random_id, read_bounded};
use crate::{
    crypto::wire::{b64_url_decode, b64_url_encode},
    error::{Error, Result},
    platform::secure_files::PrivateDirectory,
    terminal::redaction,
};

pub const LEASE_SECONDS: i64 = 300;
pub const MAX_ITEMS: usize = 10_000;
const MAX_PAYLOAD: usize = 1024 * 1024;
const MAGIC: &[u8; 4] = b"MBQ2";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobType {
    Download,
    Upload,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    Pending,
    Active,
    Done,
    Failed,
    Canceled,
    Interrupted,
}
impl JobStatus {
    pub fn terminal(self) -> bool {
        matches!(self, Self::Done | Self::Failed | Self::Canceled)
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Done => "done",
            Self::Failed => "failed",
            Self::Canceled => "canceled",
            Self::Interrupted => "interrupted",
        }
    }
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct QueuePayload {
    pub source: String,
    pub destination: String,
    pub account: Option<String>,
    pub password: Option<String>,
    pub error: Option<String>,
}
impl QueuePayload {
    fn validate(&self) -> Result<()> {
        let fields = [&self.source, &self.destination];
        if self.source.trim().is_empty()
            || fields.iter().any(|v| v.contains('\0'))
            || fields.iter().any(|v| v.len() > MAX_PAYLOAD / 4)
            || [&self.account, &self.password, &self.error]
                .iter()
                .any(|v| v.as_ref().is_some_and(|v| v.len() > MAX_PAYLOAD / 4))
        {
            return Err(Error::invalid(
                "Queue payload has blank, oversized or invalid fields",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueItem {
    pub id: String,
    pub kind: JobType,
    pub size: u64,
    pub status: JobStatus,
    pub created_iso: String,
    pub finished_iso: Option<String>,
    pub run_id: Option<String>,
    pub heartbeat_iso: Option<String>,
    pub lease_epoch: u64,
    pub enc_payload: String,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct QueueData {
    items: Vec<QueueItem>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u64,
    data: QueueData,
}

pub struct Queue {
    store: Store,
}
/// Drop only after the real executor and its workers stop. The sidecar is never unlinked.
pub struct Claim {
    pub item: QueueItem,
    _ownership: LockedStore,
}

fn corrupt(message: &str) -> Error {
    Error::Corrupt(message.into())
}
fn lease_lost() -> Error {
    Error::Busy("Queue lease was lost or expired; stale writer refused".into())
}
fn timestamp(value: &str) -> Result<DateTime<Utc>> {
    let parsed = DateTime::parse_from_rfc3339(value)
        .map_err(|_| corrupt("Queue timestamp is not timezone-aware RFC3339"))?;
    if parsed.offset().local_minus_utc() != 0 {
        return Err(corrupt("Queue timestamps must be UTC"));
    }
    Ok(parsed.with_timezone(&Utc))
}
fn valid_run(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|v| v.is_ascii_alphanumeric() || matches!(v, b'-' | b'_'))
}

impl Queue {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            store: Store::new(path),
        }
    }
    pub fn path(&self) -> &Path {
        self.store.path()
    }
    pub(crate) fn with_lock_timeout(mut self, timeout: Duration) -> Self {
        self.store = self.store.with_timeout(timeout);
        self
    }
    fn sibling(&self, suffix: &str) -> Result<PathBuf> {
        let mut name = self
            .path()
            .file_name()
            .ok_or_else(|| Error::invalid("Queue needs a filename"))?
            .to_os_string();
        name.push(suffix);
        Ok(self.path().with_file_name(name))
    }
    fn execution_lock(&self, id: &str) -> Result<LockedStore> {
        Store::new(self.sibling(&format!(".job-{id}"))?)
            .with_timeout(Duration::ZERO)
            .lock()
    }
    fn key(&self, create: bool) -> Result<Zeroizing<Vec<u8>>> {
        let path = self.sibling(".key")?;
        let directory = PrivateDirectory::ensure(
            path.parent()
                .ok_or_else(|| Error::invalid("Queue needs a parent directory"))?,
        )?;
        let name = path
            .file_name()
            .ok_or_else(|| Error::invalid("Queue key needs a filename"))?;
        let file = match directory.open_private(name, false) {
            Ok(file) => file,
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound && create => {
                let mut key = Zeroizing::new(vec![0u8; 32]);
                SysRng
                    .try_fill_bytes(&mut key)
                    .map_err(|_| Error::protocol("Operating-system randomness is unavailable"))?;
                match directory.open_private(name, true) {
                    Ok(mut file) => {
                        file.write_all(&key)?;
                        file.flush()?;
                        file.sync_all()?;
                        directory.sync()?;
                        return Ok(key);
                    }
                    Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        directory.open_private(name, false)?
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(corrupt(
                    "Queue key is missing; restore it before using encrypted jobs",
                ));
            }
            Err(error) => return Err(error),
        };
        let key = read_bounded(&file, 32)?;
        if key.len() != 32 {
            return Err(corrupt("Queue key has invalid width; it was not replaced"));
        }
        Ok(key)
    }
    fn aad(item: &QueueItem) -> String {
        format!("megabasterd-cli/native-queue/2/{}/{:?}", item.id, item.kind)
    }
    fn seal(item: &QueueItem, payload: &QueuePayload, key: &[u8]) -> Result<String> {
        payload.validate()?;
        let plaintext = Zeroizing::new(serde_json::to_vec(payload)?);
        if plaintext.len() > MAX_PAYLOAD {
            return Err(Error::invalid("Queue payload exceeds its size limit"));
        }
        let cipher =
            Aes256Gcm::new_from_slice(key).map_err(|_| corrupt("Queue key has invalid width"))?;
        let mut nonce = [0u8; 12];
        SysRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| Error::protocol("Operating-system randomness is unavailable"))?;
        let ciphertext = cipher
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: &plaintext,
                    aad: Self::aad(item).as_bytes(),
                },
            )
            .map_err(|_| Error::protocol("Queue encryption failed"))?;
        let mut output = MAGIC.to_vec();
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext);
        Ok(b64_url_encode(&output))
    }
    fn decode(item: &QueueItem, key: &[u8]) -> Result<QueuePayload> {
        if item.enc_payload.len() > (MAX_PAYLOAD + 32).div_ceil(3) * 4
            || !item
                .enc_payload
                .bytes()
                .all(|v| v.is_ascii_alphanumeric() || matches!(v, b'-' | b'_'))
        {
            return Err(corrupt("Queue ciphertext has invalid encoding or size"));
        }
        let raw = b64_url_decode(&item.enc_payload)
            .map_err(|_| corrupt("Queue ciphertext has invalid encoding"))?;
        if b64_url_encode(&raw) != item.enc_payload
            || raw.len() < 32
            || raw.len() > MAX_PAYLOAD + 32
            || &raw[..4] != MAGIC
        {
            return Err(corrupt("Queue ciphertext format or size is unsupported"));
        }
        let nonce: [u8; 12] = raw[4..16]
            .try_into()
            .map_err(|_| corrupt("Queue nonce has invalid width"))?;
        let cipher =
            Aes256Gcm::new_from_slice(key).map_err(|_| corrupt("Queue key has invalid width"))?;
        let plaintext = Zeroizing::new(cipher.decrypt(&Nonce::from(nonce), Payload { msg: &raw[16..], aad: Self::aad(item).as_bytes() })
            .map_err(|_| corrupt("Queue payload authentication failed; restore the original key and ciphertext"))?);
        let payload: QueuePayload = serde_json::from_slice(&plaintext)
            .map_err(|_| corrupt("Queue payload is not valid UTF-8 JSON"))?;
        payload
            .validate()
            .map_err(|_| corrupt("Queue payload has invalid fields"))?;
        Ok(payload)
    }
    fn read(locked: &LockedStore) -> Result<QueueData> {
        let Some(bytes) = locked.bytes()? else {
            return Ok(QueueData::default());
        };
        let envelope: Envelope = serde_json::from_slice(&bytes)
            .map_err(|_| corrupt("Queue schema or UTF-8 JSON is invalid"))?;
        if envelope.version != STORE_VERSION {
            return Err(corrupt(
                "Queue format is unsupported; do not reset a newer file",
            ));
        }
        let data = envelope.data;
        if data.items.len() > MAX_ITEMS {
            return Err(corrupt("Queue exceeds its item limit"));
        }
        let mut ids = HashSet::new();
        for item in &data.items {
            if item.id.len() != 32
                || !item
                    .id
                    .bytes()
                    .all(|v| v.is_ascii_digit() || matches!(v, b'a'..=b'f'))
                || !ids.insert(&item.id)
                || item.enc_payload.len() > (MAX_PAYLOAD + 32).div_ceil(3) * 4
                || item.enc_payload.len() < 43
                || !item
                    .enc_payload
                    .bytes()
                    .all(|v| v.is_ascii_alphanumeric() || matches!(v, b'-' | b'_'))
            {
                return Err(corrupt(
                    "Queue has duplicate IDs or invalid encrypted entries",
                ));
            }
            let created = timestamp(&item.created_iso)?;
            if item
                .finished_iso
                .as_deref()
                .map(timestamp)
                .transpose()?
                .is_some_and(|at| at < created)
                || item.run_id.as_deref().is_some_and(|v| !valid_run(v))
                || item.run_id.is_some() != item.heartbeat_iso.is_some()
                || (item.status != JobStatus::Active && item.run_id.is_some())
                || (item.status == JobStatus::Active && item.lease_epoch == 0)
                || item.status.terminal() != item.finished_iso.is_some()
            {
                return Err(corrupt(
                    "Queue lease or terminal-state fields are inconsistent",
                ));
            }
            if let Some(beat) = &item.heartbeat_iso {
                timestamp(beat)?;
            }
        }
        Ok(data)
    }
    fn load(&self, locked: &LockedStore) -> Result<QueueData> {
        let result = (|| {
            let data = Self::read(locked)?;
            if !data.items.is_empty() {
                let key = self.key(false)?;
                // ponytail: bounded O(n) authentication per transaction; index only if measured necessary.
                for item in &data.items {
                    Self::decode(item, &key)?;
                }
            }
            Ok(data)
        })();
        match result {
            Err(Error::Corrupt(reason)) => {
                if locked.bytes()?.is_some() {
                    self.preserve(locked).map_err(|_| {
                        corrupt(
                            "Queue is unusable; original preserved but backup could not be written",
                        )
                    })?;
                }
                Err(Error::Corrupt(reason))
            }
            other => other,
        }
    }
    pub fn list(&self) -> Result<Vec<QueueItem>> {
        Ok(self.load(&self.store.lock()?)?.items)
    }
    pub fn payload(&self, item: &QueueItem) -> Result<QueuePayload> {
        if item.enc_payload.len() > (MAX_PAYLOAD + 32).div_ceil(3) * 4 {
            return Err(corrupt("Queue payload exceeds its size limit"));
        }
        Self::decode(item, &self.key(false)?)
    }
    pub fn add(&self, kind: JobType, payload: &QueuePayload) -> Result<String> {
        payload.validate()?;
        let locked = self.store.lock()?;
        let mut data = self.load(&locked)?;
        if data.items.len() >= MAX_ITEMS {
            return Err(Error::invalid("Queue is full"));
        }
        if payload.error.is_some() {
            return Err(Error::invalid(
                "A new queue job cannot carry an execution error",
            ));
        }
        let key = self.key(data.items.is_empty())?;
        let mut item = QueueItem {
            id: random_id()?,
            kind,
            size: 0,
            status: JobStatus::Pending,
            created_iso: Utc::now().to_rfc3339(),
            finished_iso: None,
            run_id: None,
            heartbeat_iso: None,
            lease_epoch: 0,
            enc_payload: String::new(),
        };
        if data.items.iter().any(|existing| existing.id == item.id) {
            return Err(Error::protocol(
                "Queue ID collision; retry the add operation",
            ));
        }
        item.enc_payload = Self::seal(&item, payload, &key)?;
        let id = item.id.clone();
        data.items.push(item);
        locked.save(&data)?;
        Ok(id)
    }
    fn live(item: &QueueItem, now: DateTime<Utc>) -> Result<bool> {
        Ok(item.status == JobStatus::Active
            && item.run_id.is_some()
            && item
                .heartbeat_iso
                .as_deref()
                .map(timestamp)
                .transpose()?
                .is_some_and(|beat| {
                    now.signed_duration_since(beat).num_milliseconds() <= LEASE_SECONDS * 1000
                }))
    }
    fn recover_locked(&self, data: &mut QueueData, now: DateTime<Utc>) -> Result<Vec<String>> {
        let mut recovered = Vec::new();
        for item in &mut data.items {
            if item.status != JobStatus::Active || Self::live(item, now)? {
                continue;
            }
            // Timestamp expiry cannot steal from a suspended callback that still holds its OS lock.
            match self.execution_lock(&item.id) {
                Ok(_ownership) => {
                    item.status = JobStatus::Interrupted;
                    item.run_id = None;
                    item.heartbeat_iso = None;
                    item.finished_iso = None;
                    recovered.push(item.id.clone());
                }
                Err(Error::Busy(_)) => (),
                Err(error) => return Err(error),
            }
        }
        Ok(recovered)
    }
    pub fn recover_interrupted(&self) -> Result<Vec<String>> {
        let locked = self.store.lock()?;
        let mut data = self.load(&locked)?;
        let recovered = self.recover_locked(&mut data, Utc::now())?;
        if !recovered.is_empty() {
            locked.save(&data)?;
        }
        Ok(recovered)
    }
    pub fn claim_next(&self, run_id: &str) -> Result<Option<Claim>> {
        if !valid_run(run_id) {
            return Err(Error::invalid("Queue run ID is invalid"));
        }
        let locked = self.store.lock()?;
        let mut data = self.load(&locked)?;
        let now = Utc::now();
        let recovered = self.recover_locked(&mut data, now)?;
        for item in &mut data.items {
            if !matches!(item.status, JobStatus::Pending | JobStatus::Interrupted) {
                continue;
            }
            let ownership = match self.execution_lock(&item.id) {
                Ok(lock) => lock,
                Err(Error::Busy(_)) => continue,
                Err(error) => return Err(error),
            };
            item.lease_epoch = item
                .lease_epoch
                .checked_add(1)
                .ok_or_else(|| corrupt("Queue lease generation overflow"))?;
            item.status = JobStatus::Active;
            item.run_id = Some(run_id.to_owned());
            item.heartbeat_iso = Some(now.to_rfc3339());
            item.finished_iso = None;
            let item = item.clone();
            locked.save(&data)?;
            return Ok(Some(Claim {
                item,
                _ownership: ownership,
            }));
        }
        if !recovered.is_empty() {
            locked.save(&data)?;
        }
        Ok(None)
    }
    fn owns(current: &QueueItem, lease: &QueueItem) -> Result<bool> {
        Ok(current.id == lease.id
            && current.lease_epoch == lease.lease_epoch
            && current.run_id == lease.run_id
            && Self::live(current, Utc::now())?)
    }
    pub fn touch(&self, lease: &QueueItem) -> Result<bool> {
        let locked = self.store.lock()?;
        let mut data = self.load(&locked)?;
        let Some(item) = data.items.iter_mut().find(|v| v.id == lease.id) else {
            return Ok(false);
        };
        if !Self::owns(item, lease)? {
            return Ok(false);
        }
        item.heartbeat_iso = Some(Utc::now().to_rfc3339());
        locked.save(&data)?;
        Ok(true)
    }
    pub fn finish(&self, lease: &QueueItem, status: JobStatus, error: Option<&str>) -> Result<()> {
        if !matches!(
            status,
            JobStatus::Done | JobStatus::Failed | JobStatus::Canceled | JobStatus::Interrupted
        ) {
            return Err(Error::invalid("Queue completion status is invalid"));
        }
        let locked = self.store.lock()?;
        let mut data = self.load(&locked)?;
        let item = data
            .items
            .iter_mut()
            .find(|v| v.id == lease.id)
            .ok_or_else(lease_lost)?;
        if !Self::owns(item, lease)? {
            return Err(lease_lost());
        }
        let key = self.key(false)?;
        let mut payload = Self::decode(item, &key)?;
        // Identity redaction covers arbitrary passwords echoed by an external executor, not only patterns.
        let mut message = error.unwrap_or("").to_owned();
        if let Some(password) = payload.password.as_deref().filter(|v| !v.is_empty()) {
            message = message.replace(password, redaction::REDACTED);
        }
        payload.error = error.map(|_| redaction::text(&message));
        message.zeroize();
        item.enc_payload = Self::seal(item, &payload, &key)?;
        item.status = status;
        let finished = Utc::now().max(timestamp(&item.created_iso)?);
        item.finished_iso = status.terminal().then(|| finished.to_rfc3339());
        item.run_id = None;
        item.heartbeat_iso = None;
        locked.save(&data)
    }
    pub fn retry(&self, id: &str) -> Result<bool> {
        Ok(self.retry_items(Some(id))? != 0)
    }
    pub fn retry_all(&self) -> Result<usize> {
        self.retry_items(None)
    }
    fn retry_items(&self, id: Option<&str>) -> Result<usize> {
        let locked = self.store.lock()?;
        let mut data = self.load(&locked)?;
        let mut changed = 0;
        let key = if data.items.is_empty() {
            None
        } else {
            Some(self.key(false)?)
        };
        for item in &mut data.items {
            if id.is_some_and(|id| item.id != id)
                || !matches!(
                    item.status,
                    JobStatus::Failed | JobStatus::Canceled | JobStatus::Interrupted
                )
            {
                continue;
            }
            let key = key
                .as_deref()
                .ok_or_else(|| corrupt("Queue key is unavailable"))?;
            let mut payload = Self::decode(item, key)?;
            payload.error = None;
            item.enc_payload = Self::seal(item, &payload, key)?;
            item.status = JobStatus::Pending;
            item.finished_iso = None;
            item.run_id = None;
            item.heartbeat_iso = None;
            changed += 1;
        }
        if changed != 0 {
            locked.save(&data)?;
        }
        Ok(changed)
    }
    pub fn remove(&self, id: &str) -> Result<bool> {
        let locked = self.store.lock()?;
        let mut data = self.load(&locked)?;
        let Some(index) = data.items.iter().position(|v| v.id == id) else {
            return Ok(false);
        };
        let _ownership = self.execution_lock(&data.items[index].id)?;
        data.items.remove(index);
        locked.save(&data)?;
        Ok(true)
    }
    pub fn clear_done(&self) -> Result<usize> {
        let locked = self.store.lock()?;
        let mut data = self.load(&locked)?;
        for item in data
            .items
            .iter()
            .filter(|v| matches!(v.status, JobStatus::Done | JobStatus::Canceled))
        {
            // The queue transaction lock prevents a new claim while each ownership lock is checked.
            let _ownership = self.execution_lock(&item.id)?;
        }
        let before = data.items.len();
        data.items
            .retain(|v| !matches!(v.status, JobStatus::Done | JobStatus::Canceled));
        let removed = before - data.items.len();
        if removed != 0 {
            locked.save(&data)?;
        }
        Ok(removed)
    }
    fn preserve(&self, locked: &LockedStore) -> Result<OsString> {
        let bytes = locked
            .bytes()?
            .ok_or_else(|| Error::invalid("No queue file to preserve"))?;
        // Unsupported versions are preserved at their original path; never duplicate untrusted private fields.
        if serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|v| v.get("version").and_then(serde_json::Value::as_u64))
            .is_some_and(|v| v != STORE_VERSION)
        {
            return self
                .path()
                .file_name()
                .map(OsString::from)
                .ok_or_else(|| Error::invalid("Queue needs a filename"));
        }
        locked.preserve()
    }
    /// Explicit discard only; unknown versions are never overwritten. Every discarded file is backed up.
    pub fn reset(&self) -> Result<Option<OsString>> {
        let locked = self.store.lock()?;
        let Some(raw) = locked.bytes()? else {
            locked.save(&QueueData::default())?;
            return Ok(None);
        };
        if serde_json::from_slice::<serde_json::Value>(&raw)
            .ok()
            .and_then(|v| v.get("version").and_then(serde_json::Value::as_u64))
            .is_some_and(|v| v != STORE_VERSION)
        {
            return Err(corrupt(
                "Unsupported queue version; restore a supported file rather than reset it",
            ));
        }
        match Self::read(&locked) {
            Ok(data) => {
                for item in &data.items {
                    let _ownership = self.execution_lock(&item.id)?;
                }
            }
            Err(Error::Corrupt(_)) => (),
            Err(error) => return Err(error),
        }
        let backup = self.preserve(&locked)?;
        locked.save(&QueueData::default())?;
        Ok(Some(backup))
    }
}
