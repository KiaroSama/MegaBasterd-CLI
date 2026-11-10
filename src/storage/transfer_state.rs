use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::files::Store;
use crate::crypto::chunks::chunk_count;
use crate::error::{Error, Result};

#[cfg(test)]
#[path = "state_lock_tests.rs"]
mod lock_tests;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferState {
    pub kind: String,
    pub source_hash: String,
    pub destination: String,
    pub size: u64,
    pub key_hash: String,
    pub completed: BTreeMap<usize, [u8; 16]>,
    #[serde(default)]
    pub revision: u64,
    pub staging_name: Option<String>,
    pub staging_identity: Option<String>,
    pub registration_started: bool,
    #[serde(default)]
    pub registered_handle: Option<String>,
    #[serde(default)]
    pub finalization_started: bool,
    #[serde(default)]
    pub finalization_completed: bool,
    pub upload_url: Option<String>,
    pub sealed_upload_key: Option<String>,
    pub completion_token: Option<String>,
    pub source_identity: Option<String>,
}

impl TransferState {
    pub fn new(
        kind: &str,
        source: &str,
        destination: &Path,
        size: u64,
        raw_key: &[u8],
    ) -> Result<Self> {
        chunk_count(size)?;
        Ok(Self {
            kind: kind.to_owned(),
            source_hash: hex::encode(Sha256::digest(source.as_bytes())),
            destination: destination.to_string_lossy().into_owned(),
            size,
            key_hash: hex::encode(Sha256::digest(raw_key)),
            completed: BTreeMap::new(),
            revision: 0,
            staging_name: None,
            staging_identity: None,
            registration_started: false,
            registered_handle: None,
            finalization_started: false,
            finalization_completed: false,
            upload_url: None,
            sealed_upload_key: None,
            completion_token: None,
            source_identity: None,
        })
    }

    /// Caller holds its transfer-owner lock while claiming the next snapshot.
    pub fn snapshot(&mut self) -> Result<Self> {
        let revision = self.revision.checked_add(1).ok_or_else(|| {
            Error::Corrupt("Transfer snapshot revision is exhausted; preserve its state".into())
        })?;
        self.validate()?;
        self.revision = revision;
        Ok(self.clone())
    }

    pub fn validate(&self) -> Result<()> {
        let count = chunk_count(self.size).map_err(|_| {
            Error::Corrupt("Saved transfer size exceeds its supported bound".into())
        })?;
        if !matches!(self.kind.as_str(), "download" | "upload")
            || self.destination.is_empty()
            || self.source_hash.len() != 64
            || self.key_hash.len() != 64
            || self.completed.keys().any(|index| *index >= count)
            || hex::decode(&self.source_hash).is_err()
            || hex::decode(&self.key_hash).is_err()
            || self
                .completion_token
                .as_deref()
                .is_some_and(|token| crate::protocol::uploads::validate_token(token).is_err())
        {
            return Err(Error::Corrupt(
                "Transfer state has invalid identity or chunk coverage".into(),
            ));
        }
        if let Some(name) = &self.staging_name {
            crate::platform::secure_files::validate_name(std::ffi::OsStr::new(name))
                .map_err(|_| Error::Corrupt("Transfer staging basename is invalid".into()))?;
            if self.kind != "download"
                || self.staging_identity.as_ref().is_none_or(String::is_empty)
            {
                return Err(Error::Corrupt(
                    "Transfer staging object identity is missing".into(),
                ));
            }
        }
        if self.registration_started && (self.kind != "upload" || self.completion_token.is_none()) {
            return Err(Error::Corrupt(
                "Upload registration marker has no final token".into(),
            ));
        }
        if let Some(handle) = &self.registered_handle {
            if self.kind != "upload"
                || !self.registration_started
                || handle.len() != 8
                || !handle
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
                || self.completed.len() != count
            {
                return Err(Error::Corrupt(
                    "Confirmed upload receipt has invalid node identity or coverage".into(),
                ));
            }
        }
        if (self.finalization_started && self.registered_handle.is_none())
            || (self.finalization_completed && !self.finalization_started)
        {
            return Err(Error::Corrupt(
                "Upload finalization has no confirmed registration or start marker".into(),
            ));
        }
        if let Some(key) = &self.sealed_upload_key {
            super::vault::Vault::validate_envelope(key)?;
        }
        if let Some(url) = &self.upload_url {
            let url = url::Url::parse(url)
                .map_err(|_| Error::Corrupt("Saved upload URL is invalid".into()))?;
            crate::protocol::transport::safe_target(&url)
                .map_err(|_| Error::Corrupt("Saved upload URL is unsafe".into()))?;
            let host = url.host_str().unwrap_or("").trim_end_matches('.');
            if !(host == "mega.nz"
                || host.ends_with(".mega.nz")
                || host == "mega.co.nz"
                || host.ends_with(".mega.co.nz"))
            {
                return Err(Error::Corrupt(
                    "Saved upload destination is not a MEGA storage host".into(),
                ));
            }
        }
        Ok(())
    }

    pub fn require_complete(&self) -> Result<()> {
        self.validate()?;
        if self.completed.len() != chunk_count(self.size)? {
            return Err(Error::integrity("Transfer is missing completed chunks"));
        }
        Ok(())
    }

    pub fn compatible(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.source_hash == other.source_hash
            && self.destination == other.destination
            && self.size == other.size
            && self.key_hash == other.key_hash
            && self.source_identity == other.source_identity
    }
}

pub struct States(Store);

impl States {
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self(Store::new(path))
    }
    pub fn load(&self) -> Result<Option<TransferState>> {
        let state: Option<TransferState> = self.0.lock()?.load()?;
        if let Some(state) = &state {
            state.validate()?
        }
        Ok(state)
    }
    pub fn save(&self, state: &TransferState) -> Result<()> {
        state.validate()?;
        let locked = self.0.lock()?;
        if let Some(previous) = locked.load::<TransferState>()? {
            previous.validate()?;
            if !previous.compatible(state) {
                return Err(Error::Corrupt(
                    "Refusing to overwrite unrelated transfer state".into(),
                ));
            }
            if previous.revision > state.revision {
                return Ok(());
            }
        }
        locked.save(state)
    }
    pub fn discard_unregistered_upload(&self, expected: &TransferState) -> Result<()> {
        let locked = self.0.lock()?;
        if let Some(current) = locked.load::<TransferState>()? {
            current.validate()?;
            if current.kind != "upload"
                || !current.compatible(expected)
                || current.registration_started
                || current.registered_handle.is_some()
            {
                return Err(Error::Corrupt(
                    "Refusing to discard unrelated or registered upload state".into(),
                ));
            }
            locked.remove()?;
        }
        Ok(())
    }

    pub fn clear(&self) -> Result<()> {
        let locked = self.0.lock()?;
        if let Some(state) = locked.load::<TransferState>()? {
            state.validate()?;
        }
        locked.remove()
    }
}
