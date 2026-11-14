use crate::error::{Error, Result};

use super::config::Config;
use super::document_json::has_future_version;
use super::files::{LockedStore, Store, decode_document};

#[cfg(test)]
#[path = "config_transaction_tests.rs"]
mod transaction_tests;

pub struct ConfigStore {
    store: Store,
}

impl ConfigStore {
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            store: Store::new(path),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_test_lock_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.store = self.store.with_timeout(timeout);
        self
    }

    pub fn path(&self) -> &std::path::Path {
        self.store.path()
    }

    pub fn load(&self) -> Result<(Config, Vec<String>)> {
        self.load_with(Config::from_value)
    }

    pub(crate) fn load_for_command(&self) -> Result<(Config, Vec<String>)> {
        use std::{collections::BTreeSet, sync::Mutex};

        use sha2::{Digest, Sha256};

        static WARNED: Mutex<BTreeSet<[u8; 32]>> = Mutex::new(BTreeSet::new());
        self.load_with(|value| {
            Config::from_value_with_ignored(value, |key| {
                let identity: [u8; 32] = Sha256::digest(key.as_bytes()).into();
                let mut warned = WARNED.lock().map_err(crate::error::poisoned)?;
                if warned.contains(&identity) {
                    return Ok(false);
                }
                if warned.len() >= 4096 {
                    return Err(Error::Corrupt(
                        "Config warning limit reached; remove stale settings and restart the command".into(),
                    ));
                }
                Ok(warned.insert(identity))
            })
        })
    }

    fn load_with(
        &self,
        decode: impl FnOnce(serde_json::Value) -> Result<(Config, Vec<String>)>,
    ) -> Result<(Config, Vec<String>)> {
        let locked = match self.store.lock() {
            Ok(locked) => locked,
            Err(error @ Error::Busy(_)) => {
                // An unlocked snapshot can diagnose damage, never supply usable settings.
                if let Ok(Some(bytes)) = self.store.diagnostic_bytes()
                    && let Err(Error::Corrupt(reason)) =
                        decode_document::<serde_json::Value>(&bytes).and_then(Self::validate_root)
                {
                    return Err(Self::corruption(reason, false));
                }
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        match Self::stored_value(&locked)? {
            Some(value) => decode(value),
            None => Ok((Config::default(), Vec::new())),
        }
    }

    fn validate_root(value: serde_json::Value) -> Result<serde_json::Value> {
        if !value.is_object() {
            return Err(Error::Corrupt("Config root is not an object".into()));
        }
        Ok(value)
    }

    fn stored_value(locked: &LockedStore) -> Result<Option<serde_json::Value>> {
        let result = locked
            .load::<serde_json::Value>()
            .and_then(|value| value.map(Self::validate_root).transpose());
        match result {
            Err(Error::Corrupt(reason)) => {
                if locked
                    .bytes()?
                    .as_ref()
                    .is_some_and(|bytes| has_future_version(bytes))
                {
                    return Err(Error::Corrupt(reason));
                }
                Err(Self::corruption(reason, locked.preserve().is_ok()))
            }
            result => result,
        }
    }

    fn corruption(reason: String, preserved: bool) -> Error {
        let recovery = if preserved {
            "A private recovery copy was preserved"
        } else {
            "A private recovery copy could not be written or verified"
        };
        Error::Corrupt(format!(
            "{reason}. {recovery}; original bytes remain untouched. Inspect or explicitly recover configuration before continuing"
        ))
    }

    pub fn set(&self, key: &str, value: &str) -> Result<()> {
        self.update(|config| config.set_text(key, value))
    }

    pub fn unset(&self, key: &str) -> Result<()> {
        self.update(|config| config.unset(key))
    }

    fn update(&self, change: impl FnOnce(&mut Config) -> Result<()>) -> Result<()> {
        let locked = self.store.lock()?;
        let mut config = match Self::stored_value(&locked)? {
            Some(value) => Config::from_value(value)?.0,
            None => Config::default(),
        };
        change(&mut config)?;
        locked.save(&config)
    }

    pub fn migrate(&self) -> Result<Vec<String>> {
        let locked = self.store.lock()?;
        let Some(value) = Self::stored_value(&locked)? else {
            return Ok(Vec::new());
        };
        let (config, _) = Config::from_value(value.clone())?;
        let normalized = config.value()?;
        let mut removed: Vec<_> = value
            .as_object()
            .ok_or_else(|| Error::Corrupt("Config root is not an object".into()))?
            .keys()
            .filter(|key| normalized.get(*key).is_none())
            .cloned()
            .collect();
        removed.sort();
        if normalized != value {
            locked.save(&config)?;
        }
        Ok(removed)
    }

    pub fn reset(&self) -> Result<()> {
        let locked = self.store.lock()?;
        // Reset is not the corrupt-file recovery command.
        if let Some(value) = Self::stored_value(&locked)? {
            Config::from_value(value)?;
        }
        locked.save(&Config::default())
    }

    pub fn recover(&self, reset: bool) -> Result<Option<std::ffi::OsString>> {
        let locked = self.store.lock()?;
        let usable = Self::stored_value(&locked).and_then(|value| match value {
            Some(value) => Config::from_value(value).map(|_| ()),
            None => Ok(()),
        });
        match usable {
            Ok(()) => Ok(None),
            Err(Error::Corrupt(reason)) => {
                let raw = locked
                    .bytes()?
                    .ok_or_else(|| Error::invalid("No corrupt configuration exists"))?;
                if has_future_version(&raw) {
                    return Err(Error::Corrupt("Configuration belongs to a newer application; restore a supported version instead".into()));
                }
                if !reset {
                    return Err(Error::Corrupt(format!(
                        "{reason}; config recovery requires explicit --reset; original bytes remain untouched"
                    )));
                }
                let backup = locked.preserve()?;
                locked.save(&Config::default())?;
                Ok(Some(backup))
            }
            Err(error) => Err(error),
        }
    }
}
