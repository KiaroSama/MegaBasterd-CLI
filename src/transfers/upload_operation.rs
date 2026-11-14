//! Persistently fence a queued upload against account/target replanning on retry.

use std::path::Path;
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::storage::files::{LockedStore, Store};

pub fn bind(
    directory: &Path,
    operation: Option<&str>,
    source: &Path,
    binding: &str,
) -> Result<Option<LockedStore>> {
    let Some(operation) = operation else {
        return Ok(None);
    };
    if operation.is_empty() || operation.len() > 4096 || operation.chars().any(char::is_control) {
        return Err(Error::invalid("Upload operation identity is invalid"));
    }
    let identity = serde_json::to_vec(&(operation, source))?;
    let name = hex::encode(Sha256::digest(&identity));
    let store = Store::new(directory.join(format!("operation-{name}.binding")))
        .with_timeout(Duration::ZERO);
    let locked = store.lock()?;
    let expected = hex::encode(Sha256::digest(binding.as_bytes()));
    if let Some(previous) = locked.load::<String>()? {
        if previous != expected {
            return Err(Error::Corrupt(
                "Queued upload account, target or name changed; recheck its original remote outcome before replanning".into(),
            ));
        }
    } else {
        locked.save(&expected)?;
    }
    Ok(Some(locked))
}
