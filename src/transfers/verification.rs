use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::sync::{Condvar, Mutex, OnceLock};
use std::time::Duration;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::control::Control;
use crate::crypto::{chunks, keys};
use crate::error::{Error, Result, poisoned};

struct Gate {
    active: Mutex<usize>,
    changed: Condvar,
}
static GATE: OnceLock<Gate> = OnceLock::new();

struct Permit(&'static Gate);
impl Drop for Permit {
    fn drop(&mut self) {
        if let Ok(mut active) = self.0.active.lock() {
            *active = active.saturating_sub(1);
        }
        self.0.changed.notify_one();
    }
}

fn permit(control: &Control) -> Result<Permit> {
    let gate = GATE.get_or_init(|| Gate {
        active: Mutex::new(0),
        changed: Condvar::new(),
    });
    let mut active = gate.active.lock().map_err(poisoned)?;
    while *active >= 1 {
        if control.is_canceled() {
            return Err(Error::Canceled);
        }
        // Cancellation is a separate condition; bounded condvar waits avoid a busy spin.
        active = gate
            .changed
            .wait_timeout(active, Duration::from_millis(100))
            .map_err(poisoned)?
            .0;
    }
    if control.is_canceled() {
        return Err(Error::Canceled);
    }
    *active += 1;
    Ok(Permit(gate))
}

/// Saved coverage is only a hint: bytes on the held file decide which chunks may be skipped.
pub fn validate_completed(
    file: &mut File,
    size: u64,
    key: &keys::FileKey,
    completed: &mut std::collections::BTreeMap<usize, [u8; 16]>,
    control: &Control,
) -> Result<u64> {
    if file.metadata()?.len() != size {
        return Err(Error::integrity("Resume staging file size changed"));
    }
    let mut verified_bytes = 0;
    for chunk in chunks::iter_chunks(size)? {
        let Some(expected) = completed.get(&chunk.index).copied() else {
            continue;
        };
        control.checkpoint()?;
        file.seek(SeekFrom::Start(chunk.offset))?;
        let mut bytes = Zeroizing::new(vec![0; chunk.size as usize]);
        file.read_exact(&mut bytes)?;
        let actual = chunks::chunk_mac(&bytes, key.aes_key.as_slice(), &key.nonce)?;
        if bool::from(actual.ct_eq(&expected)) {
            verified_bytes += chunk.size;
        } else {
            completed.remove(&chunk.index);
        }
    }
    Ok(verified_bytes)
}

pub fn verify(file: &mut File, size: u64, key: &keys::FileKey, control: &Control) -> Result<()> {
    let _permit = permit(control)?;
    if file.metadata()?.len() != size {
        return Err(Error::integrity(
            "Downloaded file size differs from metadata",
        ));
    }
    let mut macs = Vec::with_capacity(chunks::chunk_count(size)?);
    for chunk in chunks::iter_chunks(size)? {
        control.checkpoint()?;
        file.seek(SeekFrom::Start(chunk.offset))?;
        let mut bytes = Zeroizing::new(vec![0; chunk.size as usize]);
        file.read_exact(&mut bytes)?;
        macs.push(chunks::chunk_mac(
            &bytes,
            key.aes_key.as_slice(),
            &key.nonce,
        )?);
    }
    let mac = chunks::condense_mac(&chunks::combine_chunk_macs(&macs, key.aes_key.as_slice())?)?;
    if !bool::from(mac.ct_eq(&key.mac)) {
        return Err(Error::integrity(
            "On-disk MEGA MAC does not match the public file key",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "verification_tests.rs"]
mod tests;
