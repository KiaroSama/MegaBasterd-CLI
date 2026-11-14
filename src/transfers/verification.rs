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

struct Permit<'a>(&'a Gate);
impl Drop for Permit<'_> {
    fn drop(&mut self) {
        if let Ok(mut active) = self.0.active.lock() {
            *active = active.saturating_sub(1);
        }
        self.0.changed.notify_one();
    }
}

impl Gate {
    fn acquire(&self, control: &Control, limit: u32) -> Result<Permit<'_>> {
        if !(1..=32).contains(&limit) {
            return Err(Error::invalid(
                "Parallel verifications must be between 1 and 32",
            ));
        }
        let mut active = self.active.lock().map_err(poisoned)?;
        while *active >= limit as usize {
            if control.is_canceled() {
                return Err(Error::Canceled);
            }
            // Cancellation is a separate condition; bounded waits avoid a busy spin.
            active = self
                .changed
                .wait_timeout(active, Duration::from_millis(100))
                .map_err(poisoned)?
                .0;
        }
        if control.is_canceled() {
            return Err(Error::Canceled);
        }
        *active += 1;
        Ok(Permit(self))
    }
}

fn gate() -> &'static Gate {
    GATE.get_or_init(|| Gate {
        active: Mutex::new(0),
        changed: Condvar::new(),
    })
}

#[cfg(test)]
fn permit(control: &Control) -> Result<Permit<'static>> {
    gate().acquire(control, 1)
}

/// Saved coverage is only a hint: bytes on the held file decide which chunks may be skipped.
pub fn validate_completed(
    file: &mut File,
    size: u64,
    key: &keys::FileKey,
    completed: &mut std::collections::BTreeMap<usize, [u8; 16]>,
    control: &Control,
) -> Result<u64> {
    validate_completed_with_limit(file, size, key, completed, control, 1)
}

/// Resume rereads hold the same configured permit as final verification, so an
/// unbounded resume cannot starve or bypass the disk gate.
pub fn validate_completed_with_limit(
    file: &mut File,
    size: u64,
    key: &keys::FileKey,
    completed: &mut std::collections::BTreeMap<usize, [u8; 16]>,
    control: &Control,
    limit: u32,
) -> Result<u64> {
    if file.metadata()?.len() != size {
        return Err(Error::integrity("Resume staging file size changed"));
    }
    let _permit = gate().acquire(control, limit)?;
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
    verify_with_limit(file, size, key, control, 1)
}

pub fn verify_with_limit(
    file: &mut File,
    size: u64,
    key: &keys::FileKey,
    control: &Control,
    limit: u32,
) -> Result<()> {
    let _permit = gate().acquire(control, limit)?;
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
