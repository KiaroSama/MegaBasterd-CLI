// SPDX-License-Identifier: GPL-3.0-or-later
//! Source-compatible MBCR streams and claimed, anchored local-file publication.
use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{AeadInOut, KeyInit},
};
use rand::{TryRng, rngs::SysRng};
use zeroize::Zeroizing;

use crate::{
    error::{Error, Result},
    platform::secure_files::{OutputDirectory, file_identity},
    transfers::claims::Claim,
};

pub const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;
pub const MAX_CHUNK_SIZE: usize = 16 * 1024 * 1024;
pub const LEGACY_WARNING: &str = "MBCR legacy v1 has per-chunk authentication only; whole-file sequence, truncation and ordering integrity are weaker than v2.";
pub type Progress<'a> = Option<&'a mut dyn FnMut(u64, u64) -> Result<()>>;

#[derive(Debug)]
pub struct CryptoResult {
    pub path: PathBuf,
    pub bytes: u64,
    pub version: u8,
    pub warning: Option<&'static str>,
}

pub(crate) fn open_source(path: &Path) -> Result<(OutputDirectory, File)> {
    let absolute = absolute(path)?;
    let directory = OutputDirectory::open(
        absolute
            .parent()
            .ok_or_else(|| Error::invalid("Source needs a parent"))?,
    )?;
    let file = directory.open_read(
        absolute
            .file_name()
            .ok_or_else(|| Error::invalid("Source needs a filename"))?,
    )?;
    // Native open refuses symlinks/reparse points and nonregular files.
    file_identity(&file)?;
    Ok((directory, file))
}

fn absolute(path: &Path) -> Result<PathBuf> {
    Ok(if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    })
}

pub(crate) fn reject_aliases(
    directory: &OutputDirectory,
    name: &OsStr,
    inputs: &[&File],
) -> Result<()> {
    match directory.open_read(name) {
        Ok(target) => {
            let identity = file_identity(&target)?;
            for input in inputs {
                if identity == file_identity(input)? {
                    return Err(Error::invalid(
                        "Local operation refused: output is the same file as an input",
                    ));
                }
            }
            Ok(())
        }
        Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// A stage owns only its newly created temporary, never an existing destination.
pub(crate) struct StagedOutput {
    claim: Claim,
    temporary: OsString,
    identity: String,
    file: Option<File>,
    published: bool,
    overwrite: bool,
}

impl StagedOutput {
    pub(crate) fn new(destination: &Path, overwrite: bool, inputs: &[&File]) -> Result<Self> {
        let path = absolute(destination)?;
        let directory = OutputDirectory::ensure(
            path.parent()
                .ok_or_else(|| Error::invalid("Output needs a parent"))?,
        )?;
        let name = path
            .file_name()
            .ok_or_else(|| Error::invalid("Output needs a filename"))?;
        reject_aliases(&directory, name, inputs)?;
        if !overwrite {
            match directory.open_read(name) {
                Ok(_) => {
                    return Err(Error::invalid(
                        "Output already exists; explicit overwrite permission is required",
                    ));
                }
                Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => (),
                Err(error) => return Err(error),
            }
        }
        // Claim's true flag requests the exact name instead of auto-numbering; it does
        // not write/truncate. Actual publication still uses the caller's consent below.
        let claim = Claim::acquire(&path, true, |_| Ok(false))?;
        reject_aliases(&claim.directory, &claim.name, inputs)?;
        let temporary = claim.temporary_name()?;
        let file = claim.directory.open_file(&temporary, true)?;
        let identity = file_identity(&file)?;
        Ok(Self {
            claim,
            temporary,
            identity,
            file: Some(file),
            published: false,
            overwrite,
        })
    }

    pub(crate) fn writer(&mut self) -> Result<&mut File> {
        self.file
            .as_mut()
            .ok_or_else(|| Error::protocol("Local output stage is closed"))
    }

    pub(crate) fn commit(mut self, inputs: &[&File]) -> Result<PathBuf> {
        self.writer()?.flush()?;
        self.writer()?.sync_all()?;
        reject_aliases(&self.claim.directory, &self.claim.name, inputs)?;
        let current = self.claim.directory.open_read(&self.temporary)?;
        if file_identity(&current)? != self.identity {
            return Err(Error::integrity(
                "Local output stage was replaced before publication",
            ));
        }
        drop(current);
        self.file.take(); // Windows publication needs the staging write handle closed.
        self.claim.publish(&self.temporary, self.overwrite)?;
        self.published = true; // A failed directory sync must never delete the published file.
        self.claim.directory.sync()?;
        Ok(self.claim.path.clone())
    }
}

impl Drop for StagedOutput {
    fn drop(&mut self) {
        let owned = self.file.take();
        if !self.published && owned.is_some() {
            // Keep our object live during comparison. Native removal verifies the
            // expected ID again on its own mutation handle, not an unchecked pathname.
            let ours = self
                .claim
                .directory
                .open_read(&self.temporary)
                .is_ok_and(|file| {
                    file_identity(&file).is_ok_and(|identity| identity == self.identity)
                });
            drop(owned);
            if ours {
                let _ = self
                    .claim
                    .directory
                    .remove_owned(&self.temporary, &self.identity);
            }
        }
        // Publication closes the original handle; retain an uncertain failed stage,
        // since an old ID is no longer sufficient proof of ownership after reuse.
    }
}

fn random(bytes: &mut [u8]) -> Result<()> {
    SysRng
        .try_fill_bytes(bytes)
        .map_err(|_| Error::protocol("Operating-system randomness is unavailable"))
}

fn scrypt_parameters(n: i64, r: u32, p: u32) -> Result<scrypt::Params> {
    let invalid = || Error::invalid("scrypt parameters exceed the MBCR resource bounds");
    let n = u64::try_from(n).map_err(|_| invalid())?;
    if !(1 << 10..=1 << 20).contains(&n)
        || !n.is_power_of_two()
        || !(1..=32).contains(&r)
        || !(1..=16).contains(&p)
    {
        return Err(invalid());
    }
    let memory = 128u64
        .checked_mul(n)
        .and_then(|v| v.checked_mul(u64::from(r)))
        .and_then(|v| v.checked_mul(u64::from(p)));
    if memory.is_none_or(|bytes| bytes > 256 * 1024 * 1024) {
        return Err(invalid());
    }
    scrypt::Params::new(n.ilog2() as u8, r, p).map_err(|_| invalid())
}

fn cipher(passphrase: &str, salt: &[u8]) -> Result<Aes256Gcm> {
    if salt.len() != 16 {
        return Err(Error::invalid("MBCR salt must contain exactly 16 bytes"));
    }
    // MBCR has no KDF parameters in its header. Changing these changes its format.
    let params = scrypt_parameters(1 << 14, 8, 1)?;
    let mut key = Zeroizing::new([0; 32]);
    scrypt::scrypt(passphrase.as_bytes(), salt, &params, &mut *key)
        .map_err(|_| Error::protocol("MBCR key derivation failed"))?;
    Aes256Gcm::new_from_slice(&*key)
        .map_err(|_| Error::protocol("MBCR cipher initialization failed"))
}

fn validate_chunk(chunk: usize) -> Result<()> {
    if chunk == 0 || chunk > MAX_CHUNK_SIZE {
        return Err(Error::invalid(
            "MBCR chunk size must be between 1 and 16 MiB",
        ));
    }
    Ok(())
}

fn exact<const N: usize>(file: &mut File) -> Result<[u8; N]> {
    let mut bytes = [0; N];
    file.read_exact(&mut bytes).map_err(|error| {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            Error::integrity("Truncated MBCR file")
        } else {
            error.into()
        }
    })?;
    Ok(bytes)
}

pub(crate) fn require_unchanged(file: &File, before: &std::fs::Metadata) -> Result<()> {
    let after = file.metadata()?;
    if after.len() != before.len() || after.modified()? != before.modified()? {
        return Err(Error::integrity(
            "Input file changed during local processing",
        ));
    }
    Ok(())
}

fn aad(header: &[u8], index: u64, flag: u8) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(header.len() + 9);
    bytes.extend_from_slice(header);
    bytes.extend_from_slice(&index.to_be_bytes());
    bytes.push(flag);
    bytes
}

pub(crate) fn progress(callback: &mut Progress<'_>, done: u64, total: u64) -> Result<()> {
    if let Some(callback) = callback.as_mut() {
        callback(done, total)?;
    }
    Ok(())
}

/// Writes only v2. Cancellation/progress errors abort before replacing the output.
pub fn encrypt_file(
    src: &Path,
    dst: &Path,
    passphrase: &str,
    chunk_size: usize,
    overwrite: bool,
    on_progress: Progress<'_>,
) -> Result<CryptoResult> {
    encrypt_with_entropy(
        src,
        dst,
        passphrase,
        chunk_size,
        overwrite,
        on_progress,
        random,
    )
}

fn encrypt_with_entropy(
    src: &Path,
    dst: &Path,
    passphrase: &str,
    chunk_size: usize,
    overwrite: bool,
    mut on_progress: Progress<'_>,
    mut fill: impl FnMut(&mut [u8]) -> Result<()>,
) -> Result<CryptoResult> {
    validate_chunk(chunk_size)?;
    let (_directory, mut input) = open_source(src)?;
    let metadata = input.metadata()?;
    let total = metadata.len();
    let mut output = StagedOutput::new(dst, overwrite, &[&input])?;
    let mut salt = [0; 16];
    fill(&mut salt)?;
    let mut header = b"MBCR\x02".to_vec();
    header.extend(salt);
    header.extend((chunk_size as u32).to_be_bytes());
    header.extend(total.to_be_bytes());
    let cipher = cipher(passphrase, &salt)?;
    output.writer()?.write_all(&header)?;
    let mut buffer = Zeroizing::new(Vec::with_capacity(chunk_size + 16));
    let (mut done, mut index) = (0u64, 0u64);
    loop {
        let length = (total - done).min(chunk_size as u64) as usize;
        buffer.resize(length, 0);
        input.read_exact(&mut buffer).map_err(|error| {
            if error.kind() == std::io::ErrorKind::UnexpectedEof {
                Error::integrity("Source changed while encrypting")
            } else {
                error.into()
            }
        })?;
        let flag = u8::from(done + length as u64 == total);
        let mut nonce = [0; 12];
        fill(&mut nonce)?;
        cipher
            .encrypt_in_place(
                &Nonce::from(nonce),
                &aad(&header, index, flag),
                &mut *buffer,
            )
            .map_err(|_| Error::protocol("MBCR encryption failed"))?;
        let writer = output.writer()?;
        writer.write_all(&[flag])?;
        writer.write_all(&((12 + buffer.len()) as u32).to_be_bytes())?;
        writer.write_all(&nonce)?;
        writer.write_all(&buffer)?;
        done += length as u64;
        progress(&mut on_progress, done, total)?;
        if flag == 1 {
            break;
        }
        index = index
            .checked_add(1)
            .ok_or_else(|| Error::invalid("Too many MBCR chunks"))?;
    }
    if input.read(&mut [0])? != 0 {
        return Err(Error::integrity("Source grew while encrypting"));
    }
    require_unchanged(&input, &metadata)?;
    let path = output.commit(&[&input])?;
    Ok(CryptoResult {
        path,
        bytes: done,
        version: 2,
        warning: None,
    })
}

/// Reads v2 or legacy v1; callers must display a returned legacy warning.
pub fn decrypt_file(
    src: &Path,
    dst: &Path,
    passphrase: &str,
    overwrite: bool,
    on_progress: Progress<'_>,
) -> Result<CryptoResult> {
    decrypt_with_cipher(src, dst, passphrase, overwrite, on_progress, cipher)
}

fn decrypt_with_cipher(
    src: &Path,
    dst: &Path,
    passphrase: &str,
    overwrite: bool,
    mut on_progress: Progress<'_>,
    derive: impl FnOnce(&str, &[u8]) -> Result<Aes256Gcm>,
) -> Result<CryptoResult> {
    let (_directory, mut input) = open_source(src)?;
    let metadata = input.metadata()?;
    let size = metadata.len();
    let prefix = exact::<5>(&mut input)?;
    if &prefix[..4] != b"MBCR" {
        return Err(Error::invalid("Not a MegaBasterd Crypter file (bad magic)"));
    }
    let version = prefix[4];
    if !matches!(version, 1 | 2) {
        return Err(Error::invalid("Unsupported Crypter version"));
    }
    let salt = exact::<16>(&mut input)?;
    let chunk_bytes = exact::<4>(&mut input)?;
    let chunk_size = u32::from_be_bytes(chunk_bytes) as usize;
    validate_chunk(chunk_size)?;
    let original = if version == 2 {
        Some(u64::from_be_bytes(exact::<8>(&mut input)?))
    } else {
        None
    };
    if original.is_some_and(|length| length > size) {
        return Err(Error::invalid(
            "Declared original length exceeds the encrypted file size",
        ));
    }
    let mut header = prefix.to_vec();
    header.extend(salt);
    header.extend(chunk_bytes);
    if let Some(length) = original {
        header.extend(length.to_be_bytes());
    }
    // All untrusted header fields have been checked before the memory-expensive KDF.
    let mut output = StagedOutput::new(dst, overwrite, &[&input])?;
    let cipher = derive(passphrase, &salt)?;
    let (mut done, mut index) = (0u64, 0u64);
    loop {
        let flag = if version == 2 {
            exact::<1>(&mut input)?[0]
        } else {
            0
        };
        if flag > 1 {
            return Err(Error::integrity("Corrupt MBCR chunk flag"));
        }
        let length = u32::from_be_bytes(exact::<4>(&mut input)?) as usize;
        if version == 1 && length == 0 {
            break;
        }
        if length < 28 || length > chunk_size + 28 {
            return Err(Error::integrity(
                "Declared chunk length exceeds header chunk size or is too short",
            ));
        }
        let nonce = exact::<12>(&mut input)?;
        let mut buffer = Zeroizing::new(vec![0; length - 12]);
        input.read_exact(&mut buffer).map_err(|error| {
            if error.kind() == std::io::ErrorKind::UnexpectedEof {
                Error::integrity("Truncated MBCR chunk")
            } else {
                error.into()
            }
        })?;
        let associated = if version == 2 {
            aad(&header, index, flag)
        } else {
            Vec::new()
        };
        cipher
            .decrypt_in_place(&Nonce::from(nonce), &associated, &mut *buffer)
            .map_err(|_| {
                Error::integrity("Decryption failed (wrong passphrase, corruption, or tampering)")
            })?;
        done = done
            .checked_add(buffer.len() as u64)
            .ok_or_else(|| Error::integrity("MBCR plaintext length overflows"))?;
        if original.is_some_and(|length| done > length) {
            return Err(Error::integrity(
                "Decrypted length exceeds authenticated header length",
            ));
        }
        output.writer()?.write_all(&buffer)?;
        progress(&mut on_progress, done, size)?;
        index = index
            .checked_add(1)
            .ok_or_else(|| Error::integrity("Too many MBCR chunks"))?;
        if version == 2 && flag == 1 {
            if input.read(&mut [0])? != 0 {
                return Err(Error::integrity("Trailing data after final MBCR chunk"));
            }
            if original != Some(done) {
                return Err(Error::integrity(
                    "Decrypted length does not match authenticated header length",
                ));
            }
            break;
        }
    }
    // v1 deliberately preserves source read compatibility, including its weaker tail semantics.
    require_unchanged(&input, &metadata)?;
    let path = output.commit(&[&input])?;
    Ok(CryptoResult {
        path,
        bytes: done,
        version,
        warning: (version == 1).then_some(LEGACY_WARNING),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn mbcr_scrypt_defaults_and_all_source_unsafe_parameters_use_the_real_resource_guard()
    -> Result<()> {
        let params = scrypt_parameters(1 << 14, 8, 1)?;
        assert_eq!((params.n(), params.r(), params.p()), (16384, 8, 1));
        for (n, r, p) in [
            (1 << 30, 8, 1),
            (12345, 8, 1),
            (0, 8, 1),
            (-1, 8, 1),
            (1 << 14, 0, 1),
            (1 << 14, 1000, 1),
            (1 << 14, 8, 0),
            (1 << 14, 8, 1000),
            (1 << 20, 32, 16),
        ] {
            assert!(matches!(
                scrypt_parameters(n, r, p),
                Err(Error::Invalid(message)) if message.contains("scrypt")
            ));
        }
        Ok(())
    }

    #[test]
    fn invalid_headers_refuse_before_key_derivation_or_output_creation() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let input = directory.path().join("invalid.mbcr");
        let output = directory.path().join("output");
        for (chunk, original, expected) in [
            (0, 0, "chunk size"),
            (MAX_CHUNK_SIZE + 1, 0, "chunk size"),
            (16, 1 << 40, "exceeds the encrypted file size"),
            (16, u64::MAX, "exceeds the encrypted file size"),
        ] {
            let mut header = b"MBCR\x02".to_vec();
            header.extend([0; 16]);
            header.extend((chunk as u32).to_be_bytes());
            header.extend(original.to_be_bytes());
            fs::write(&input, &header)?;
            let mut calls = 0;
            let result = decrypt_with_cipher(&input, &output, "pw", false, None, |_, _| {
                calls += 1;
                Err(Error::protocol(
                    "Derivation must not run for an invalid header",
                ))
            });
            assert!(matches!(result, Err(Error::Invalid(message)) if message.contains(expected)));
            assert_eq!(calls, 0);
            assert!(!output.exists());
            assert_eq!(fs::read(&input)?, header);
            assert_eq!(fs::read_dir(directory.path())?.count(), 1);
        }
        Ok(())
    }

    #[test]
    fn fourth_entropy_failure_after_two_chunks_preserves_input_destination_and_cleans_stage()
    -> Result<()> {
        let directory = tempfile::tempdir()?;
        let input = directory.path().join("src.bin");
        let output = directory.path().join("important.txt");
        let bytes = vec![b'x'; DEFAULT_CHUNK_SIZE * 3];
        let original = b"irreplaceable user data\n".repeat(40);
        fs::write(&input, &bytes)?;
        fs::write(&output, &original)?;
        let mut calls = 0u8;
        let mut observed = Vec::new();
        let mut progress = |done, total| {
            observed.push((done, total));
            Ok(())
        };
        let result = encrypt_with_entropy(
            &input,
            &output,
            "correct horse battery staple",
            DEFAULT_CHUNK_SIZE,
            true,
            Some(&mut progress),
            |buffer| {
                calls += 1;
                if calls == 4 {
                    return Err(Error::protocol("Entropy source failed"));
                }
                buffer.fill(calls);
                Ok(())
            },
        );
        assert!(
            matches!(result, Err(Error::Protocol(message)) if message == "Entropy source failed")
        );
        assert_eq!(calls, 4);
        assert_eq!(
            observed,
            [
                (DEFAULT_CHUNK_SIZE as u64, bytes.len() as u64),
                ((DEFAULT_CHUNK_SIZE * 2) as u64, bytes.len() as u64),
            ]
        );
        assert_eq!(fs::read(&input)?, bytes);
        assert_eq!(fs::read(&output)?, original);
        for entry in fs::read_dir(directory.path())? {
            assert!(!entry?.file_name().to_string_lossy().ends_with(".tmp"));
        }
        Ok(())
    }
}
