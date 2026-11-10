// SPDX-License-Identifier: GPL-3.0-or-later
//! File keys, account derivation, authenticated protected links and RSA session MPIs.
use hmac::{Hmac, KeyInit, Mac};
use num_bigint::BigUint;
use rand::{TryRng, rngs::SysRng};
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

use super::wire::{
    AesBlock, a32_to_bytes, a32_to_str, b64_url_decode, b64_url_encode, bytes_to_a32,
};
use crate::error::{Error, Result};

pub const ACCOUNT_KDF_ITERATIONS: u32 = 100_000;
pub const MAX_KDF_ITERATIONS: u32 = 1_000_000;
pub const MAX_MPI_BITS: usize = 8192;
const MAX_PROTECTED_LINK_TEXT: usize = 160;

pub struct FileKey {
    pub aes_key: Zeroizing<[u8; 16]>,
    pub nonce: [u8; 8],
    pub mac: [u32; 2],
}

pub fn unpack_file_key(words: &[u32]) -> Result<FileKey> {
    let words: &[u32; 8] = words
        .try_into()
        .map_err(|_| Error::invalid("File key must have eight uint32 words"))?;
    let mut aes_key = Zeroizing::new([0; 16]);
    for (i, output) in aes_key.chunks_exact_mut(4).enumerate() {
        output.copy_from_slice(&(words[i] ^ words[i + 4]).to_be_bytes());
    }
    let mut nonce = [0; 8];
    nonce[..4].copy_from_slice(&words[4].to_be_bytes());
    nonce[4..].copy_from_slice(&words[5].to_be_bytes());
    Ok(FileKey {
        aes_key,
        nonce,
        mac: [words[6], words[7]],
    })
}

pub fn pack_file_key(aes_key: &[u8], nonce: &[u8], mac: &[u32]) -> Result<[u32; 8]> {
    if aes_key.len() != 16 || nonce.len() != 8 || mac.len() != 2 {
        return Err(Error::invalid(
            "File key requires a 16-byte AES key, 8-byte nonce and two MAC words",
        ));
    }
    let aes = Zeroizing::new(bytes_to_a32(aes_key));
    let nonce = bytes_to_a32(nonce);
    Ok([
        aes[0] ^ nonce[0],
        aes[1] ^ nonce[1],
        aes[2] ^ mac[0],
        aes[3] ^ mac[1],
        nonce[0],
        nonce[1],
        mac[0],
        mac[1],
    ])
}

pub fn derive_key_legacy(password: &str) -> Result<[u32; 4]> {
    let mut state = Zeroizing::new([0; 16]);
    state.copy_from_slice(&a32_to_bytes(&[
        0x93c467e3, 0x7db0c7a4, 0xd1be3f81, 0x0152cb56,
    ]));
    let mut ciphers = Vec::new();
    for chunk in password.as_bytes().chunks(16) {
        let mut key = Zeroizing::new([0; 16]);
        key[..chunk.len()].copy_from_slice(chunk);
        ciphers.push(AesBlock::new(&*key)?);
    }
    for _ in 0..65_536 {
        for cipher in &ciphers {
            cipher.encrypt(&mut state);
        }
    }
    bytes_to_a32(&*state)
        .try_into()
        .map_err(|_| Error::protocol("Legacy key derivation width mismatch"))
}

/// Protocol entry point: MEGA version 2 uses 100,000 PBKDF2-HMAC-SHA512 rounds.
pub fn derive_account_key_v2(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    derive_key_v2(password, salt, ACCOUNT_KDF_ITERATIONS)
}

/// Explicit-round source-compatible seam; never use wire input to select its work factor.
pub fn derive_key_v2(password: &str, salt: &[u8], iterations: u32) -> Result<Zeroizing<[u8; 32]>> {
    if iterations == 0 || iterations > MAX_KDF_ITERATIONS {
        return Err(Error::invalid(
            "PBKDF2 work factor is outside the supported bound",
        ));
    }
    let mut derived = Zeroizing::new([0; 32]);
    pbkdf2::pbkdf2::<Hmac<Sha512>>(password.as_bytes(), salt, iterations, &mut *derived)
        .map_err(|_| Error::protocol("Cannot initialize account password derivation"))?;
    Ok(derived)
}

pub fn stringhash(value: &str, key_words: &[u32]) -> Result<String> {
    if key_words.len() != 4 {
        return Err(Error::invalid(
            "Legacy string hash requires four AES key words",
        ));
    }
    let key = Zeroizing::new(a32_to_bytes(key_words));
    let cipher = AesBlock::new(&key)?;
    let words = Zeroizing::new(bytes_to_a32(value.as_bytes()));
    let mut hash = Zeroizing::new([0_u32; 4]);
    for (i, &word) in words.iter().enumerate() {
        hash[i % 4] ^= word;
    }
    let mut state = Zeroizing::new([0; 16]);
    state.copy_from_slice(&a32_to_bytes(&*hash));
    for _ in 0..0x4000 {
        cipher.encrypt(&mut state);
    }
    let final_words = Zeroizing::new(bytes_to_a32(&*state));
    Ok(a32_to_str(&[final_words[0], final_words[2]]))
}

pub fn derive_password_link_keys(
    password: &str,
    salt: &[u8],
    algorithm: u8,
) -> Result<(Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>)> {
    if !matches!(algorithm, 1 | 2) || salt.len() != 32 {
        return Err(Error::invalid(
            "Protected link requires algorithm 1 or 2 and a 32-byte salt",
        ));
    }
    let mut derived = Zeroizing::new([0; 64]);
    pbkdf2::pbkdf2::<Hmac<Sha512>>(
        password.as_bytes(),
        salt,
        ACCOUNT_KDF_ITERATIONS,
        &mut *derived,
    )
    .map_err(|_| Error::protocol("Cannot initialize protected-link password derivation"))?;
    let mut xor_key = Zeroizing::new([0; 32]);
    let mut hmac_key = Zeroizing::new([0; 32]);
    xor_key.copy_from_slice(&derived[..32]);
    hmac_key.copy_from_slice(&derived[32..]);
    Ok((xor_key, hmac_key))
}

pub struct PasswordLink {
    pub node_type: u8,
    pub public_handle: [u8; 6],
    pub raw_key: Zeroizing<Vec<u8>>,
}

fn protected_key_length(node_type: u8) -> Result<usize> {
    match node_type {
        0 => Ok(32),
        1 => Ok(16),
        _ => Err(Error::invalid(
            "Protected node type must be file 0 or folder 1",
        )),
    }
}

fn link_hmac(key: &[u8], body: &[u8]) -> Result<Hmac<Sha256>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| Error::protocol("Cannot initialize protected-link authenticator"))?;
    mac.update(body);
    Ok(mac)
}

pub fn encrypt_password_link(
    node_type: u8,
    handle: &[u8],
    raw_key: &[u8],
    password: &str,
    algorithm: u8,
) -> Result<String> {
    validate_password_link(node_type, handle, raw_key, algorithm)?;
    let mut salt = [0; 32];
    SysRng
        .try_fill_bytes(&mut salt)
        .map_err(|_| Error::protocol("Operating-system randomness is unavailable"))?;
    encrypt_password_link_with_salt(node_type, handle, raw_key, password, algorithm, &salt)
}

fn validate_password_link(
    node_type: u8,
    handle: &[u8],
    raw_key: &[u8],
    algorithm: u8,
) -> Result<()> {
    if handle.len() != 6
        || raw_key.len() != protected_key_length(node_type)?
        || !matches!(algorithm, 1 | 2)
    {
        return Err(Error::invalid(
            "Protected link has an invalid handle, key length or algorithm",
        ));
    }
    Ok(())
}

/// Deterministic salt boundary for reproducible source-oracle vectors; production uses OS randomness.
pub fn encrypt_password_link_with_salt(
    node_type: u8,
    handle: &[u8],
    raw_key: &[u8],
    password: &str,
    algorithm: u8,
    salt: &[u8],
) -> Result<String> {
    validate_password_link(node_type, handle, raw_key, algorithm)?;
    let (xor_key, hmac_key) = derive_password_link_keys(password, salt, algorithm)?;
    let mut body = vec![algorithm, node_type];
    body.extend_from_slice(handle);
    body.extend_from_slice(salt);
    body.extend(
        raw_key
            .iter()
            .zip(xor_key.iter())
            .map(|(&plain, &mask)| plain ^ mask),
    );
    let mac = link_hmac(&*hmac_key, &body)?.finalize().into_bytes();
    body.extend_from_slice(&mac);
    Ok(b64_url_encode(&body))
}

pub fn decrypt_password_link(encoded: &str, password: &str) -> Result<PasswordLink> {
    if encoded.len() > MAX_PROTECTED_LINK_TEXT {
        return Err(Error::invalid(
            "Protected link exceeds its wire length limit",
        ));
    }
    let raw = b64_url_decode(encoded)?;
    if raw.len() < 2 {
        return Err(Error::invalid("Protected link is truncated"));
    }
    let length = protected_key_length(raw[1])?;
    if raw.len() != 40 + length + 32 || !matches!(raw[0], 1 | 2) {
        return Err(Error::invalid("Malformed protected-link payload"));
    }
    let (xor_key, hmac_key) = derive_password_link_keys(password, &raw[8..40], raw[0])?;
    let body_end = 40 + length;
    link_hmac(&*hmac_key, &raw[..body_end])?
        .verify_slice(&raw[body_end..])
        .map_err(|_| Error::integrity("Wrong password or damaged protected link"))?;
    let mut public_handle = [0; 6];
    public_handle.copy_from_slice(&raw[2..8]);
    let raw_key = Zeroizing::new(
        raw[40..body_end]
            .iter()
            .zip(xor_key.iter())
            .map(|(&encrypted, &mask)| encrypted ^ mask)
            .collect(),
    );
    Ok(PasswordLink {
        node_type: raw[1],
        public_handle,
        raw_key,
    })
}

/// Read one two-byte BIT-length-prefixed integer; return value and total bytes consumed.
pub fn read_mpi(blob: &[u8], offset: usize) -> Result<(BigUint, usize)> {
    let header_end = offset
        .checked_add(2)
        .ok_or_else(|| Error::protocol("MPI offset overflows"))?;
    let header = blob
        .get(offset..header_end)
        .ok_or_else(|| Error::protocol("MPI bit-length prefix is truncated"))?;
    let bits = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if bits > MAX_MPI_BITS {
        return Err(Error::protocol("MPI exceeds the supported RSA width"));
    }
    let bytes = bits.div_ceil(8);
    let end = header_end
        .checked_add(bytes)
        .ok_or_else(|| Error::protocol("MPI size overflows"))?;
    let payload = blob
        .get(header_end..end)
        .ok_or_else(|| Error::protocol("MPI integer payload is truncated"))?;
    let value = BigUint::from_bytes_be(payload);
    // MEGA also emits byte-rounded bit counts; smaller significant widths are valid.
    if value.bits() > bits as u64 {
        return Err(Error::protocol(
            "MPI integer exceeds its declared bit length",
        ));
    }
    Ok((value, 2 + bytes))
}

pub fn decode_session_id(csid_encrypted: &[u8], private_blob: &[u8]) -> Result<String> {
    if private_blob.len() > 4 * (MAX_MPI_BITS / 8 + 2) + 15 {
        return Err(Error::protocol(
            "RSA private-key payload exceeds the supported bound",
        ));
    }
    let mut parts = Vec::with_capacity(4);
    let mut cursor = 0;
    for _ in 0..4 {
        let (value, consumed) = read_mpi(private_blob, cursor)?;
        parts.push(value);
        cursor += consumed;
    }
    let padding = &private_blob[cursor..];
    // Historical MEGA accounts pad private keys with random bytes, not zeros.
    if padding.len() > 15 {
        return Err(Error::protocol("RSA private-key padding exceeds one block"));
    }
    let p = &parts[0];
    let q = &parts[1];
    let d = &parts[2];
    let one = BigUint::from(1_u8);
    if p <= &one
        || q <= &one
        || p == q
        || !p.bit(0)
        || !q.bit(0)
        || d <= &one
        || parts[3] == BigUint::from(0_u8)
    {
        return Err(Error::protocol("RSA private-key factors are invalid"));
    }
    let n = p * q;
    if n.bits() > MAX_MPI_BITS as u64 || d >= &n {
        return Err(Error::protocol(
            "RSA modulus or private exponent is invalid",
        ));
    }
    let (encrypted, consumed) = read_mpi(csid_encrypted, 0)?;
    if consumed != csid_encrypted.len() || encrypted >= n {
        return Err(Error::protocol(
            "Encrypted session MPI is out of range or has trailing data",
        ));
    }
    // MEGA strips leading zeros: modulus-width padding shifts and truncates the SID.
    let plaintext = Zeroizing::new(encrypted.modpow(d, &n).to_bytes_be());
    let sid = plaintext
        .get(..43)
        .ok_or_else(|| Error::protocol("RSA session plaintext is shorter than 43 bytes"))?;
    Ok(b64_url_encode(sid))
}
