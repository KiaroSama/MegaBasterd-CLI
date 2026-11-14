// SPDX-License-Identifier: GPL-3.0-or-later
//! MEGA wire encodings and AES modes. Key wrapping is independent blocks, not CBC.
use aes::cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};
use base64::{
    Engine, alphabet,
    engine::{
        DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig, general_purpose::URL_SAFE_NO_PAD,
    },
};
use cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

const MEGA_BASE64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::RequireNone)
        .with_decode_allow_trailing_bits(true),
);
pub const MAX_ATTRIBUTE_BYTES: usize = 1024 * 1024;

pub fn b64_url_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn b64_url_decode(data: &str) -> Result<Vec<u8>> {
    let normalized: Vec<u8> = data
        .bytes()
        .filter(|&b| b != b',')
        .map(|b| match b {
            b'-' => b'+',
            b'_' => b'/',
            _ => b,
        })
        .collect();
    if normalized
        .iter()
        .any(|b| !b.is_ascii_alphanumeric() && !matches!(b, b'+' | b'/'))
    {
        return Err(Error::invalid("Non-base64 character in MEGA data"));
    }
    MEGA_BASE64
        .decode(normalized)
        .map_err(|_| Error::invalid("Malformed MEGA base64 data"))
}

pub fn bytes_to_a32(data: &[u8]) -> Vec<u32> {
    data.chunks(4)
        .map(|chunk| {
            let mut word = [0; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            u32::from_be_bytes(word)
        })
        .collect()
}

pub fn a32_to_bytes(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_be_bytes()).collect()
}

pub fn a32_to_str(words: &[u32]) -> String {
    b64_url_encode(&a32_to_bytes(words))
}

pub fn str_to_a32(data: &str) -> Result<Vec<u32>> {
    Ok(bytes_to_a32(&b64_url_decode(data)?))
}

// The source's generic CBC helpers accept all three AES key sizes. MEGA file
// content and key structures use AES128 and validate that separately.
pub(crate) enum AesBlock {
    A128(Aes128),
    A192(Aes192),
    A256(Aes256),
}

impl AesBlock {
    pub(crate) fn new(key: &[u8]) -> Result<Self> {
        let bad_key = || Error::invalid("AES key must have 16, 24 or 32 bytes");
        match key.len() {
            16 => Aes128::new_from_slice(key)
                .map(Self::A128)
                .map_err(|_| bad_key()),
            24 => Aes192::new_from_slice(key)
                .map(Self::A192)
                .map_err(|_| bad_key()),
            32 => Aes256::new_from_slice(key)
                .map(Self::A256)
                .map_err(|_| bad_key()),
            _ => Err(bad_key()),
        }
    }

    pub(crate) fn encrypt(&self, block: &mut [u8; 16]) {
        let mut value = Array::from(*block);
        match self {
            Self::A128(c) => c.encrypt_block(&mut value),
            Self::A192(c) => c.encrypt_block(&mut value),
            Self::A256(c) => c.encrypt_block(&mut value),
        }
        block.copy_from_slice(&value);
    }

    fn decrypt(&self, block: &mut [u8; 16]) {
        let mut value = Array::from(*block);
        match self {
            Self::A128(c) => c.decrypt_block(&mut value),
            Self::A192(c) => c.decrypt_block(&mut value),
            Self::A256(c) => c.decrypt_block(&mut value),
        }
        block.copy_from_slice(&value);
    }
}

fn crypt_blocks(data: &[u8], key: &[u8], encrypt: bool, chained: bool) -> Result<Vec<u8>> {
    if !data.len().is_multiple_of(16) {
        return Err(Error::invalid(
            "AES block input must be a multiple of 16 bytes",
        ));
    }
    let cipher = AesBlock::new(key)?;
    let mut output = Vec::with_capacity(data.len());
    let mut previous = Zeroizing::new([0; 16]);
    for input in data.as_chunks::<16>().0 {
        let mut block = Zeroizing::new([0; 16]);
        block.copy_from_slice(input);
        if encrypt {
            if chained {
                for (byte, iv) in block.iter_mut().zip(previous.iter()) {
                    *byte ^= iv;
                }
            }
            cipher.encrypt(&mut block);
            previous.copy_from_slice(&*block);
        } else {
            cipher.decrypt(&mut block);
            if chained {
                for (byte, iv) in block.iter_mut().zip(previous.iter()) {
                    *byte ^= iv;
                }
                previous.copy_from_slice(input);
            }
        }
        output.extend_from_slice(&*block);
    }
    Ok(output)
}

pub fn aes_key_wrap_encrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    crypt_blocks(data, key, true, false)
}
pub fn aes_key_wrap_decrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    crypt_blocks(data, key, false, false)
}
pub fn aes_cbc_encrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    crypt_blocks(data, key, true, true)
}
pub fn aes_cbc_decrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    crypt_blocks(data, key, false, true)
}
pub fn aes_cbc_encrypt_a32(data: &[u32], key: &[u32]) -> Result<Vec<u32>> {
    Ok(bytes_to_a32(&aes_cbc_encrypt(
        &a32_to_bytes(data),
        &a32_to_bytes(key),
    )?))
}
pub fn aes_cbc_decrypt_a32(data: &[u32], key: &[u32]) -> Result<Vec<u32>> {
    Ok(bytes_to_a32(&aes_cbc_decrypt(
        &a32_to_bytes(data),
        &a32_to_bytes(key),
    )?))
}

pub struct MegaCtr(ctr::Ctr64BE<Aes128>);

impl MegaCtr {
    pub fn at_offset(key: &[u8], nonce: &[u8], byte_offset: u64) -> Result<Self> {
        let mut cipher = Self::at_counter(key, nonce, 0)?;
        cipher
            .0
            .try_seek(byte_offset)
            .map_err(|_| Error::invalid("CTR offset exceeds counter range"))?;
        Ok(cipher)
    }

    pub fn at_counter(key: &[u8], nonce: &[u8], counter: u64) -> Result<Self> {
        if key.len() != 16 || nonce.len() != 8 {
            return Err(Error::invalid(
                "MEGA CTR requires a 16-byte key and 8-byte nonce",
            ));
        }
        let mut iv = [0; 16];
        iv[..8].copy_from_slice(nonce);
        let mut cipher = ctr::Ctr64BE::<Aes128>::new_from_slices(key, &iv)
            .map_err(|_| Error::invalid("Invalid MEGA CTR key or nonce"))?;
        cipher
            .try_seek(u128::from(counter) * 16)
            .map_err(|_| Error::invalid("CTR counter exceeds supported range"))?;
        Ok(Self(cipher))
    }

    /// Retains a partially consumed first block across arbitrary short reads.
    pub fn apply(&mut self, data: &mut [u8]) -> Result<()> {
        self.0
            .try_apply_keystream(data)
            .map_err(|_| Error::invalid("CTR counter exhausted"))
    }
}

pub fn make_ctr_cipher(key: &[u8], nonce: &[u8], initial_value: u64) -> Result<MegaCtr> {
    MegaCtr::at_counter(key, nonce, initial_value)
}

pub fn ctr_offset_to_counter(byte_offset: u64) -> Result<u64> {
    if !byte_offset.is_multiple_of(16) {
        return Err(Error::invalid("CTR offset must be a multiple of 16 bytes"));
    }
    Ok(byte_offset / 16)
}

pub fn ctr_crypt_at_offset(key: &[u8], nonce: &[u8], offset: u64, data: &[u8]) -> Result<Vec<u8>> {
    offset
        .checked_add(
            u64::try_from(data.len()).map_err(|_| Error::invalid("CTR input is too large"))?,
        )
        .ok_or_else(|| Error::invalid("CTR byte range overflows"))?;
    let mut output = data.to_vec();
    MegaCtr::at_offset(key, nonce, offset)?.apply(&mut output)?;
    Ok(output)
}

pub fn encrypt_attributes(attributes: &Value, key: &[u8]) -> Result<Vec<u8>> {
    if !attributes.is_object() {
        return Err(Error::invalid("MEGA attributes must be a JSON object"));
    }
    let json = Zeroizing::new(
        serde_json::to_string(attributes)
            .map_err(|_| Error::invalid("Cannot serialize MEGA attributes"))?,
    );
    if json.len() > MAX_ATTRIBUTE_BYTES {
        return Err(Error::invalid("MEGA attributes exceed the size limit"));
    }
    let mut plaintext = Zeroizing::new(b"MEGA".to_vec());
    // Python json.dumps defaults to ensure_ascii, including surrogate pairs.
    // Preserve these wire bytes, not just the logically equivalent JSON value.
    for character in json.chars() {
        if character >= '\u{7f}' {
            let mut units = [0; 2];
            for &unit in character.encode_utf16(&mut units).iter() {
                use std::io::Write;
                write!(&mut *plaintext, "\\u{unit:04x}")
                    .map_err(|_| Error::invalid("Cannot encode MEGA attribute text"))?;
            }
        } else {
            plaintext.push(character as u8);
        }
        if plaintext.len() > MAX_ATTRIBUTE_BYTES {
            return Err(Error::invalid("MEGA attributes exceed the size limit"));
        }
    }
    let padded = plaintext.len().next_multiple_of(16);
    plaintext.resize(padded, 0);
    aes_cbc_encrypt(&plaintext, key)
}

pub fn decrypt_attributes(data: &[u8], key: &[u8]) -> Result<Value> {
    if data.is_empty() || data.len() > MAX_ATTRIBUTE_BYTES || !data.len().is_multiple_of(16) {
        return Err(Error::protocol("Malformed MEGA attribute ciphertext"));
    }
    let plaintext = Zeroizing::new(aes_cbc_decrypt(data, key)?);
    if !plaintext.starts_with(b"MEGA") {
        return Err(Error::integrity("MEGA attribute prefix mismatch"));
    }
    let end = plaintext
        .iter()
        .rposition(|&byte| byte != 0)
        .map_or(4, |n| n + 1);
    let attributes: Value = serde_json::from_slice(&plaintext[4..end])
        .map_err(|_| Error::protocol("Malformed MEGA attribute JSON"))?;
    if !attributes.is_object() {
        return Err(Error::protocol("MEGA attributes are not a JSON object"));
    }
    Ok(attributes)
}
