// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded MEGA chunk scheduling and plaintext CBC-MAC.
use zeroize::Zeroizing;

use super::wire::AesBlock;
use crate::error::{Error, Result};

pub const CHUNK_SIZES_KB: [u64; 8] = [128, 256, 384, 512, 640, 768, 896, 1024];
pub const MAX_CHUNK_SIZE: u64 = 1024 * 1024;
pub const MAX_CHUNKS: usize = 200_000;
pub const MAX_FILE_SIZE: u64 = 4_718_592 + (MAX_CHUNKS as u64 - 8) * MAX_CHUNK_SIZE;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Chunk {
    pub index: usize,
    pub offset: u64,
    pub size: u64,
}

impl Chunk {
    pub fn end(self) -> Result<u64> {
        self.offset
            .checked_add(self.size)
            .ok_or_else(|| Error::invalid("Chunk byte range overflows"))
    }
}

fn validate_size(file_size: u64) -> Result<()> {
    if file_size > MAX_FILE_SIZE {
        return Err(Error::invalid(
            "Declared file size exceeds the supported chunk bound",
        ));
    }
    Ok(())
}

pub fn chunk_count(file_size: u64) -> Result<usize> {
    validate_size(file_size)?;
    let mut offset = 0;
    let mut count = 0;
    for size in CHUNK_SIZES_KB {
        if offset >= file_size {
            return Ok(count);
        }
        offset += (size * 1024).min(file_size - offset);
        count += 1;
    }
    Ok(count + (file_size - offset).div_ceil(MAX_CHUNK_SIZE) as usize)
}

pub struct Chunks {
    file_size: u64,
    offset: u64,
    index: usize,
}

impl Iterator for Chunks {
    type Item = Chunk;

    fn next(&mut self) -> Option<Chunk> {
        if self.offset >= self.file_size {
            return None;
        }
        let size = CHUNK_SIZES_KB
            .get(self.index)
            .map_or(MAX_CHUNK_SIZE, |kb| kb * 1024)
            .min(self.file_size - self.offset);
        let chunk = Chunk {
            index: self.index,
            offset: self.offset,
            size,
        };
        self.offset += size;
        self.index += 1;
        Some(chunk)
    }
}

pub fn iter_chunks(file_size: u64) -> Result<Chunks> {
    validate_size(file_size)?;
    Ok(Chunks {
        file_size,
        offset: 0,
        index: 0,
    })
}

pub fn chunks_for_range(file_size: u64, start: u64, end: u64) -> Result<Vec<Chunk>> {
    validate_size(file_size)?;
    if start > end || end > file_size {
        return Err(Error::invalid("Requested byte range is outside the file"));
    }
    if start == end {
        return Ok(Vec::new());
    }
    iter_chunks(file_size)?
        .filter_map(|chunk| match chunk.end() {
            Ok(chunk_end) if chunk_end > start && chunk.offset < end => Some(Ok(chunk)),
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        })
        .collect()
}

fn mega_cipher(key: &[u8]) -> Result<AesBlock> {
    if key.len() != 16 {
        return Err(Error::invalid("MEGA MAC requires a 16-byte AES key"));
    }
    AesBlock::new(key)
}

pub fn chunk_mac(plaintext: &[u8], aes_key: &[u8], nonce: &[u8]) -> Result<[u8; 16]> {
    let cipher = mega_cipher(aes_key)?;
    if nonce.len() != 8 {
        return Err(Error::invalid("MEGA MAC nonce must have 8 bytes"));
    }
    if plaintext.len() as u64 > MAX_CHUNK_SIZE {
        return Err(Error::invalid("Chunk plaintext exceeds 1 MiB"));
    }
    // Source empty-file MAC is zero, not nonce||nonce or AES(nonce||nonce).
    if plaintext.is_empty() {
        return Ok([0; 16]);
    }
    let mut state = Zeroizing::new([0; 16]);
    state[..8].copy_from_slice(nonce);
    state[8..].copy_from_slice(nonce);
    for input in plaintext.chunks(16) {
        // The missing bytes of the final block are zero, so XOR changes only
        // the present bytes; no temporary padded plaintext allocation is needed.
        for (byte, plain) in state.iter_mut().zip(input.iter()) {
            *byte ^= plain;
        }
        cipher.encrypt(&mut state);
    }
    Ok(*state)
}

pub fn combine_chunk_macs<T: AsRef<[u8]>>(macs: &[T], aes_key: &[u8]) -> Result<[u8; 16]> {
    let cipher = mega_cipher(aes_key)?;
    if macs.len() > MAX_CHUNKS {
        return Err(Error::invalid("Too many chunk MACs"));
    }
    let mut state = Zeroizing::new([0; 16]);
    for mac in macs {
        let mac = mac.as_ref();
        if mac.len() != 16 {
            return Err(Error::invalid("Chunk MAC must have 16 bytes"));
        }
        for (byte, part) in state.iter_mut().zip(mac.iter()) {
            *byte ^= part;
        }
        cipher.encrypt(&mut state);
    }
    Ok(*state)
}

pub fn condense_mac(file_mac: &[u8]) -> Result<[u32; 2]> {
    let bytes: &[u8; 16] = file_mac
        .try_into()
        .map_err(|_| Error::invalid("File MAC must have 16 bytes"))?;
    let word = |offset: usize| {
        u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ])
    };
    // The source folds adjacent words, NOT the two eight-byte halves.
    Ok([word(0) ^ word(4), word(8) ^ word(12)])
}
