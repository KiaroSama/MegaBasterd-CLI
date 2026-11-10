use std::time::Instant;

use sha2::{Digest, Sha256};

use crate::crypto::wire::{b64_url_decode, b64_url_encode};
use crate::error::{Error, Result};
use crate::transfers::control::Control;

pub struct Challenge {
    pub easiness: u8,
    pub token: [u8; 48],
    timestamped: bool,
}

#[cfg(test)]
#[path = "hashcash_tests.rs"]
mod tests;

impl Challenge {
    pub fn parse(header: &str) -> Result<Self> {
        Self::parse_with(header, b64_url_decode)
    }

    fn parse_with(header: &str, decode: impl FnOnce(&str) -> Result<Vec<u8>>) -> Result<Self> {
        if header.len() > 160 {
            return Err(Error::protocol(
                "Hashcash challenge or token exceeds its header bound",
            ));
        }
        let parts: Vec<_> = header.trim().split(':').collect();
        if !matches!(parts.len(), 3 | 4) {
            return Err(Error::protocol("Malformed Hashcash challenge"));
        }
        if parts[0] != "1" {
            return Err(Error::protocol("Unsupported Hashcash version"));
        }
        let easiness = parts[1]
            .parse::<u8>()
            .map_err(|_| Error::protocol("Hashcash easiness is invalid"))?;
        let timestamped = parts.len() == 4;
        if timestamped
            && (parts[2].is_empty()
                || !parts[2].bytes().all(|byte| byte.is_ascii_digit())
                || parts[2].parse::<u64>().is_err())
        {
            return Err(Error::protocol("Hashcash timestamp is invalid"));
        }
        let encoded = parts[parts.len() - 1];
        if encoded.len() > 128 {
            return Err(Error::protocol("Hashcash token bound exceeded"));
        }
        let token = decode(encoded)
            .map_err(|_| Error::protocol("Hashcash token is not valid base64"))?
            .try_into()
            .map_err(|_| Error::protocol("Hashcash token must have 48 bytes"))?;
        Ok(Self {
            easiness,
            token,
            timestamped,
        })
    }

    pub fn threshold(&self) -> u32 {
        (((u32::from(self.easiness) & 0x3f) << 1) + 1) << ((u32::from(self.easiness) >> 6) * 7 + 3)
    }

    pub fn valid(&self, nonce: [u8; 4]) -> bool {
        self.valid_with(nonce, || Ok(())).unwrap_or(false)
    }

    fn valid_with(
        &self,
        nonce: [u8; 4],
        mut checkpoint: impl FnMut() -> Result<()>,
    ) -> Result<bool> {
        checkpoint()?;
        let mut digest = Sha256::new();
        digest.update(nonce);
        let mut batch = [0u8; 48 * 256];
        for token in batch.as_chunks_mut::<48>().0 {
            token.copy_from_slice(&self.token)
        }
        for _ in 0..1024 {
            checkpoint()?;
            digest.update(batch)
        }
        let result = digest.finalize();
        checkpoint()?;
        Ok(u32::from_be_bytes([result[0], result[1], result[2], result[3]]) <= self.threshold())
    }

    pub fn solve(&self, deadline: Instant, control: &Control) -> Result<String> {
        self.solve_with(|| control.checkpoint_until(deadline))
    }

    fn solve_with(&self, mut checkpoint: impl FnMut() -> Result<()>) -> Result<String> {
        let mut nonce = 0u32;
        loop {
            if self.valid_with(nonce.to_be_bytes(), &mut checkpoint)? {
                let token = b64_url_encode(&self.token);
                let nonce = b64_url_encode(&nonce.to_be_bytes());
                return Ok(if self.timestamped {
                    format!("1:{token}:{nonce}")
                } else {
                    format!("1:{}:{token}:{nonce}", self.easiness)
                });
            }
            nonce = nonce.checked_add(1).ok_or(Error::Timeout)?;
        }
    }
}
