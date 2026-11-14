use std::{collections::VecDeque, sync::Mutex};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{TryRng, rngs::SysRng};
use zeroize::Zeroizing;

use crate::crypto::wire::b64_url_encode;
use crate::error::{Error, Result, poisoned};

#[cfg(test)]
#[path = "vault_cache_tests.rs"]
mod cache_tests;

const MAGIC: &[u8; 4] = b"MBV2";
const HEADER: usize = 35;
const MAX_SECRET_BYTES: usize = 1024 * 1024;
const MAX_CACHED_KEYS: usize = 32;

struct CachedKey {
    salt: [u8; 16],
    parameters: [u8; 3],
    key: Zeroizing<[u8; 32]>,
}

pub struct Vault {
    passphrase: Zeroizing<Vec<u8>>,
    keys: Mutex<VecDeque<CachedKey>>,
}

impl Vault {
    pub fn new(passphrase: &str) -> Self {
        Self {
            passphrase: Zeroizing::new(passphrase.as_bytes().to_vec()),
            keys: Mutex::new(VecDeque::with_capacity(MAX_CACHED_KEYS)),
        }
    }

    pub(crate) fn require_passphrase(&self) -> Result<()> {
        if self.passphrase.is_empty() {
            return Err(Error::Auth(
                "A nonempty vault passphrase is required".into(),
            ));
        }
        Ok(())
    }

    fn key(&self, salt: &[u8], parameters: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        self.key_with(salt, parameters, |password, salt, parameters, key| {
            let [log_n, r, p] = *parameters;
            let params = scrypt::Params::new(log_n, u32::from(r), u32::from(p))
                .map_err(|_| Error::Corrupt("Encrypted work factor is unsupported".into()))?;
            scrypt::scrypt(password, salt, &params, key)
                .map_err(|_| Error::protocol("Vault key derivation failed"))
        })
    }

    fn key_with(
        &self,
        salt: &[u8],
        parameters: &[u8],
        derive: impl FnOnce(&[u8], &[u8; 16], &[u8; 3], &mut [u8; 32]) -> Result<()>,
    ) -> Result<Zeroizing<[u8; 32]>> {
        let parameters = Self::parameters(parameters)?;
        let salt: [u8; 16] = salt
            .try_into()
            .map_err(|_| Error::Corrupt("Encrypted salt has invalid width".into()))?;
        let mut cached = self.keys.lock().map_err(poisoned)?;
        if let Some(found) = cached
            .iter()
            .find(|entry| entry.salt == salt && entry.parameters == parameters)
        {
            return Ok(found.key.clone());
        }
        // Keep one bounded KDF allocation in flight per vault; eviction drops zeroizing keys.
        let mut key = Zeroizing::new([0u8; 32]);
        derive(&self.passphrase, &salt, &parameters, &mut key)?;
        if cached.len() == MAX_CACHED_KEYS {
            drop(cached.pop_front());
        }
        cached.push_back(CachedKey {
            salt,
            parameters,
            key: key.clone(),
        });
        Ok(key)
    }

    pub fn seal(&self, plaintext: &[u8], context: &[u8]) -> Result<String> {
        self.require_passphrase()?;
        if plaintext.len() > MAX_SECRET_BYTES {
            return Err(Error::invalid("Secret payload exceeds its size limit"));
        }
        let mut header = [0u8; HEADER];
        header[..4].copy_from_slice(MAGIC);
        header[4..7].copy_from_slice(&[15, 8, 1]);
        SysRng
            .try_fill_bytes(&mut header[7..])
            .map_err(|_| Error::protocol("Operating-system randomness is unavailable"))?;
        let key = self.key(&header[7..23], &header[4..7])?;
        let cipher = Aes256Gcm::new_from_slice(&*key)
            .map_err(|_| Error::protocol("Vault encryption initialization failed"))?;
        let mut aad = header.to_vec();
        aad.extend_from_slice(context);
        let nonce: &[u8; 12] = header[23..]
            .try_into()
            .map_err(|_| Error::protocol("Vault nonce width mismatch"))?;
        let ciphertext = cipher
            .encrypt(
                &Nonce::from(*nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::protocol("Vault encryption failed"))?;
        let mut output = header.to_vec();
        output.extend_from_slice(&ciphertext);
        Ok(b64_url_encode(&output))
    }

    pub(crate) fn validate_envelope(encoded: &str) -> Result<()> {
        Self::decode(encoded).map(|_| ())
    }

    fn decode(encoded: &str) -> Result<Vec<u8>> {
        if encoded.len() > (HEADER + MAX_SECRET_BYTES + 16).div_ceil(3) * 4 {
            return Err(Error::Corrupt(
                "Encrypted payload exceeds its size limit".into(),
            ));
        }
        let raw = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| Error::Corrupt("Encrypted payload has invalid encoding".into()))?;
        if raw.len() < HEADER + 16
            || raw.len() > HEADER + MAX_SECRET_BYTES + 16
            || &raw[..4] != MAGIC
        {
            return Err(Error::Corrupt(
                "Encrypted format or work factor is unsupported".into(),
            ));
        }
        Self::parameters(&raw[4..7])?;
        Ok(raw)
    }

    fn parameters(header: &[u8]) -> Result<[u8; 3]> {
        let parameters: [u8; 3] = header
            .try_into()
            .map_err(|_| Error::Corrupt("Encrypted work factor header is invalid".into()))?;
        let [log_n, r, p] = parameters;
        if !(10..=22).contains(&log_n) || !(1..=32).contains(&r) || !(1..=16).contains(&p) {
            return Err(Error::Corrupt(
                "Encrypted work factor is out of range".into(),
            ));
        }
        let blocks = (1u64 << log_n) * u64::from(r);
        // File-controlled costs must fit both the memory and CPU budget before scrypt runs.
        if blocks * 128 > 64 * 1024 * 1024 || blocks * u64::from(p) > 2_097_152 {
            return Err(Error::Corrupt(
                "Encrypted work factor exceeds its resource limit".into(),
            ));
        }
        Ok(parameters)
    }

    pub fn open(&self, encoded: &str, context: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        self.require_passphrase()?;
        let raw = Self::decode(encoded)?;
        let key = self.key(&raw[7..23], &raw[4..7])?;
        let cipher = Aes256Gcm::new_from_slice(&*key)
            .map_err(|_| Error::protocol("Vault encryption initialization failed"))?;
        let mut aad = raw[..HEADER].to_vec();
        aad.extend_from_slice(context);
        let nonce: &[u8; 12] = raw[23..HEADER]
            .try_into()
            .map_err(|_| Error::Corrupt("Encrypted nonce has invalid width".into()))?;
        cipher
            .decrypt(
                &Nonce::from(*nonce),
                Payload {
                    msg: &raw[HEADER..],
                    aad: &aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| {
                Error::Auth(
                    "Wrong vault passphrase or damaged encrypted data; nothing was overwritten"
                        .into(),
                )
            })
    }
}
