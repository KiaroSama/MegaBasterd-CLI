// SPDX-License-Identifier: GPL-3.0-or-later
//! Pure local encrypted-container stages. Never performs network or credential lookup.
//! Public protocol constants originate in MegaBasterd CryptTools, retained as protocol provenance.
use super::links::{self, LinkType, ParsedLink};
use crate::{
    crypto::wire,
    error::{Error, Result},
};
use aes::{
    Aes128, Aes192, Aes256,
    cipher::{Array, BlockCipherDecrypt, KeyInit},
};
use base64::{
    Engine, alphabet,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig, general_purpose::STANDARD},
};
use flate2::bufread::GzDecoder;
use hmac::Hmac;
use regex::Regex;
use serde_json::Value;
use sha2::Sha256;
use std::io::Read;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const MAX_ELC_COMPRESSED_BYTES: usize = 1 << 20;
pub const MAX_ELC_DECOMPRESSED_BYTES: usize = 8 << 20;
pub const MAX_SERVICE_BYTES: usize = 2_000_000;
pub const MAX_MEGACRYPTER_PBKDF2_ITERATIONS: u32 = 200_000;
pub const DLC_SERVICE_URL: &str = "https://service.jdownloader.org/dlcrypt/service.php";
pub const DLC_REV: &str = "34065";
const ENC_KEYS: [&str; 2] = [
    "6B316F36416C2D316B7A3F217A30357958585858585858585858585858585858",
    "ED1F4C200B35139806B260563B3D3876F011B4750F3A1A4A5EFD0BBE67554B44",
];
const ENC_IV: &str = "79F10A01844A0B27FF5B2D4E0ED3163E";
const DLC_MASTER_KEY: &str = "447E787351E60E2C6A96B3964BE0C9BD";
const CONTAINER_BASE64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

fn decode_base64(text: &str, limit: usize) -> Result<Vec<u8>> {
    if text.len() > limit.saturating_mul(2) {
        return Err(Error::invalid("Container base64 exceeds its input limit"));
    }
    let normalized: String = text
        .trim()
        .chars()
        .filter(|&c| c != ',' && !c.is_ascii_whitespace())
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            _ => c,
        })
        .collect();
    let bytes = CONTAINER_BASE64
        .decode(normalized)
        .map_err(|_| Error::invalid("Malformed container base64"))?;
    if bytes.len() > limit {
        return Err(Error::invalid("Decoded container exceeds its size limit"));
    }
    Ok(bytes)
}
fn constant(text: &str) -> Result<Vec<u8>> {
    hex::decode(text).map_err(|_| Error::protocol("Invalid built-in container protocol constant"))
}
fn cbc_decrypt(data: &[u8], key: &[u8], iv: &[u8], pkcs7: bool) -> Result<Zeroizing<Vec<u8>>> {
    if (pkcs7 && data.is_empty()) || !data.len().is_multiple_of(16) || iv.len() != 16 {
        return Err(Error::invalid("Malformed AES-CBC container block or IV"));
    }
    let mut previous = [0; 16];
    previous.copy_from_slice(iv);
    let mut plain = Zeroizing::new(Vec::with_capacity(data.len()));
    enum Cipher {
        A128(Aes128),
        A192(Aes192),
        A256(Aes256),
    }
    let bad = || Error::invalid("Container AES key must have 16, 24 or 32 bytes");
    let cipher = match key.len() {
        16 => Cipher::A128(Aes128::new_from_slice(key).map_err(|_| bad())?),
        24 => Cipher::A192(Aes192::new_from_slice(key).map_err(|_| bad())?),
        32 => Cipher::A256(Aes256::new_from_slice(key).map_err(|_| bad())?),
        _ => return Err(bad()),
    };
    for input in data.as_chunks::<16>().0 {
        let mut block = Array::from([0; 16]);
        block.copy_from_slice(input);
        match &cipher {
            Cipher::A128(c) => c.decrypt_block(&mut block),
            Cipher::A192(c) => c.decrypt_block(&mut block),
            Cipher::A256(c) => c.decrypt_block(&mut block),
        };
        for (byte, old) in block.iter_mut().zip(previous.iter()) {
            *byte ^= old;
        }
        plain.extend_from_slice(&block);
        previous.copy_from_slice(input);
    }
    if pkcs7 {
        let padding = usize::from(
            *plain
                .last()
                .ok_or_else(|| Error::integrity("Empty padded ciphertext"))?,
        );
        if padding == 0
            || padding > 16
            || padding > plain.len()
            || !plain[plain.len() - padding..]
                .iter()
                .all(|&b| usize::from(b) == padding)
        {
            return Err(Error::integrity("Invalid encrypted-container padding"));
        }
        let length = plain.len() - padding;
        plain.truncate(length);
    }
    Ok(plain)
}
fn decoded_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}
fn strip_zeros(bytes: &[u8]) -> &[u8] {
    let end = bytes.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    &bytes[..end]
}
fn checked_service_url(text: &str) -> Result<()> {
    let malformed_authority = std::cell::Cell::new(false);
    let note = |violation| {
        if violation == url::SyntaxViolation::ExpectedDoubleSlash {
            malformed_authority.set(true);
        }
    };
    let url = url::Url::options()
        .syntax_violation_callback(Some(&note))
        .parse(text)
        .map_err(|_| Error::invalid("Malformed container service URL"))?;
    if malformed_authority.get() {
        return Err(Error::invalid("Malformed container service authority"));
    }
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(Error::invalid(
            "Container service requires HTTPS without embedded credentials",
        ));
    }
    Ok(())
}

pub fn resolve_encrypted_container_link(parsed: &ParsedLink) -> Result<ParsedLink> {
    if parsed.kind != LinkType::EncryptedContainer {
        return Err(Error::invalid("Not an encrypted link container"));
    }
    let raw = parsed
        .container_blob
        .as_deref()
        .ok_or_else(|| Error::invalid("Encrypted container has no payload"))?;
    let ciphertext = decode_base64(raw, MAX_ELC_COMPRESSED_BYTES)?;
    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(16) {
        return Err(Error::invalid(
            "Encrypted link payload must contain complete AES blocks",
        ));
    }
    let variant = parsed.container_variant.as_deref().unwrap_or("enc");
    let order = if variant.ends_with('2') {
        [1, 0]
    } else {
        [0, 1]
    };
    let iv = constant(ENC_IV)?;
    for index in order {
        let key = constant(ENC_KEYS[index])?;
        let plain = cbc_decrypt(&ciphertext, &key, &iv, false)?;
        // Full URLs from source use zero padding; upstream fragments commonly usePKCS7.
        let padding = plain.last().copied().map_or(0, usize::from);
        let valid_padding = padding > 0
            && padding <= 16
            && padding <= plain.len()
            && plain[plain.len() - padding..]
                .iter()
                .all(|&b| usize::from(b) == padding);
        let payload = if valid_padding {
            &plain[..plain.len() - padding]
        } else {
            strip_zeros(&plain)
        };
        let text = decoded_text(payload);
        let text = text.trim();
        let candidate = if text.starts_with("https://mega") || text.starts_with("http://mega") {
            text.to_owned()
        } else if text.starts_with("mega.nz") {
            format!("https://{text}")
        } else if text.starts_with('!') {
            format!(
                "https://mega.nz/#{}{text}",
                if variant.starts_with('f') { "F" } else { "" }
            )
        } else if text.starts_with('#') {
            format!("https://mega.nz/{text}")
        } else {
            continue;
        };
        if let Ok(link) = links::parse_link(&candidate) {
            return Ok(link);
        }
    }
    Err(Error::integrity(
        "Cannot decrypt the encrypted MEGA link container",
    ))
}

pub struct ElcPayload {
    pub encrypted_links: Vec<u8>,
    pub service_url: String,
    pub data_token: String,
}
struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(n)
            .ok_or_else(|| Error::invalid("Container cursor size overflows"))?;
        let part = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| Error::invalid("Truncated ELC envelope"))?;
        self.offset = end;
        Ok(part)
    }
    fn le16(&mut self) -> Result<usize> {
        let p = self.take(2)?;
        Ok(usize::from(u16::from_le_bytes([p[0], p[1]])))
    }
    fn le32(&mut self) -> Result<usize> {
        let p = self.take(4)?;
        usize::try_from(u32::from_le_bytes([p[0], p[1], p[2], p[3]]))
            .map_err(|_| Error::invalid("ELC payload length cannot fit this platform"))
    }
}
pub fn decode_elc_payload(parsed: &ParsedLink) -> Result<ElcPayload> {
    if parsed.kind != LinkType::ElcContainer {
        return Err(Error::invalid("Not an ELC envelope"));
    }
    let raw = decode_base64(
        parsed
            .elc_blob
            .as_deref()
            .ok_or_else(|| Error::invalid("ELC envelope has no data"))?,
        MAX_ELC_DECOMPRESSED_BYTES + 1,
    )?;
    let (&marker, payload) = raw
        .split_first()
        .ok_or_else(|| Error::invalid("Empty ELC envelope"))?;

    let inflated = if marker == 0x70 {
        if payload.len() > MAX_ELC_COMPRESSED_BYTES {
            return Err(Error::invalid("Compressed ELC envelope exceeds 1 MiB"));
        }
        let mut decoder = GzDecoder::new(payload);
        let mut bytes = Vec::new();
        decoder
            .by_ref()
            .take((MAX_ELC_DECOMPRESSED_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::invalid("Corrupt or truncated gzip ELC envelope"))?;
        if bytes.len() > MAX_ELC_DECOMPRESSED_BYTES {
            return Err(Error::invalid("ELC envelope expands beyond 8 MiB"));
        }
        bytes
    } else if marker == 0xb9 {
        payload.to_vec()
    } else {
        return Err(Error::invalid("Bad ELC marker"));
    };
    if inflated.len() > MAX_ELC_DECOMPRESSED_BYTES {
        return Err(Error::invalid("ELC envelope exceeds 8 MiB"));
    }
    let mut cursor = Cursor {
        bytes: &inflated,
        offset: 0,
    };
    let count = cursor.le32()?;
    let encrypted_links = cursor.take(count)?.to_vec();
    let count = cursor.le16()?;
    let service_url = std::str::from_utf8(cursor.take(count)?)
        .map_err(|_| Error::invalid("ELC service URL is not UTF8"))?
        .trim()
        .to_owned();
    checked_service_url(&service_url)?;
    let count = cursor.le16()?;
    let data_token = std::str::from_utf8(cursor.take(count)?)
        .map_err(|_| Error::invalid("ELC token is not UTF8"))?
        .to_owned();
    Ok(ElcPayload {
        encrypted_links,
        service_url,
        data_token,
    })
}
pub fn decrypt_elc_links(payload: &ElcPayload, decrypt_key: &str) -> Result<Vec<String>> {
    let material = Zeroizing::new(decode_base64(decrypt_key, MAX_SERVICE_BYTES)?);
    if material.len() < 24 {
        return Err(Error::invalid("ELC decrypt key is shorter than 24 bytes"));
    }
    let mut iv = [0; 16];
    iv[..8].copy_from_slice(&material[16..24]);
    let plain = cbc_decrypt(&payload.encrypted_links, &material[..16], &iv, false)?;
    let text = decoded_text(strip_zeros(&plain));
    let mut links = Vec::new();
    for part in text
        .trim()
        .split('|')
        .map(str::trim)
        .filter(|p| !p.is_empty())
    {
        if links.len() >= 200_000 {
            return Err(Error::invalid("ELC link count exceeds its bound"));
        }
        let low = part.to_ascii_lowercase();
        links.push(
            if low.starts_with("http://")
                || low.starts_with("https://")
                || low.starts_with("mega://")
                || low.starts_with("mc://")
            {
                part.to_owned()
            } else {
                format!("https://mega.nz/{}", part.trim_start_matches('/'))
            },
        );
    }
    Ok(links)
}

#[derive(Clone)]
pub struct MegaCrypterInfo {
    pub name: Option<String>,
    pub size: Option<u64>,
    pub key: Option<String>,
    pub pass_hash: Option<String>,
    pub noexpire_token: Option<String>,
    pub inline_url: Option<String>,
    pub raw: Value,
}
impl MegaCrypterInfo {
    pub fn underlying_link(&self) -> Option<String> {
        self.inline_url
            .as_deref()
            .and_then(|url| links::normalize_link(url).ok())
            .or_else(|| {
                let id = string(&self.raw, "file_id").or_else(|| string(&self.raw, "id"))?;
                let key = string(&self.raw, "file_key").or_else(|| self.key.clone())?;
                links::normalize_link(&format!("https://mega.nz/file/{id}#{key}")).ok()
            })
    }
}
fn string(body: &Value, name: &str) -> Option<String> {
    body.get(name)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}
pub fn inline_megacrypter_link(body: &Value) -> Option<String> {
    ["url", "link", "mega_url", "megaurl", "mega_link"]
        .iter()
        .find_map(|key| string(body, key))
}
pub(crate) fn megacrypter_rejected(body: &Value) -> bool {
    ["error", "err"].iter().any(|key| {
        body.get(*key)
            .is_some_and(|v| !(v.is_null() || v == "" || v == false || v == 0))
    })
}
fn verify_body(body: &Value) -> Result<()> {
    if !body.is_object() {
        return Err(Error::protocol(
            "MegaCrypter response must be a JSON object",
        ));
    }
    if megacrypter_rejected(body) {
        return Err(Error::protocol(
            "MegaCrypter service rejected the operation",
        ));
    }
    Ok(())
}
fn field(body: &mut Value, name: &str, key: &[u8], iv: &[u8], raw_key: bool) -> Result<()> {
    if let Some(encoded) = string(body, name) {
        let cipher = decode_base64(&encoded, MAX_SERVICE_BYTES)?;
        let plain = cbc_decrypt(&cipher, key, iv, true)?;
        body[name] = Value::String(if raw_key {
            wire::b64_url_encode(&plain)
        } else {
            decoded_text(&plain)
        });
    }
    Ok(())
}
pub fn decrypt_megacrypter_info(body: &Value, password: Option<&str>) -> Result<MegaCrypterInfo> {
    verify_body(body)?;
    let inline_url = inline_megacrypter_link(body);
    let mut raw = body.clone();
    let mut pass_hash = None;
    if let Some(descriptor) = body
        .get("pass")
        .filter(|v| !v.is_null() && *v != "" && *v != false)
    {
        let descriptor = descriptor
            .as_str()
            .ok_or_else(|| Error::invalid("Malformed MegaCrypter password descriptor"))?;
        if descriptor.len() > MAX_SERVICE_BYTES {
            return Err(Error::invalid(
                "MegaCrypter password descriptor exceeds its bound",
            ));
        }
        let password = password
            .filter(|p| !p.is_empty())
            .ok_or_else(|| Error::invalid("MegaCrypter link requires a password"))?;
        let parts: Vec<_> = descriptor.splitn(5, '#').collect();
        if parts.len() != 4 {
            return Err(Error::invalid("Malformed MegaCrypter password descriptor"));
        }
        let power: u32 = parts[0]
            .parse()
            .map_err(|_| Error::invalid("Malformed MegaCrypter iteration exponent"))?;
        let rounds = 1u32
            .checked_shl(power)
            .filter(|&n| n <= MAX_MEGACRYPTER_PBKDF2_ITERATIONS)
            .ok_or_else(|| Error::invalid("MegaCrypter requests too many password iterations"))?;
        let check = decode_base64(parts[1], MAX_SERVICE_BYTES)?;
        let salt = decode_base64(parts[2], MAX_SERVICE_BYTES)?;
        let iv = decode_base64(parts[3], 16)?;
        if iv.len() != 16 {
            return Err(Error::invalid("MegaCrypter password IV must have 16 bytes"));
        }
        let mut key = Zeroizing::new([0; 32]);
        pbkdf2::pbkdf2::<Hmac<Sha256>>(password.as_bytes(), &salt, rounds, &mut *key)
            .map_err(|_| Error::protocol("Cannot initialize MegaCrypter derivation"))?;
        let checked = cbc_decrypt(&check, &*key, &iv, true)
            .map_err(|_| Error::integrity("Wrong MegaCrypter password"))?;
        if checked.len() != 32 || !bool::from(checked.as_slice().ct_eq(key.as_slice())) {
            return Err(Error::integrity("Wrong MegaCrypter password"));
        }
        field(&mut raw, "key", &*key, &iv, true)?;
        field(&mut raw, "name", &*key, &iv, false)?;
        field(&mut raw, "path", &*key, &iv, false)?;
        pass_hash = Some(STANDARD.encode(*key));
    }
    let name = string(&raw, "name")
        .map(|name| format!("{}{name}", string(&raw, "path").unwrap_or_default()));
    let size = raw.get("size").and_then(|v| {
        v.as_u64()
            .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
    });
    let noexpire_token =
        string(&raw, "expire").map(|s| s.split('#').nth(1).unwrap_or(&s).to_owned());
    let key = string(&raw, "key");
    Ok(MegaCrypterInfo {
        name,
        size,
        key,
        pass_hash,
        noexpire_token,
        inline_url,
        raw,
    })
}
pub fn decrypt_megacrypter_download_url(body: &Value, info: &MegaCrypterInfo) -> Result<String> {
    verify_body(body)?;
    let encoded = string(body, "url")
        .ok_or_else(|| Error::protocol("MegaCrypter download response has no URL"))?;
    let url = if let Some(pass_hash) = &info.pass_hash {
        let key = Zeroizing::new(decode_base64(pass_hash, 32)?);
        let iv = decode_base64(
            &string(body, "pass")
                .ok_or_else(|| Error::protocol("MegaCrypter encrypted URL has no IV"))?,
            16,
        )?;
        let cipher = decode_base64(&encoded, MAX_SERVICE_BYTES)?;
        decoded_text(&cbc_decrypt(&cipher, &key, &iv, true)?)
    } else {
        encoded
    };
    checked_service_url(&url)?;
    Ok(url)
}

pub struct DlcRequest {
    pub id: String,
    pub encrypted_data: String,
}
pub fn parse_dlc_request(data: &str) -> Result<DlcRequest> {
    if data.len() > MAX_ELC_DECOMPRESSED_BYTES {
        return Err(Error::invalid("DLC container exceeds its size bound"));
    }
    let text: String = data.chars().filter(|c| !c.is_whitespace()).collect();
    if text.len() <= 88 || !text.is_ascii() {
        return Err(Error::invalid("DLC container is too short or not ASCII"));
    }
    let split = text.len() - 88;
    Ok(DlcRequest {
        id: text[split..].to_owned(),
        encrypted_data: text[..split].to_owned(),
    })
}
pub fn decrypt_dlc_response(request: &DlcRequest, key_response: &str) -> Result<Vec<String>> {
    if key_response.len() > MAX_SERVICE_BYTES {
        return Err(Error::protocol("DLC key response exceeds its bound"));
    }
    let pattern = Regex::new(r"(?is)<\s*rc\s*>(.+?)<\s*/\s*rc\s*>")
        .map_err(|_| Error::protocol("Invalid built-in DLC key grammar"))?;
    let encoded = pattern
        .captures(key_response)
        .and_then(|m| m.get(1))
        .ok_or_else(|| Error::protocol("DLC service did not return a key"))?;
    let encrypted_key = decode_base64(encoded.as_str(), MAX_SERVICE_BYTES)?;
    let master = constant(DLC_MASTER_KEY)?;
    let decrypted_key = Zeroizing::new(wire::aes_key_wrap_decrypt(&encrypted_key, &master)?);
    let keytext = decoded_text(strip_zeros(&decrypted_key));
    let key = Zeroizing::new(decode_base64(keytext.trim(), 32)?);
    let cipher = decode_base64(&request.encrypted_data, MAX_ELC_DECOMPRESSED_BYTES)?;
    let plain = cbc_decrypt(&cipher, &key, &key, false)?;
    let xml_b64 = decoded_text(strip_zeros(&plain));
    let xml = decode_base64(xml_b64.trim(), MAX_ELC_DECOMPRESSED_BYTES)?;
    let xml = decoded_text(&xml);
    // Source DLC format is deliberately the simple file/url subset; no DTD or entity expansion.
    let files = Regex::new(r"(?is)<\s*file\s*>(.+?)<\s*/\s*file\s*>")
        .map_err(|_| Error::protocol("Invalid built-in DLC file grammar"))?;
    let urls = Regex::new(r"(?is)<\s*url\s*>(.+?)<\s*/\s*url\s*>")
        .map_err(|_| Error::protocol("Invalid built-in DLC URL grammar"))?;
    let mut output = Vec::new();
    for file in files.captures_iter(&xml) {
        for value in urls.captures_iter(&file[1]) {
            if output.len() >= 200_000 {
                return Err(Error::invalid("DLC URL count exceeds its bound"));
            }
            output.push(decoded_text(&decode_base64(&value[1], MAX_SERVICE_BYTES)?));
        }
    }
    Ok(output)
}
