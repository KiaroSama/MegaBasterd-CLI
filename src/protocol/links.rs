// SPDX-License-Identifier: GPL-3.0-or-later
//! Offline MEGA link grammar; service resolution belongs to the transport coordinator.
use super::containers;
use crate::{
    crypto::{keys, wire},
    error::{Error, Result},
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const MAX_LINK_BYTES: usize = 12 * 1024 * 1024;
pub const MAX_OFFLINE_DEPTH: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkType {
    File,
    Folder,
    FileInFolder,
    FolderInFolder,
    PasswordProtected,
    Megacrypter,
    EncryptedContainer,
    ElcContainer,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ParsedLink {
    pub kind: LinkType,
    pub public_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subpath: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_blob: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crypter_server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crypter_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_variant: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_blob: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elc_blob: Option<String>,
}
impl ParsedLink {
    pub fn new(kind: LinkType) -> Self {
        Self {
            kind,
            public_id: String::new(),
            key: None,
            subpath: None,
            encrypted_blob: None,
            crypter_server: None,
            crypter_token: None,
            container_variant: None,
            container_blob: None,
            elc_blob: None,
        }
    }
    pub fn is_folder(&self) -> bool {
        matches!(self.kind, LinkType::Folder | LinkType::FolderInFolder)
    }
    pub fn is_file(&self) -> bool {
        matches!(self.kind, LinkType::File | LinkType::FileInFolder)
    }
    pub fn needs_password(&self) -> bool {
        self.kind == LinkType::PasswordProtected
    }
    pub fn expected_key_bytes(&self) -> Option<usize> {
        match self.kind {
            LinkType::File => Some(32),
            LinkType::Folder | LinkType::FolderInFolder | LinkType::FileInFolder => Some(16),
            _ => None,
        }
    }
}
fn pattern(expression: &str) -> Result<Regex> {
    Regex::new(expression).map_err(|_| Error::protocol("Invalid built-in link grammar"))
}

pub fn parse_link(input: &str) -> Result<ParsedLink> {
    if input.len() > MAX_LINK_BYTES {
        return Err(Error::invalid("Link exceeds the supported envelope size"));
    }
    let mut text = input.trim();
    if let Ok(url) = url::Url::parse(text) {
        if matches!(url.host_str(), Some("mega.nz" | "mega.co.nz")) {
            text = text.trim_end_matches('/');
        }
    }
    if let Some(m) = pattern(r"^https?://mega(?:\.co)?\.nz/#P!(.+)$")?.captures(text) {
        let mut result = ParsedLink::new(LinkType::PasswordProtected);
        result.encrypted_blob = Some(m[1].to_owned());
        return Ok(result);
    }
    if let Some(m) = pattern(r"(?i)^mega://(f?enc[0-9]?)\?([A-Za-z0-9+/=_\-]+)\s*$")?.captures(text)
    {
        let mut result = ParsedLink::new(LinkType::EncryptedContainer);
        result.container_variant = Some(m[1].to_ascii_lowercase());
        result.container_blob = Some(m[2].to_owned());
        return Ok(result);
    }
    if let Some(m) = pattern(r"(?i)^mega://elc\?([A-Za-z0-9+/=,_\-]+)\s*$")?.captures(text) {
        let mut result = ParsedLink::new(LinkType::ElcContainer);
        result.elc_blob = Some(m[1].to_owned());
        return Ok(result);
    }
    if let Some(m) = pattern(r"^mc://([^/]+)/(.+)$")?.captures(text) {
        let mut result = ParsedLink::new(LinkType::Megacrypter);
        result.crypter_server = Some(m[1].to_owned());
        result.crypter_token = Some(m[2].to_owned());
        return Ok(result);
    }
    if let Some(m) = pattern(r"^https?://mega(?:\.co)?\.nz/folder/([^#?/]+)(?:#([^!?/]+))?(?:/(file|folder)/([^#?/]+))?$")?.captures(text) {
        let kind = match m.get(3).map(|v|v.as_str()) { Some("file") => LinkType::FileInFolder, Some("folder") => LinkType::FolderInFolder, _ => LinkType::Folder };
        let mut result = ParsedLink::new(kind); result.public_id = m[1].to_owned(); result.key = m.get(2).map(|v|v.as_str().to_owned()); result.subpath = m.get(4).map(|v|v.as_str().to_owned()); return Ok(result);
    }
    if let Some(m) =
        pattern(r"^https?://mega(?:\.co)?\.nz/file/([^#?/]+)(?:#([^!?/]+))?(?:!(.+))?$")?
            .captures(text)
    {
        let mut result = ParsedLink::new(LinkType::File);
        result.public_id = m[1].to_owned();
        result.key = m.get(2).map(|v| v.as_str().to_owned());
        result.subpath = m.get(3).map(|v| v.as_str().to_owned());
        return Ok(result);
    }
    if let Some(m) =
        pattern(r"^https?://mega(?:\.co)?\.nz/#(?:F\*|N!)([^!]+)!([^!]+)!(.+)$")?.captures(text)
    {
        let mut result = ParsedLink::new(LinkType::FileInFolder);
        result.public_id = m[2].to_owned();
        result.key = Some(m[3].to_owned());
        result.subpath = Some(m[1].to_owned());
        return Ok(result);
    }
    if let Some(m) =
        pattern(r"^https?://mega(?:\.co)?\.nz/#F!([^!@]+)(?:@([^!]+))?!([^!]+)(?:!(.+))?$")?
            .captures(text)
    {
        let kind = if m.get(4).is_some() {
            LinkType::FileInFolder
        } else if m.get(2).is_some() {
            LinkType::FolderInFolder
        } else {
            LinkType::Folder
        };
        let mut result = ParsedLink::new(kind);
        result.public_id = m[1].to_owned();
        result.key = Some(m[3].to_owned());
        result.subpath = m.get(4).or_else(|| m.get(2)).map(|v| v.as_str().to_owned());
        return Ok(result);
    }
    if let Some(m) = pattern(r"^https?://mega(?:\.co)?\.nz/#!([^!]+)!(.+)$")?.captures(text) {
        let mut result = ParsedLink::new(LinkType::File);
        result.public_id = m[1].to_owned();
        result.key = Some(m[2].to_owned());
        return Ok(result);
    }
    if let Some(m) = pattern(r"^https?://([^/]+)/!([A-Za-z0-9_\-]+)$")?.captures(text) {
        if !text.contains("mega.nz") && !text.contains("mega.co.nz") {
            let mut result = ParsedLink::new(LinkType::Megacrypter);
            result.crypter_server = Some(m[1].to_owned());
            result.crypter_token = Some(m[2].to_owned());
            return Ok(result);
        }
    }
    Err(Error::invalid(
        "Not a recognizable MEGA or supported container link",
    ))
}

pub fn require_link_key(parsed: &ParsedLink) -> Result<Zeroizing<Vec<u8>>> {
    let key = parsed
        .key
        .as_deref()
        .filter(|k| !k.is_empty())
        .ok_or_else(|| {
            Error::invalid("Link needs its decryption key after the fragment separator")
        })?;
    let expected = parsed
        .expected_key_bytes()
        .ok_or_else(|| Error::invalid("Link has no raw MEGA key"))?;
    if !key
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(Error::invalid(
            "MEGA link key must be unpadded URL-safe base64",
        ));
    }
    let decoded = Zeroizing::new(wire::b64_url_decode(key)?);
    if decoded.len() != expected {
        return Err(Error::invalid(format!(
            "MEGA link key has {} bytes; expected {expected} bytes",
            decoded.len()
        )));
    }
    Ok(decoded)
}
pub fn resolve_password_link(parsed: &ParsedLink, password: &str) -> Result<ParsedLink> {
    if !parsed.needs_password() {
        return Err(Error::invalid("Not a protected MEGA link"));
    }
    let blob = parsed
        .encrypted_blob
        .as_deref()
        .ok_or_else(|| Error::invalid("Protected link has no payload"))?;
    let decoded = keys::decrypt_password_link(blob, password)?;
    let mut result = ParsedLink::new(if decoded.node_type == 0 {
        LinkType::File
    } else {
        LinkType::Folder
    });
    result.public_id = wire::b64_url_encode(&decoded.public_handle);
    result.key = Some(wire::b64_url_encode(&decoded.raw_key));
    Ok(result)
}
pub fn resolve_offline(parsed: &ParsedLink, password: Option<&str>) -> Result<ParsedLink> {
    let mut current = parsed.clone();
    for _ in 0..MAX_OFFLINE_DEPTH {
        current = match current.kind {
            LinkType::PasswordProtected => resolve_password_link(
                &current,
                password.ok_or_else(|| Error::invalid("Protected link requires a password"))?,
            )?,
            LinkType::EncryptedContainer => containers::resolve_encrypted_container_link(&current)?,
            _ => return Ok(current),
        };
    }
    if matches!(
        current.kind,
        LinkType::PasswordProtected | LinkType::EncryptedContainer
    ) {
        Err(Error::invalid(
            "Offline encrypted link nesting exceeds the supported depth",
        ))
    } else {
        Ok(current)
    }
}
pub fn normalize_link(input: &str) -> Result<String> {
    let parsed = parse_link(input)?;
    let key = parsed
        .key
        .as_deref()
        .map_or(String::new(), |k| format!("#{k}"));
    Ok(match parsed.kind {
        LinkType::File => format!("https://mega.nz/file/{}{key}", parsed.public_id),
        LinkType::Folder => format!("https://mega.nz/folder/{}{key}", parsed.public_id),
        LinkType::FileInFolder | LinkType::FolderInFolder => format!(
            "https://mega.nz/folder/{}#{}/{}/{}",
            parsed.public_id,
            parsed.key.as_deref().unwrap_or("None"),
            if parsed.kind == LinkType::FileInFolder {
                "file"
            } else {
                "folder"
            },
            parsed.subpath.as_deref().unwrap_or("None")
        ),
        _ => input.to_owned(),
    })
}
pub fn is_mega_url(input: &str) -> bool {
    parse_link(input).is_ok()
}
