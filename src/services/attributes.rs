use std::path::Path;

use reqwest::{Method, header::HeaderMap};
use serde_json::{Value, json};
use url::Url;
use zeroize::Zeroizing;

use super::thumbnails;
use crate::crypto::{keys, wire};
use crate::error::{Error, Result};
use crate::protocol::{api::string, cloud::Cloud};
use crate::transfers::control::Control;

const MAX_BYTES: usize = 1024 * 1024;

#[derive(Debug, serde::Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Attachment {
    NotApplicable,
    Attached {
        #[serde(skip_serializing_if = "Option::is_none")]
        warning: Option<String>,
    },
}

pub fn encrypt_thumbnail(jpeg: &[u8], raw_key: &[u8]) -> Result<Vec<u8>> {
    if jpeg.is_empty() || jpeg.len() > MAX_BYTES || raw_key.len() != 32 {
        return Err(Error::invalid(
            "Thumbnail bytes or file key exceed the attribute contract",
        ));
    }
    let key = keys::unpack_file_key(&wire::bytes_to_a32(raw_key))?;
    let mut padded = Zeroizing::new(jpeg.to_vec());
    padded.resize(jpeg.len().next_multiple_of(16), 0);
    wire::aes_cbc_encrypt(&padded, key.aes_key.as_slice())
}

pub fn upload_ticket(size: usize) -> Value {
    json!({"a":"ufa","s":size,"ssl":2})
}

pub fn attachment(node: &str, handle: &[u8]) -> Result<Value> {
    if node.is_empty() || handle.len() != 8 {
        return Err(Error::protocol(
            "Thumbnail attachment needs a node and eight-byte attribute handle",
        ));
    }
    Ok(json!({"a":"pfa","n":node,"fa":format!("0*{}",wire::b64_url_encode(handle))}))
}

pub fn attach(
    cloud: &mut Cloud,
    source: &Path,
    node: &str,
    raw_key: &[u8],
    control: &Control,
) -> Result<Attachment> {
    let extension = source
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if !matches!(
        extension.as_str(),
        "jpg"
            | "jpeg"
            | "png"
            | "gif"
            | "bmp"
            | "webp"
            | "tiff"
            | "mp4"
            | "mkv"
            | "webm"
            | "mov"
            | "avi"
            | "mpeg"
            | "mpg"
            | "vob"
            | "ts"
            | "m2ts"
            | "flv"
            | "wmv"
            | "asf"
            | "mp3"
            | "flac"
            | "m4a"
            | "m4b"
            | "ogg"
            | "opus"
            | "wav"
            | "aif"
            | "aiff"
    ) {
        return Ok(Attachment::NotApplicable);
    }
    let ffmpeg = std::env::var_os("MEGABASTERD_FFMPEG")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| "ffmpeg".into());
    let thumbnail = thumbnails::generate_thumbnail(source, Some(&ffmpeg), control)?;
    // The MEGA thumbnail contract is square; standalone local thumbnails retain source aspect ratio.
    let jpeg = thumbnails::square(&thumbnail)?;
    let ciphertext = encrypt_thumbnail(&jpeg, raw_key)?;
    control.checkpoint()?;
    let ticket = cloud.api.request(upload_ticket(ciphertext.len()), &[])?;
    let endpoint = Url::parse(string(&ticket, "p")?)
        .map_err(|_| Error::protocol("Thumbnail upload URL is invalid"))?;
    let mut reply = cloud.api.transport.send(
        Method::POST,
        endpoint,
        HeaderMap::new(),
        Some(ciphertext),
        false,
    )?;
    if !reply.response.status().is_success() {
        return Err(Error::protocol(
            "Thumbnail upload returned an unsuccessful HTTP status",
        ));
    }
    let handle = reply.bytes(8)?;
    let command = attachment(node, &handle)?;
    reply.credit()?;
    control.checkpoint()?;
    cloud.api.request(command, &[])?;
    cloud.invalidate();
    Ok(Attachment::Attached {
        warning: thumbnail.warning,
    })
}

#[cfg(test)]
#[path = "attribute_peer_tests.rs"]
mod peer_tests;
