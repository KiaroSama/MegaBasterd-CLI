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
    // Upstream 3bb42c7: let MEGA choose its attribute storage endpoint.
    json!({"a":"ufa","s":size})
}

fn retry_upload<T>(
    control: &Control,
    mut upload: impl FnMut() -> Result<T>,
    mut wait: impl FnMut(std::time::Duration) -> Result<()>,
) -> Result<T> {
    for attempt in 0..5 {
        control.checkpoint()?;
        match upload() {
            Ok(value) => return Ok(value),
            Err(error)
                if attempt < 4
                    && (error.retryable_network()
                        || matches!(error, Error::Mega { code: -3 | -4, .. })) =>
            {
                wait(std::time::Duration::from_secs(1 << attempt))?;
            }
            Err(error) => return Err(error),
        }
    }
    Err(Error::protocol("Thumbnail retry budget exhausted"))
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
    // Reuse the thumbnail backend's classification so attachment coverage cannot
    // drift from what generation actually supports (m4v and 3gp were missing here).
    if !thumbnails::supports(&extension) {
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
    let handle = retry_upload(
        control,
        || {
            let mut reply = cloud.api.transport.send(
                Method::POST,
                endpoint.clone(),
                HeaderMap::new(),
                Some(ciphertext.clone()),
                false,
            )?;
            let status = reply.response.status();
            if status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                return Err(Error::mega(
                    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                        -4
                    } else {
                        -3
                    },
                ));
            }
            if !status.is_success() {
                return Err(Error::protocol(
                    "Thumbnail upload returned an unsuccessful HTTP status",
                ));
            }
            let handle = reply.bytes(8)?;
            if handle.len() != 8 {
                return Err(Error::protocol("Thumbnail handle must contain eight bytes"));
            }
            reply.credit()?;
            Ok(handle)
        },
        |delay| control.wait(delay),
    )?;
    let command = attachment(node, &handle)?;
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
