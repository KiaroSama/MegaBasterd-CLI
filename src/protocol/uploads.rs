use serde_json::{Value, json};

use crate::crypto::wire;
use crate::error::{Error, Result};

pub const MAX_TOKEN_BYTES: usize = 4096;

pub fn validate_token(token: &str) -> Result<()> {
    if token.is_empty()
        || token.len() > MAX_TOKEN_BYTES
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        || token.parse::<i64>().is_ok_and(|number| number < 0)
    {
        return Err(Error::protocol(
            "Upload completion token has an invalid shape",
        ));
    }
    Ok(())
}

pub fn completion_token(body: &[u8], final_chunk: bool) -> Result<Option<String>> {
    if body.len() > MAX_TOKEN_BYTES {
        return Err(Error::protocol(
            "Upload completion response exceeds its size limit",
        ));
    }
    if !body.is_empty() && !final_chunk {
        return Err(Error::protocol(
            "Upload completion token came from a nonfinal chunk",
        ));
    }
    if body.is_empty() {
        return if final_chunk {
            Err(Error::protocol("Upload completed without a final token"))
        } else {
            Ok(None)
        };
    }
    let token = std::str::from_utf8(body)
        .map_err(|_| Error::protocol("Upload completion token is not ASCII"))?;
    if let Ok(code) = token.parse::<i64>()
        && code < 0
    {
        return Err(Error::mega(code));
    }
    validate_token(token)?;
    Ok(Some(token.to_owned()))
}

pub fn registration_request(
    target: &str,
    name: &str,
    token: &str,
    aes_key: &[u8],
    raw_key: &[u8],
    master_key: &[u8],
) -> Result<Value> {
    validate_token(token)?;
    if target.is_empty() || raw_key.len() != 32 || aes_key.len() != 16 || master_key.len() != 16 {
        return Err(Error::invalid(
            "Upload registration needs a destination and complete file keys",
        ));
    }
    let attributes = wire::encrypt_attributes(&json!({"n":name}), aes_key)?;
    let wrapped = wire::aes_key_wrap_encrypt(raw_key, master_key)?;
    Ok(
        json!({"a":"p", "t":target, "n":[{"h":token,"t":0,"a":wire::b64_url_encode(&attributes),"k":wire::b64_url_encode(&wrapped)}]}),
    )
}
