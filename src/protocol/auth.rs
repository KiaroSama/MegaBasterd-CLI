use serde::{Deserialize, Serialize};
use serde_json::json;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::api::{Api, string};
use crate::crypto::{keys, wire};
use crate::error::{Error, Result};

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Session {
    pub sid: String,
    pub master_key: [u8; 16],
    pub rsa_private_key: Option<Vec<u8>>,
    pub user_handle: String,
    pub email: String,
}

impl Session {
    pub fn validate(&self) -> Result<()> {
        if self.sid.is_empty()
            || self.sid.len() > 2048
            || self
                .rsa_private_key
                .as_ref()
                .is_some_and(|key| key.len() > 8192)
        {
            return Err(Error::Corrupt(
                "Saved session has invalid key or session data".into(),
            ));
        }
        Ok(())
    }
}

pub fn login(
    api: &mut Api,
    email: &str,
    password: &str,
    mfa_code: Option<&str>,
    mut prompt: impl FnMut() -> Result<String>,
) -> Result<Session> {
    let email = email.to_lowercase();
    let prelogin = api.request(json!({"a": "us0", "user": email}), &[])?;
    let version = match prelogin.get("v") {
        None => 1,
        Some(value) => value
            .as_u64()
            .ok_or_else(|| Error::protocol("Account login version is not an unsigned integer"))?,
    };
    let salt = match prelogin.get("s") {
        None => None,
        Some(serde_json::Value::String(salt)) => Some(salt.as_str()),
        Some(_) => return Err(Error::protocol("Account salt is not text")),
    };
    let (login_key, password_hash) = match version {
        2 => {
            let salt = salt
                .filter(|salt| !salt.is_empty())
                .ok_or_else(|| Error::protocol("Version 2 account login requires a salt"))?;
            let salt = wire::b64_url_decode(salt)?;
            if salt.len() > 1024 {
                return Err(Error::protocol("Account salt exceeds its response limit"));
            }
            let derived = keys::derive_account_key_v2(password, &salt)?;
            (
                Zeroizing::new(derived[..16].to_vec()),
                Zeroizing::new(wire::b64_url_encode(&derived[16..])),
            )
        }
        1 => {
            let derived = Zeroizing::new(keys::derive_key_legacy(password)?);
            (
                Zeroizing::new(wire::a32_to_bytes(&*derived)),
                Zeroizing::new(keys::stringhash(&email, &*derived)?),
            )
        }
        _ => return Err(Error::protocol("Unsupported MEGA account login version")),
    };
    let result = match api.request(
        json!({"a": "us", "user": email, "uh": &*password_hash}),
        &[],
    ) {
        Err(Error::Mega { code: -26, .. }) => {
            let code = Zeroizing::new(match mfa_code {
                Some(code) => code.to_owned(),
                None => prompt()?,
            });
            if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Error::invalid(
                    "2FA needs the current six-digit authenticator code",
                ));
            }
            api.request(
                json!({"a": "us", "user": email, "uh": &*password_hash, "mfa": &*code}),
                &[],
            )
            .map_err(|error| match error {
                Error::Mega {
                    code: -5 | -9 | -26,
                    ..
                } => Error::Auth(
                    "MEGA rejected that 2FA code. Codes expire every 30 seconds - take the current one from your authenticator app and retry.".into(),
                ),
                error => error,
            })?
        }
        result => result?,
    };
    let mut session = decode_login_response(&result, &email, &login_key)?;
    api.set_session(&session.sid);
    // Cryptographic decode alone does not prove that MEGA accepts this SID/account identity.
    let probe = api.request(json!({"a": "ug"}), &[]).and_then(|user| {
        probe_user(
            &user,
            (!session.user_handle.is_empty()).then_some(session.user_handle.as_str()),
        )
    });
    match probe {
        Ok(handle) => session.user_handle = handle,
        Err(error) => {
            api.clear_session();
            return Err(error);
        }
    }
    Ok(session)
}

pub fn probe_user(user: &serde_json::Value, expected: Option<&str>) -> Result<String> {
    let handle = string(user, "u")?;
    if handle.is_empty() || expected.is_some_and(|expected| expected != handle) {
        return Err(Error::Auth(
            "MEGA session probe returned a different or missing account identity".into(),
        ));
    }
    Ok(handle.to_owned())
}

pub fn decode_login_response(
    result: &serde_json::Value,
    email: &str,
    login_key: &[u8],
) -> Result<Session> {
    let user_handle = match result.get("u") {
        None => "",
        Some(serde_json::Value::String(handle)) => handle.as_str(),
        Some(_) => return Err(Error::protocol("Login user handle is not text")),
    };
    let encrypted_master = wire::b64_url_decode(string(result, "k")?)?;
    if encrypted_master.len() != 16 {
        return Err(Error::protocol("Login master key has an invalid width"));
    }
    let master = Zeroizing::new(wire::aes_key_wrap_decrypt(&encrypted_master, login_key)?);
    let master_key: [u8; 16] = master
        .as_slice()
        .try_into()
        .map_err(|_| Error::protocol("Invalid master key"))?;
    let (sid, rsa_private_key) = match result.get("tsid") {
        Some(value) => {
            let sid = value
                .as_str()
                .ok_or_else(|| Error::protocol("Temporary session ID is not text"))?;
            let challenge = Zeroizing::new(wire::b64_url_decode(sid)?);
            if challenge.len() != 43 {
                return Err(Error::Auth(
                    "Temporary session challenge has invalid width".into(),
                ));
            }
            let encrypted = wire::aes_key_wrap_encrypt(&challenge[..16], &master_key)?;
            use subtle::ConstantTimeEq;
            if !bool::from(encrypted.as_slice().ct_eq(&challenge[27..])) {
                return Err(Error::Auth(
                    "Temporary session password challenge was rejected".into(),
                ));
            }
            (sid.to_owned(), None)
        }
        None => {
            let private = wire::b64_url_decode(string(result, "privk")?)?;
            let decrypted = Zeroizing::new(wire::aes_key_wrap_decrypt(&private, &master_key)?);
            let csid = wire::b64_url_decode(string(result, "csid")?)?;
            let sid = keys::decode_session_id(&csid, &decrypted)?;
            (sid, Some(decrypted.to_vec()))
        }
    };
    let session = Session {
        sid,
        master_key,
        rsa_private_key,
        user_handle: user_handle.to_owned(),
        email: email.to_lowercase(),
    };
    session.validate()?;
    Ok(session)
}

#[cfg(test)]
#[path = "auth_peer_tests.rs"]
mod peer_tests;
