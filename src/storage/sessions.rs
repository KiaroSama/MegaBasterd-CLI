use serde::{Deserialize, Serialize};
use serde_json::json;
use zeroize::Zeroizing;

use super::{files::Store, vault::Vault};
use crate::error::{Error, Result};
use crate::protocol::{
    api::Api,
    auth::{Session, probe_user},
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Sealed {
    encrypted: String,
}

pub struct Sessions(Store);

pub enum LogoutOutcome {
    Missing,
    Unreadable,
    Ended,
    Rejected(Error),
}

fn open_session(sealed: &Sealed, email: &str, vault: &Vault) -> Result<Session> {
    let plaintext = vault.open(
        &sealed.encrypted,
        format!("session:{}", email.to_lowercase()).as_bytes(),
    )?;
    let session: Session = serde_json::from_slice(&plaintext)
        .map_err(|_| Error::Corrupt("Saved session has invalid content".into()))?;
    session.validate()?;
    if !session.email.eq_ignore_ascii_case(email) {
        return Err(Error::Corrupt(
            "Saved session belongs to another account".into(),
        ));
    }
    Ok(session)
}

impl Sessions {
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self(Store::new(path))
    }

    pub fn has_cached(&self) -> Result<bool> {
        Ok(self.0.lock()?.bytes()?.is_some())
    }

    /// Fence cache replacement until explicit logout and its local cleanup have one outcome.
    pub fn end_cached(
        &self,
        email: &str,
        vault: &Vault,
        end: impl FnOnce(&Session) -> Result<()>,
    ) -> Result<LogoutOutcome> {
        vault.require_passphrase()?;
        let locked = self.0.lock()?;
        let Some(sealed) = locked.load::<Sealed>()? else {
            return Ok(LogoutOutcome::Missing);
        };
        let session = match open_session(&sealed, email, vault) {
            Ok(session) => session,
            Err(Error::Auth(_)) => {
                locked.remove()?;
                return Ok(LogoutOutcome::Unreadable);
            }
            Err(error) => return Err(error),
        };
        let outcome = match end(&session) {
            Ok(()) => LogoutOutcome::Ended,
            Err(error @ Error::Mega { .. }) => LogoutOutcome::Rejected(error),
            Err(error) => return Err(error),
        };
        locked.remove()?;
        Ok(outcome)
    }

    pub fn restore(&self, email: &str, vault: &Vault, api: &mut Api) -> Result<Option<Session>> {
        let locked = self.0.lock()?;
        let Some(sealed) = locked.load::<Sealed>()? else {
            return Ok(None);
        };
        let session = match open_session(&sealed, email, vault) {
            Ok(session) => session,
            Err(Error::Auth(_)) => {
                api.clear_session();
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        api.set_session(&session.sid);
        match api.request(json!({"a": "ug"}), &[]).and_then(|user| {
            probe_user(
                &user,
                (!session.user_handle.is_empty()).then_some(session.user_handle.as_str()),
            )
        }) {
            Ok(handle) => {
                let mut session = session;
                session.user_handle = handle;
                Ok(Some(session))
            }
            Err(Error::Mega { code: -15, .. }) => {
                api.clear_session();
                locked.remove()?;
                Ok(None)
            }
            Err(error) => {
                // Transport uncertainty is not definitive rejection; keep the encrypted file.
                api.clear_session();
                Err(error)
            }
        }
    }

    pub fn remember(&self, session: &Session, vault: &Vault) -> Result<()> {
        vault.require_passphrase()?;
        session.validate()?;
        let locked = self.0.lock()?;
        if let Some(existing) = locked.load::<Sealed>()? {
            open_session(&existing, &session.email, vault)?;
        }
        let plaintext = Zeroizing::new(serde_json::to_vec(session)?);
        let sealed = Sealed {
            encrypted: vault.seal(
                &plaintext,
                format!("session:{}", session.email.to_lowercase()).as_bytes(),
            )?,
        };
        locked.save(&sealed)
    }

    pub fn forget(&self) -> Result<()> {
        self.0.lock()?.remove()
    }
}
