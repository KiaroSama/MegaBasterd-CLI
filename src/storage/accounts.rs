use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{
    files::{LockedStore, Store},
    vault::Vault,
};
use crate::error::{Error, Result};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Account {
    pub email: String,
    pub enc_password: String,
    pub label: Option<String>,
    pub quota_total: Option<u64>,
    pub quota_used: Option<u64>,
    pub last_used_iso: Option<String>,
    pub notes: Option<String>,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountData {
    pub accounts: Vec<Account>,
    pub default_email: Option<String>,
}

impl Account {
    fn matches(&self, choice: &str) -> bool {
        let choice = choice.to_lowercase();
        self.email.to_lowercase() == choice
            || self
                .label
                .as_deref()
                .is_some_and(|label| !label.is_empty() && label.to_lowercase() == choice)
    }
}

pub struct Accounts(Store);

impl Accounts {
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self(Store::new(path))
    }
    pub fn list(&self) -> Result<AccountData> {
        Self::load(&self.0.lock()?)
    }

    fn load(locked: &LockedStore) -> Result<AccountData> {
        let result = (|| {
            let Some(value) = locked.load::<serde_json::Value>()? else {
                return Ok(AccountData::default());
            };
            let entries = value
                .as_object()
                .and_then(|object| object.get("accounts"))
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| {
                    Error::Corrupt("Account data must contain an account list".into())
                })?;
            if !entries.iter().all(serde_json::Value::is_object) {
                return Err(Error::Corrupt("Account entries must be objects".into()));
            }
            let data: AccountData = serde_json::from_value(value)
                .map_err(|_| Error::Corrupt("Account data has an invalid structure".into()))?;
            Self::validate(&data)?;
            Ok(data)
        })();
        match result {
            Err(Error::Corrupt(reason)) => {
                let recovery = if locked.preserve().is_ok() {
                    "A private recovery copy was preserved"
                } else {
                    "A private recovery copy could not be written or verified"
                };
                Err(Error::Corrupt(format!(
                    "{reason}. {recovery}; original bytes remain untouched. Restore supported data before retrying"
                )))
            }
            result => result,
        }
    }

    fn validate(data: &AccountData) -> Result<()> {
        if data.accounts.len() > 10_000 {
            return Err(Error::Corrupt("Account list exceeds its size limit".into()));
        }
        let mut emails = std::collections::HashSet::new();
        let mut labels = std::collections::HashSet::new();
        for account in &data.accounts {
            if account.email.trim().is_empty()
                || !emails.insert(account.email.trim().to_lowercase())
            {
                return Err(Error::Corrupt(
                    "Account list has duplicate or invalid entries".into(),
                ));
            }
            if let Some(label) = account
                .label
                .as_deref()
                .filter(|label| !label.trim().is_empty())
                && !labels.insert(label.trim().to_lowercase())
            {
                return Err(Error::Corrupt("Account labels are ambiguous".into()));
            }
            if [account.quota_total, account.quota_used]
                .into_iter()
                .flatten()
                .any(|bytes| bytes > (1u64 << 60))
            {
                return Err(Error::Corrupt("Account quota is out of range".into()));
            }
            Vault::validate_envelope(&account.enc_password)?;
        }
        if data.default_email.as_deref().is_some_and(|email| {
            !email.trim().is_empty() && !emails.contains(&email.trim().to_lowercase())
        }) {
            return Err(Error::Corrupt("Default account does not exist".into()));
        }
        Ok(())
    }

    pub fn find(&self, choice: Option<&str>) -> Result<Account> {
        self.resolve(choice, None)
    }

    pub fn resolve(&self, choice: Option<&str>, fallback: Option<&str>) -> Result<Account> {
        let data = self.list()?;
        let selected = choice
            .filter(|value| !value.is_empty())
            .or(data
                .default_email
                .as_deref()
                .filter(|value| !value.is_empty()))
            .or(fallback.filter(|value| !value.is_empty()));
        match selected {
            Some(value) => data
                .accounts
                .into_iter()
                .find(|account| account.matches(value)),
            None if data.accounts.len() == 1 => data.accounts.into_iter().next(),
            None => None,
        }
        .ok_or_else(|| {
            Error::Auth("Choose a stored account with --account, or set an account default".into())
        })
    }

    pub fn password(account: &Account, vault: &Vault) -> Result<Zeroizing<String>> {
        let password = vault.open(
            &account.enc_password,
            format!("account:{}", account.email.to_lowercase()).as_bytes(),
        )?;
        let value = std::str::from_utf8(&password)
            .map_err(|_| Error::Corrupt("Stored password is not UTF-8".into()))?;
        Ok(Zeroizing::new(value.to_owned()))
    }

    /// Returns false for an existing account after proving that its vault opens; never overwrites it.
    pub fn add(
        &self,
        email: &str,
        password: &str,
        label: Option<String>,
        default: bool,
        vault: &Vault,
    ) -> Result<bool> {
        if email.trim() != email || !email.contains('@') || email.chars().any(char::is_control) {
            return Err(Error::invalid("Account email is invalid"));
        }
        let email = email.to_lowercase();
        let locked = self.0.lock()?;
        let mut data = Self::load(&locked)?;
        // Unlock every existing credential before mutation to prevent a split-passphrase vault.
        for account in &data.accounts {
            Self::password(account, vault)?;
        }
        if data
            .accounts
            .iter()
            .any(|account| account.email.eq_ignore_ascii_case(&email))
        {
            return Ok(false);
        }
        let sealed = vault.seal(password.as_bytes(), format!("account:{email}").as_bytes())?;
        let account = Account {
            email: email.clone(),
            enc_password: sealed,
            label,
            quota_total: None,
            quota_used: None,
            last_used_iso: None,
            notes: None,
        };
        data.accounts.push(account);
        if default || data.default_email.is_none() {
            data.default_email = Some(email)
        }
        Self::validate(&data)?;
        locked.save(&data)?;
        Ok(true)
    }

    pub fn remove(&self, choice: &str) -> Result<String> {
        let locked = self.0.lock()?;
        let mut data = Self::load(&locked)?;
        let index = data
            .accounts
            .iter()
            .position(|account| account.matches(choice))
            .ok_or_else(|| Error::invalid("Stored account was not found"))?;
        let email = data.accounts.remove(index).email;
        if data
            .default_email
            .as_deref()
            .is_some_and(|default| default.trim().to_lowercase() == email.trim().to_lowercase())
        {
            data.default_email = data.accounts.first().map(|a| a.email.clone());
        }
        Self::validate(&data)?;
        locked.save(&data)?;
        Ok(email)
    }

    pub fn set_default(&self, choice: &str) -> Result<()> {
        let locked = self.0.lock()?;
        let mut data = Self::load(&locked)?;
        let email = data
            .accounts
            .iter()
            .find(|account| account.matches(choice))
            .ok_or_else(|| Error::invalid("Stored account was not found"))?
            .email
            .clone();
        data.default_email = Some(email);
        locked.save(&data)
    }

    pub fn quota(&self, email: &str, total: u64, used: u64) -> Result<()> {
        let locked = self.0.lock()?;
        let mut data = Self::load(&locked)?;
        let account = data
            .accounts
            .iter_mut()
            .find(|a| a.email.eq_ignore_ascii_case(email))
            .ok_or_else(|| Error::invalid("Stored account was not found"))?;
        account.quota_total = Some(total);
        account.quota_used = Some(used);
        account.last_used_iso = Some(chrono::Utc::now().to_rfc3339());
        Self::validate(&data)?;
        locked.save(&data)
    }
}
