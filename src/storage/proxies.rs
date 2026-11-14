use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rand::{TryRng, rngs::SysRng};
use serde::{Deserialize, Serialize};
use url::Url;

use super::files::{LockedStore, Store};
use crate::error::{Error, Result, poisoned};

#[cfg(test)]
#[path = "proxy_transaction_tests.rs"]
mod transaction_tests;

pub fn validate_proxy(value: &str) -> Result<Url> {
    if value.chars().any(char::is_control) {
        return Err(Error::invalid("Proxy URL contains control characters"));
    }
    let normalized = if value.contains("://") {
        value.to_owned()
    } else {
        format!("http://{value}")
    };
    let url = Url::parse(&normalized).map_err(|_| Error::invalid("Invalid proxy URL"))?;
    if !matches!(
        url.scheme(),
        "http" | "https" | "socks4" | "socks5" | "socks5h"
    ) || url.host_str().is_none()
        || url.port_or_known_default().is_none_or(|port| port == 0)
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::invalid(
            "Proxy needs a supported scheme, host and port without path/query/fragment",
        ));
    }
    Ok(url)
}

pub fn canonical_proxy(value: &str) -> Result<String> {
    Ok(validate_proxy(value)?.to_string())
}

/// Import MegaBasterd's host:port@base64-user:base64-password list entries.
/// Split credentials before interpreting '/' so base64 authentication is never truncated.
pub fn import_proxy(value: &str) -> Result<String> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    if value.chars().any(char::is_control) {
        return Err(Error::invalid("Proxy entry contains control characters"));
    }
    let value = value.trim();
    let address = value.split_once("://").map_or(value, |(_, rest)| rest);
    let Some((host, credentials)) = address.split_once('@') else {
        validate_proxy(value)?;
        return Ok(value.to_owned());
    };
    // URL-style authentication already has an unambiguous parser; legacy entries start
    // with an actual host:port, not a username and a potentially numeric password.
    if validate_proxy(credentials).is_ok() {
        validate_proxy(value)?;
        return Ok(value.to_owned());
    }
    let (user, password) = credentials
        .split_once(':')
        .ok_or_else(|| Error::invalid("Invalid legacy proxy credentials"))?;
    let decode = |value: &str| -> Result<String> {
        String::from_utf8(
            STANDARD
                .decode(value)
                .map_err(|_| Error::invalid("Invalid base64 proxy credentials"))?,
        )
        .map_err(|_| Error::invalid("Proxy credentials are not UTF-8"))
    };
    let user = decode(user)?;
    let password = decode(password)?;
    if user.chars().chain(password.chars()).any(char::is_control) {
        return Err(Error::invalid(
            "Proxy credentials contain control characters",
        ));
    }
    let scheme = value.split_once("://").map_or("http", |(scheme, _)| scheme);
    let host = host.split('/').next().unwrap_or_default();
    let mut url = validate_proxy(&format!("{scheme}://{host}"))?;
    url.set_username(&user)
        .map_err(|_| Error::invalid("Invalid proxy username"))?;
    url.set_password(Some(&password))
        .map_err(|_| Error::invalid("Invalid proxy password"))?;
    Ok(url.to_string())
}

fn validate_urls(urls: &[String]) -> Result<()> {
    if urls.len() > 10_000 || urls.iter().any(|value| validate_proxy(value).is_err()) {
        return Err(Error::Corrupt(
            "Proxy list has invalid or oversized entries; original data was preserved".into(),
        ));
    }
    Ok(())
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyData {
    pub urls: Vec<String>,
}

pub struct ProxyStore(Store);

impl ProxyStore {
    pub fn new(path: PathBuf) -> Self {
        Self(Store::new(path))
    }
    pub fn list(&self) -> Result<Vec<String>> {
        Ok(Self::load(&self.0.lock()?)?.urls)
    }

    fn load(locked: &LockedStore) -> Result<ProxyData> {
        let result = (|| {
            let Some(value) = locked.load::<serde_json::Value>()? else {
                return Ok(ProxyData::default());
            };
            if !value.is_object() {
                return Err(Error::Corrupt("Proxy data must be an object".into()));
            }
            let data: ProxyData = serde_json::from_value(value)
                .map_err(|_| Error::Corrupt("Proxy data has an invalid structure".into()))?;
            validate_urls(&data.urls)?;
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

    pub fn update(&self, change: impl FnOnce(&mut Vec<String>)) -> Result<()> {
        self.try_update(|urls| {
            change(urls);
            Ok(())
        })
    }

    pub(crate) fn try_update(
        &self,
        change: impl FnOnce(&mut Vec<String>) -> Result<()>,
    ) -> Result<()> {
        self.update_with_save(change, |locked, data| locked.save(data))
    }

    fn update_with_save(
        &self,
        change: impl FnOnce(&mut Vec<String>) -> Result<()>,
        save: impl FnOnce(&LockedStore, &ProxyData) -> Result<()>,
    ) -> Result<()> {
        let locked = self.0.lock()?;
        let mut data = Self::load(&locked)?;
        change(&mut data.urls)?;
        if data.urls.len() > 10_000 {
            return Err(Error::invalid("Proxy pool exceeds 10,000 entries"));
        }
        let mut seen = HashSet::new();
        for value in &data.urls {
            validate_proxy(value)?;
        }
        data.urls.retain(|value| seen.insert(value.clone()));
        save(&locked, &data)
    }
}

#[derive(Clone)]
struct Entry {
    url: String,
    successes: u64,
    failures: u64,
    cooldown: Instant,
}

struct PoolState {
    entries: Vec<Entry>,
    next_reload: Instant,
}

pub struct Pool {
    state: Mutex<PoolState>,
    configured: Vec<String>,
    file: Option<PathBuf>,
}

impl Pool {
    pub fn new(
        mut urls: Vec<String>,
        configured: Vec<String>,
        file: Option<PathBuf>,
    ) -> Result<Arc<Self>> {
        urls.extend(configured.iter().cloned());
        for url in &urls {
            validate_proxy(url)?;
        }
        if urls.len() > 10_000 {
            return Err(Error::invalid("Proxy pool exceeds its entry limit"));
        }
        let mut seen = HashSet::new();
        urls.retain(|url| seen.insert(url.clone()));
        let now = Instant::now();
        Ok(Arc::new(Self {
            state: Mutex::new(PoolState {
                entries: urls
                    .into_iter()
                    .map(|url| Entry {
                        url,
                        successes: 0,
                        failures: 0,
                        cooldown: now,
                    })
                    .collect(),
                next_reload: now,
            }),
            configured,
            file,
        }))
    }

    pub(crate) fn has_available(&self) -> Result<bool> {
        let state = self.state.lock().map_err(poisoned)?;
        let now = Instant::now();
        Ok(state.entries.iter().any(|entry| entry.cooldown <= now))
    }

    pub fn pick(&self) -> Result<Option<String>> {
        self.reload_if_due()?;
        let mut state = self.state.lock().map_err(poisoned)?;
        let now = Instant::now();
        let total: f64 = state
            .entries
            .iter()
            .filter(|e| e.cooldown <= now)
            .map(|e| (e.successes as f64 + 1.0) / (e.successes as f64 + e.failures as f64 + 2.0))
            .sum();
        if total == 0.0 {
            return Ok(None);
        }
        let mut bytes = [0u8; 8];
        SysRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| Error::protocol("Operating-system randomness is unavailable"))?;
        let mut threshold = (u64::from_le_bytes(bytes) as f64 / u64::MAX as f64) * total;
        let mut last = None;
        for entry in state.entries.iter_mut().filter(|e| e.cooldown <= now) {
            last = Some(entry.url.clone());
            threshold -= (entry.successes as f64 + 1.0)
                / (entry.successes as f64 + entry.failures as f64 + 2.0);
            if threshold <= 0.0 {
                return Ok(last);
            }
        }
        Ok(last)
    }

    #[cfg(test)]
    pub(crate) fn test_health_counts(&self, picked: &str) -> Result<Option<(u64, u64)>> {
        let state = self.state.lock().map_err(poisoned)?;
        Ok(state
            .entries
            .iter()
            .find(|entry| entry.url == picked)
            .map(|entry| (entry.successes, entry.failures)))
    }

    pub fn report(&self, picked: &str, success: bool) -> Result<()> {
        let mut state = self.state.lock().map_err(poisoned)?;
        if let Some(entry) = state.entries.iter_mut().find(|e| e.url == picked) {
            if success {
                entry.successes = entry.successes.saturating_add(1);
                entry.failures = entry.failures.saturating_sub(1);
            } else {
                entry.failures = entry.failures.saturating_add(1);
                if entry.failures >= 3 {
                    entry.cooldown = Instant::now() + Duration::from_secs(60);
                }
            }
        }
        Ok(())
    }

    fn reload_if_due(&self) -> Result<()> {
        {
            let mut state = self.state.lock().map_err(poisoned)?;
            if state.next_reload > Instant::now() {
                return Ok(());
            }
            state.next_reload = Instant::now() + Duration::from_secs(5);
        }
        self.reload()
    }

    pub fn reload(&self) -> Result<()> {
        let Some(file) = &self.file else {
            return Ok(());
        };
        // Bad/empty replacement must not destroy the last usable snapshot or reset cooldowns.
        let mut urls = match ProxyStore::new(file.clone()).list() {
            Ok(urls)
                if !urls.is_empty()
                    && urls.len() <= 10_000
                    && urls.iter().all(|u| validate_proxy(u).is_ok()) =>
            {
                urls
            }
            _ => return Ok(()),
        };
        urls.extend(self.configured.iter().cloned());
        let mut seen = HashSet::new();
        urls.retain(|url| seen.insert(url.clone()));
        if urls.len() > 10_000 {
            return Ok(());
        }
        let mut state = self.state.lock().map_err(poisoned)?;
        let now = Instant::now();
        state.entries = urls
            .into_iter()
            .map(|url| {
                state
                    .entries
                    .iter()
                    .find(|e| e.url == url)
                    .cloned()
                    .unwrap_or(Entry {
                        url,
                        successes: 0,
                        failures: 0,
                        cooldown: now,
                    })
            })
            .collect();
        Ok(())
    }
}

#[derive(Clone)]
pub struct Routing {
    pub explicit: Option<String>,
    pub pool: Option<Arc<Pool>>,
    pub force: bool,
}

impl Routing {
    pub fn select(&self) -> Result<(Option<String>, Option<String>)> {
        if let Some(proxy) = &self.explicit {
            validate_proxy(proxy)?;
            return Ok((Some(canonical_proxy(proxy)?), None));
        }
        if let Some(pool) = &self.pool
            && let Some(picked) = pool.pick()?
        {
            return Ok((Some(canonical_proxy(&picked)?), Some(picked)));
        }
        if self.force {
            return Err(Error::protocol(
                "Force-proxy mode has no usable proxy; direct connection was refused",
            ));
        }
        Ok((None, None))
    }

    pub fn report(&self, picked: Option<&str>, success: bool) -> Result<()> {
        if let (Some(pool), Some(url)) = (&self.pool, picked) {
            pool.report(url, success)?
        }
        Ok(())
    }
}
