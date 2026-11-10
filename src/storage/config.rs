use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Error, Result};

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub download_path: String,
    pub max_workers: u32,
    pub upload_workers: u32,
    pub max_parallel_downloads: u32,
    pub max_parallel_uploads: u32,
    pub speed_limit_kbps: f64,
    pub upload_speed_limit_kbps: f64,
    pub verify_integrity: bool,
    pub smart_proxy_enabled: bool,
    pub smart_proxy_url: Option<String>,
    pub timeout_seconds: u64,
    pub auto_resume: bool,
    pub keep_state_files_on_error: bool,
    pub default_account: Option<String>,
    pub streaming_port: u16,
    pub streaming_host: String,
    pub log_level: String,
    pub log_to_file: bool,
    pub log_max_bytes: u64,
    pub log_backups: u32,
    pub user_agent: String,
    pub megacrypter_server: Option<String>,
    pub elc_accounts: BTreeMap<String, BTreeMap<String, String>>,
    pub quota_wait_seconds: u64,
    pub quota_max_wait_loops: u32,
    pub run_command: Option<String>,
    pub all_finished_command: Option<String>,
    pub upload_log_path: Option<String>,
    pub force_smart_proxy: bool,
    pub connect_proxy_port: u16,
    pub connect_proxy_password: Option<String>,
    pub connect_proxy_allow_any_port: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            download_path: String::new(),
            max_workers: 8,
            upload_workers: 4,
            max_parallel_downloads: 6,
            max_parallel_uploads: 1,
            speed_limit_kbps: 0.0,
            upload_speed_limit_kbps: 0.0,
            verify_integrity: true,
            smart_proxy_enabled: false,
            smart_proxy_url: None,
            timeout_seconds: 60,
            auto_resume: true,
            keep_state_files_on_error: true,
            default_account: None,
            streaming_port: 8080,
            streaming_host: "127.0.0.1".to_owned(),
            log_level: "WARNING".to_owned(),
            log_to_file: true,
            log_max_bytes: 5_000_000,
            log_backups: 5,
            user_agent: String::new(),
            megacrypter_server: None,
            elc_accounts: BTreeMap::new(),
            quota_wait_seconds: 3600,
            quota_max_wait_loops: 24,
            run_command: None,
            all_finished_command: None,
            upload_log_path: None,
            force_smart_proxy: false,
            connect_proxy_port: 9999,
            connect_proxy_password: None,
            connect_proxy_allow_any_port: false,
        }
    }
}

pub const OPTIONAL_STRINGS: &[&str] = &[
    "default_account",
    "smart_proxy_url",
    "run_command",
    "all_finished_command",
    "upload_log_path",
    "connect_proxy_password",
    "megacrypter_server",
];
pub const DEPRECATED: &[&str] = &[
    "chunk_size_kb",
    "smart_proxy_autorefresh_minutes",
    "smart_proxy_timeout_seconds",
    "smart_proxy_random",
];

fn valid(key: &str, value: &Value, default: &Value) -> bool {
    if OPTIONAL_STRINGS.contains(&key) {
        return value.is_null() || value.is_string();
    }
    if key == "elc_accounts" {
        return value.as_object().is_some_and(|hosts| {
            hosts.values().all(|entry| {
                entry
                    .as_object()
                    .is_some_and(|fields| fields.values().all(Value::is_string))
            })
        });
    }
    if default.is_boolean() {
        return value.is_boolean();
    }
    if default.is_string() {
        return value.as_str().is_some_and(|v| {
            key != "log_level"
                || matches!(
                    v.to_ascii_uppercase().as_str(),
                    "DEBUG" | "INFO" | "WARNING" | "ERROR" | "CRITICAL"
                )
        });
    }
    if matches!(key, "speed_limit_kbps" | "upload_speed_limit_kbps") {
        return value.as_f64().is_some_and(|n| n.is_finite() && n >= 0.0);
    }
    let Some(n) = value.as_u64() else {
        return false;
    };
    match key {
        "max_workers" | "upload_workers" => (1..=64).contains(&n),
        "max_parallel_downloads" | "max_parallel_uploads" => (1..=32).contains(&n),
        "timeout_seconds" => n > 0,
        "streaming_port" | "connect_proxy_port" => (1..=65535).contains(&n),
        "log_backups" | "quota_max_wait_loops" => n <= u64::from(u32::MAX),
        _ => true,
    }
}

impl Config {
    pub fn value(&self) -> Result<Value> {
        Ok(serde_json::to_value(self)?)
    }

    pub fn from_value(input: Value) -> Result<(Self, Vec<String>)> {
        Self::from_value_with_ignored(input, |_| Ok(true))
    }

    pub(crate) fn from_value_with_ignored(
        input: Value,
        mut report_ignored: impl FnMut(&str) -> Result<bool>,
    ) -> Result<(Self, Vec<String>)> {
        let supplied = input
            .as_object()
            .ok_or_else(|| Error::Corrupt("Config root is not an object".into()))?;
        let mut settings = serde_json::to_value(Self::default())?;
        let defaults = settings
            .as_object_mut()
            .ok_or_else(|| Error::protocol("Config schema is invalid"))?;
        let mut warnings = Vec::new();
        for (key, value) in supplied {
            let Some(default) = defaults.get(key) else {
                if report_ignored(key)? {
                    // Only retired schema names are safe to echo, never arbitrary keys or values.
                    warnings.push(if DEPRECATED.contains(&key.as_str()) {
                        format!("Config setting {key} is retired; it was ignored")
                    } else {
                        "Config contains an unknown setting; it was ignored".to_owned()
                    });
                }
                continue;
            };
            if !valid(key, value, default) {
                warnings.push(format!(
                    "Config setting {key} is invalid; using its default"
                ));
                continue;
            }
            defaults.insert(key.clone(), value.clone());
        }
        let mut result: Self = serde_json::from_value(settings)
            .map_err(|_| Error::Corrupt("Config contains an unsupported value".into()))?;
        result.log_level.make_ascii_uppercase();
        if result.user_agent == "MegaBasterd-CLI/1.0" {
            result.user_agent.clear();
        }
        Ok((result, warnings))
    }

    pub fn set_text(&mut self, key: &str, text: &str) -> Result<()> {
        let mut settings = self.value()?;
        let values = settings
            .as_object_mut()
            .ok_or_else(|| Error::protocol("Config schema is invalid"))?;
        if DEPRECATED.contains(&key) {
            return Err(Error::invalid(
                "This setting was retired because it had no effect",
            ));
        }
        let current = values
            .get(key)
            .ok_or_else(|| Error::invalid("Unknown config setting"))?;
        let value = if OPTIONAL_STRINGS.contains(&key) {
            if matches!(text.trim().to_ascii_lowercase().as_str(), "null" | "none") {
                Value::Null
            } else {
                Value::String(text.to_owned())
            }
        } else if current.is_boolean() {
            Value::Bool(match text.trim().to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" | "y" | "on" => true,
                "0" | "false" | "no" | "n" | "off" => false,
                _ => return Err(Error::invalid("Expected true/false, yes/no, on/off or 1/0")),
            })
        } else if current.is_string() {
            Value::String(text.to_owned())
        } else {
            serde_json::from_str(text)
                .map_err(|_| Error::invalid("Expected a valid number or JSON object"))?
        };
        if !valid(key, &value, current) {
            return Err(Error::invalid(format!(
                "Invalid value for config setting {key}"
            )));
        }
        values.insert(key.to_owned(), value);
        let (updated, warnings) = Self::from_value(settings)?;
        if !warnings.is_empty() {
            return Err(Error::invalid(
                "Config update would discard an invalid setting",
            ));
        }
        *self = updated;
        Ok(())
    }

    pub fn unset(&mut self, key: &str) -> Result<()> {
        if !OPTIONAL_STRINGS.contains(&key) {
            return Err(Error::invalid("Only nullable settings can be unset"));
        }
        self.set_text(key, "null")
    }
}
