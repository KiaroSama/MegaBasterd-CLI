//! Supported native settings normalize without importing or overwriting older stores.
#![allow(clippy::unwrap_used)]

use std::{fs, path::Path};

use megabasterd_cli::{
    error::Error,
    storage::{
        config::Config,
        config_store::ConfigStore,
        files::{STORE_VERSION, Store},
    },
};
use serde_json::{Value, json};

#[test]
fn normalization_removes_only_stale_settings_preserves_values_and_is_byte_stable_afterward() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/config-normalization");
    fs::create_dir_all(&base).unwrap();
    let scratch = private_tempfile::tempdir_in(base).unwrap();
    let path = scratch.path().join("private/config.json");
    let store = ConfigStore::new(&path);
    Store::new(&path)
        .lock()
        .unwrap()
        .save(&json!({
            "chunk_size_kb":2048,"smart_proxy_random":false,"totally_unknown_key":1,
            "max_workers":4,"default_account":"a@example.com",
            "connect_proxy_password":"synthetic-preserved-password",
            "elc_accounts":{"host.example":{"user":"u","api_key":"synthetic-preserved-key"}}
        }))
        .unwrap();
    assert_eq!(
        store.migrate().unwrap(),
        ["chunk_size_kb", "smart_proxy_random", "totally_unknown_key"]
    );
    let bytes = fs::read(&path).unwrap();
    let raw: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(raw["version"], STORE_VERSION);
    let data = &raw["data"];
    for key in ["chunk_size_kb", "smart_proxy_random", "totally_unknown_key"] {
        assert!(data.get(key).is_none());
    }
    assert_eq!(data["max_workers"], 4);
    assert_eq!(data["default_account"], "a@example.com");
    assert_eq!(
        data["connect_proxy_password"],
        "synthetic-preserved-password"
    );
    assert_eq!(
        data["elc_accounts"]["host.example"]["api_key"],
        "synthetic-preserved-key"
    );
    assert!(store.migrate().unwrap().is_empty());
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert!(store.load().unwrap().1.is_empty());
    assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 2);
}

#[test]
fn normalization_never_creates_missing_data_or_rewrites_corrupt_future_or_previous_formats() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/config-normalization");
    fs::create_dir_all(&base).unwrap();
    let scratch = private_tempfile::tempdir_in(base).unwrap();
    let missing = ConfigStore::new(scratch.path().join("missing/config.json"));
    assert!(missing.migrate().unwrap().is_empty());
    assert!(!missing.path().exists());
    let cases = [
        b"{malformed".to_vec(),
        serde_json::to_vec(&json!({"version":STORE_VERSION+1,"data":{"max_workers":7}})).unwrap(),
        serde_json::to_vec(&json!({"version":STORE_VERSION,"data":[]})).unwrap(),
        serde_json::to_vec(&json!({"max_workers":7})).unwrap(),
    ];
    for (index, bytes) in cases.into_iter().enumerate() {
        let path = scratch.path().join(format!("case-{index}/config.json"));
        Store::new(&path)
            .lock()
            .unwrap()
            .write_bytes(&bytes)
            .unwrap();
        let store = ConfigStore::new(&path);
        assert!(matches!(store.migrate(), Err(Error::Corrupt(_))));
        assert_eq!(fs::read(&path).unwrap(), bytes);
        let copies: Vec<_> = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|entry| {
                entry
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("config.json.corrupt-")
            })
            .collect();
        assert_eq!(copies.len(), usize::from(index != 1));
        for copy in copies {
            assert_eq!(fs::read(copy).unwrap(), bytes);
        }
        assert_eq!(
            fs::read_dir(path.parent().unwrap()).unwrap().count(),
            if index == 1 { 2 } else { 3 }
        );
    }
}

#[test]
fn obsolete_builtin_user_agent_normalizes_while_custom_values_and_other_settings_survive() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/config-normalization");
    fs::create_dir_all(&base).unwrap();
    let scratch = private_tempfile::tempdir_in(base).unwrap();
    for (index, (agent, expected)) in [
        ("MegaBasterd-CLI/1.0", ""),
        ("custom-client/7.2", "custom-client/7.2"),
        ("", ""),
    ]
    .into_iter()
    .enumerate()
    {
        let path = scratch.path().join(format!("agent-{index}/config.json"));
        Store::new(&path)
            .lock()
            .unwrap()
            .save(&json!({
                "chunk_size_kb":1024,"smart_proxy_autorefresh_minutes":30,
                "smart_proxy_timeout_seconds":10,"smart_proxy_random":true,
                "user_agent":agent,"max_workers":6
            }))
            .unwrap();
        let store = ConfigStore::new(&path);
        let original = fs::read(&path).unwrap();
        let (config, warnings) = store.load().unwrap();
        assert_eq!(config.max_workers, 6);
        assert_eq!(config.user_agent, expected);
        assert_eq!(warnings.len(), 4);
        assert_eq!(
            fs::read(&path).unwrap(),
            original,
            "Read-only load must not persist normalization"
        );
        assert_eq!(store.migrate().unwrap().len(), 4);
        let (config, warnings) = store.load().unwrap();
        assert_eq!(config.max_workers, 6);
        assert_eq!(config.user_agent, expected);
        assert!(warnings.is_empty());
    }
}

#[test]
fn malformed_in_memory_settings_report_exact_repairs_without_echoing_values() {
    let invalid = Config {
        streaming_port: 0,
        log_level: "NOPE".into(),
        ..Config::default()
    };
    let (repaired, warnings) = Config::from_value(invalid.value().unwrap()).unwrap();
    assert_eq!(warnings.len(), 2);
    assert_eq!(repaired.streaming_port, Config::default().streaming_port);
    assert_eq!(repaired.log_level, Config::default().log_level);
    assert!(!warnings.join(" ").contains("NOPE"));
}

#[path = "common/private_tempfile.rs"]
mod private_tempfile;
