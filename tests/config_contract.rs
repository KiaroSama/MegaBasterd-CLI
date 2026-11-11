#![allow(clippy::unwrap_used)]

use megabasterd_cli::storage::{
    config::{Config, DEPRECATED, OPTIONAL_STRINGS},
    config_store::ConfigStore,
};
use serde_json::json;

#[test]
fn configuration_defaults_and_typed_updates_preserve_cli_contract() {
    let mut config = Config::default();
    assert_eq!(config.max_workers, 8);
    assert_eq!(config.upload_workers, 4);
    assert_eq!(config.max_parallel_downloads, 6);
    assert_eq!(config.max_parallel_uploads, 1);
    assert!(config.verify_integrity);
    assert!(config.log_to_file);
    config.set_text("max_workers", "12").unwrap();
    config.set_text("force_smart_proxy", "yes").unwrap();
    config.set_text("default_account", "null").unwrap();
    assert_eq!(config.max_workers, 12);
    assert!(config.force_smart_proxy);
    assert!(config.default_account.is_none());
    config.set_text("download_path", "anything").unwrap();
    let (loaded, warnings) = Config::from_value(config.value().unwrap()).unwrap();
    assert_eq!(loaded.download_path, "anything");
    assert!(warnings.is_empty());
    for (key, invalid) in [
        ("max_workers", "0"),
        ("max_workers", "65"),
        ("force_smart_proxy", "شاید"),
        ("speed_limit_kbps", "NaN"),
        ("elc_accounts", "[]"),
        ("unknown", "x"),
        ("chunk_size_kb", "12"),
    ] {
        assert!(config.set_text(key, invalid).is_err());
    }
    assert_eq!(config.max_workers, 12);
    assert!(config.force_smart_proxy);
}

#[test]
fn disk_verification_limit_defaults_to_one_and_rejects_invalid_updates() {
    let mut config = Config::default();
    assert_eq!(config.value().unwrap()["max_parallel_verifications"], 1);
    for accepted in ["1", "2", "32"] {
        config
            .set_text("max_parallel_verifications", accepted)
            .unwrap();
        let expected: u32 = accepted.parse().unwrap();
        assert_eq!(
            config.value().unwrap()["max_parallel_verifications"],
            expected
        );
    }
    let before = config.value().unwrap();
    for rejected in ["0", "33", "-1", "true", "1.5"] {
        assert!(
            config
                .set_text("max_parallel_verifications", rejected)
                .is_err()
        );
        assert_eq!(config.value().unwrap(), before);
    }
}

#[test]
fn malformed_values_warn_without_printing_secret_values() {
    let (config, warnings) = Config::from_value(json!({
        "max_workers": 0, "upload_workers": 2, "speed_limit_kbps": -1,
        "connect_proxy_password": ["invented-secret"],
        "elc_accounts": {"host": {"api_key": false}}, "log_level": "debug"
    }))
    .unwrap();
    assert_eq!(config.max_workers, 8);
    assert_eq!(config.upload_workers, 2);
    assert_eq!(config.speed_limit_kbps, 0.0);
    assert_eq!(config.log_level, "DEBUG");
    assert!(config.connect_proxy_password.is_none());
    assert_eq!(warnings.len(), 4);
    assert!(!format!("{warnings:?}").contains("invented-secret"));
    assert!(Config::from_value(json!([])).is_err());
}

#[test]
fn exact_source_config_updates_validate_bounds_and_preserve_the_previous_value_on_rejection() {
    let mut config = Config::default();
    let original = config.value().unwrap();
    for (key, bad) in [
        ("streaming_port", "0"),
        ("streaming_port", "70000"),
        ("connect_proxy_port", "-1"),
        ("timeout_seconds", "0"),
        ("max_workers", "0"),
        ("max_workers", "1000"),
        ("speed_limit_kbps", "-5"),
        ("quota_wait_seconds", "-1"),
        ("log_backups", "-2"),
        ("log_level", "CHATTY"),
    ] {
        assert!(config.set_text(key, bad).is_err(), "{key}");
        assert_eq!(config.value().unwrap(), original);
    }
    for (key, value) in [
        ("streaming_port", "9000"),
        ("max_workers", "16"),
        ("speed_limit_kbps", "512"),
        ("log_level", "info"),
    ] {
        config.set_text(key, value).unwrap();
    }
    assert_eq!(config.streaming_port, 9000);
    assert_eq!(config.max_workers, 16);
    assert_eq!(config.speed_limit_kbps, 512.0);
    assert_eq!(config.log_level, "INFO");
    for key in DEPRECATED {
        assert!(config.set_text(key, "1").is_err());
    }
    let (config, _) = Config::from_value(
        json!({"chunk_size_kb":2048,"smart_proxy_random":false,"max_workers":4}),
    )
    .unwrap();
    assert_eq!(config.max_workers, 4);
    let value = config.value().unwrap();
    assert!(value.get("chunk_size_kb").is_none() && value.get("smart_proxy_random").is_none());
    let mut config = Config::default();
    config.set_text("verify_integrity", "no").unwrap();
    assert!(!config.verify_integrity);
    assert!(config.set_text("verify_integrity", "yse").is_err());
    assert!(!config.verify_integrity);
}

#[test]
fn exact_source_hand_edited_values_and_nested_secrets_fall_back_without_echoing_values() {
    let (config, warnings) = Config::from_value(json!({"streaming_port":999999,"max_workers":-3,
        "timeout_seconds":"sixty","verify_integrity":"yes-ish","speed_limit_kbps":-1}))
    .unwrap();
    let defaults = Config::default();
    assert_eq!(config.streaming_port, defaults.streaming_port);
    assert_eq!(config.max_workers, defaults.max_workers);
    assert_eq!(config.timeout_seconds, defaults.timeout_seconds);
    assert_eq!(config.verify_integrity, defaults.verify_integrity);
    assert_eq!(config.speed_limit_kbps, defaults.speed_limit_kbps);
    assert_eq!(warnings.len(), 5);
    for key in OPTIONAL_STRINGS {
        for valid in [serde_json::Value::Null, json!("some-string")] {
            let input = json!({(*key):valid});
            let strict: Config = serde_json::from_value(input.clone()).unwrap();
            let (config, warnings) = Config::from_value(input).unwrap();
            assert_eq!(strict.value().unwrap()[*key], valid);
            assert_eq!(config.value().unwrap()[*key], valid);
            assert!(warnings.is_empty());
        }
        for invalid in [json!(["list"]), json!(42)] {
            let input = json!({(*key):invalid});
            assert!(serde_json::from_value::<Config>(input.clone()).is_err());
            let (config, warnings) = Config::from_value(input).unwrap();
            assert!(config.value().unwrap()[*key].is_null());
            assert_eq!(warnings.len(), 1);
        }
        let mut config = Config::default();
        for text in ["some-string", "[\"list\"]", "42"] {
            config.set_text(key, text).unwrap();
            assert_eq!(config.value().unwrap()[*key], text);
        }
        config.unset(key).unwrap();
        assert!(config.value().unwrap()[*key].is_null());
    }
    let (config, warnings) = Config::from_value(json!({"default_account":["not","a","string"],
        "run_command":42,"connect_proxy_password":{"oops":"SECRET-VALUE"},"upload_log_path":3.25}))
    .unwrap();
    assert!(config.default_account.is_none() && config.run_command.is_none());
    assert!(config.connect_proxy_password.is_none() && config.upload_log_path.is_none());
    assert!(!warnings.join(" ").contains("SECRET-VALUE"));
    let (config, warnings) =
        Config::from_value(json!({"elc_accounts":{"host.example":{"user":"u","api_key":123}}}))
            .unwrap();
    assert!(config.elc_accounts.is_empty());
    let joined = warnings.join(" ");
    assert!(!joined.contains("123") && !joined.contains("api_key"));
    let payload = json!({"elc_accounts":{"host.example":{"user":"u","api_key":"k"}}});
    let (config, warnings) = Config::from_value(payload.clone()).unwrap();
    assert_eq!(
        config.value().unwrap()["elc_accounts"],
        payload["elc_accounts"]
    );
    assert!(warnings.is_empty());
    let (config, warnings) =
        Config::from_value(json!({"max_workers":true,"speed_limit_kbps":false})).unwrap();
    assert_eq!(config.max_workers, defaults.max_workers);
    assert_eq!(config.speed_limit_kbps, defaults.speed_limit_kbps);
    assert_eq!(warnings.len(), 2);
}

#[test]
fn missing_native_config_retains_exact_logging_and_transfer_defaults() {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/config-defaults");
    std::fs::create_dir_all(&base).unwrap();
    let scratch = private_tempfile::tempdir_in(base).unwrap();
    let (config, warnings) = ConfigStore::new(scratch.path().join("private/missing.json"))
        .load()
        .unwrap();
    assert!(warnings.is_empty());
    assert_eq!(config.max_workers, 8);
    assert_eq!(config.max_parallel_downloads, 6);
    assert_eq!(config.log_level, "WARNING");
    assert!(config.log_to_file && config.log_max_bytes > 0 && config.log_backups >= 1);
}

#[test]
fn batch_command_is_a_nullable_persisted_string_and_invalid_values_fall_back_safely() {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/config-defaults");
    std::fs::create_dir_all(&base).unwrap();
    let scratch = private_tempfile::tempdir_in(base).unwrap();
    let store = ConfigStore::new(scratch.path().join("private/config.json"));
    assert!(store.load().unwrap().0.all_finished_command.is_none());
    store.set("all_finished_command", "notify --flag").unwrap();
    assert_eq!(
        store.load().unwrap().0.all_finished_command.as_deref(),
        Some("notify --flag")
    );
    store.unset("all_finished_command").unwrap();
    assert!(store.load().unwrap().0.all_finished_command.is_none());
    for invalid in [json!(17), json!(["sensitive-value"])] {
        megabasterd_cli::storage::files::Store::new(store.path())
            .lock()
            .unwrap()
            .save(&json!({"all_finished_command":invalid}))
            .unwrap();
        let before = std::fs::read(store.path()).unwrap();
        let (config, warnings) = store.load().unwrap();
        assert!(config.all_finished_command.is_none());
        assert_eq!(warnings.len(), 1);
        assert!(!warnings[0].contains("sensitive-value"));
        assert_eq!(std::fs::read(store.path()).unwrap(), before);
    }
}

#[path = "common/private_tempfile.rs"]
mod private_tempfile;
