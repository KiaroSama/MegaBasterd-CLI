#![allow(clippy::unwrap_used)]

use std::path::Path;

use megabasterd_cli::{
    error::Error,
    storage::{
        config_store::ConfigStore,
        files::{STORE_VERSION, Store},
    },
};
use serde_json::{Value, json};

#[test]
fn every_native_config_entry_refuses_invalid_roots_and_explicit_recovery_preserves_original_bytes()
{
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/config-recovery");
    std::fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    let mut invalid = vec![
        b"{\"max_workers\": 8,,,\n".to_vec(),
        b"\xff\xfe not utf-8 at all".to_vec(),
        b"[1, 2, 3]".to_vec(),
        b"\"just a string\"".to_vec(),
        b"12345".to_vec(),
        b"null".to_vec(),
        b"{\"connect_proxy_password\": \"s3cr3t-not-a-real-password\", oops}".to_vec(),
        br#"{"version":2,"version":2,"data":{"max_workers":7}}"#.to_vec(),
        br#"{"version":2,"data":null,"data":{"max_workers":7}}"#.to_vec(),
        br#"{"version":2,"data":{"max_workers":3,"max_workers":7}}"#.to_vec(),
        br#"{"version":2,"data":{"elc_accounts":{"fixture":{"password":"s3cr3t-first","password":"s3cr3t-last"}}}}"#.to_vec(),
        br#"{"version":2,"data":{"ignored":[{"key":1,"key":2}]}}"#.to_vec(),
    ];
    for data in [
        json!([1, 2, 3]),
        json!("just a string"),
        json!(12345),
        Value::Null,
    ] {
        invalid.push(serde_json::to_vec(&json!({"version":STORE_VERSION,"data":data})).unwrap());
    }
    for (index, bytes) in invalid.iter().enumerate() {
        let path = scratch.path().join(format!("case-{index}/config.json"));
        let store = ConfigStore::new(path.clone());
        Store::new(&path)
            .lock()
            .unwrap()
            .write_bytes(bytes)
            .unwrap();
        for action in 0..6 {
            let fresh = ConfigStore::new(path.clone());
            let result = match action {
                0 => fresh.load().map(|_| ()),
                1 => fresh.set("max_workers", "4"),
                2 => fresh.unset("default_account"),
                3 => fresh.reset(),
                4 => fresh.migrate().map(|_| ()),
                _ => fresh.recover(false).map(|_| ()),
            };
            let error = result.unwrap_err();
            assert!(
                matches!(error, Error::Corrupt(_)),
                "case {index} action {action}"
            );
            assert!(!error.to_string().contains("s3cr3t"));
            assert_eq!(std::fs::read(&path).unwrap(), *bytes);
            let copies: Vec<_> = std::fs::read_dir(path.parent().unwrap())
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
            assert_eq!(copies.len(), 1);
            assert_eq!(std::fs::read(&copies[0]).unwrap(), *bytes);
        }
        assert_eq!(
            std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
            3,
            "Read/refusal must create only one exact backup and leave no stages"
        );
        let backup = store.recover(true).unwrap().unwrap();
        assert_eq!(
            std::fs::read(path.parent().unwrap().join(&backup)).unwrap(),
            *bytes
        );
        assert_eq!(store.load().unwrap().0.max_workers, 8);
        store.set("max_workers", "5").unwrap();
        assert_eq!(store.load().unwrap().0.max_workers, 5);
        assert!(store.recover(true).unwrap().is_none());
        assert_eq!(
            std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
            3
        );
        let raw: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(raw["version"], STORE_VERSION);
        assert_eq!(raw["data"]["max_workers"], 5);
    }
}

#[test]
fn concurrent_native_config_updates_reload_latest_and_recovery_creates_one_exact_backup() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/config-concurrency");
    std::fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    let path = scratch.path().join("private/config.json");
    let stale = ConfigStore::new(path.clone());
    stale.set("max_workers", "4").unwrap();
    std::thread::scope(|scope| {
        let first = scope.spawn(|| ConfigStore::new(path.clone()).set("max_workers", "12"));
        let second = scope.spawn(|| ConfigStore::new(path.clone()).set("upload_workers", "7"));
        first.join().unwrap().unwrap();
        second.join().unwrap().unwrap();
    });
    let current = stale.load().unwrap().0;
    assert_eq!(current.max_workers, 12);
    assert_eq!(current.upload_workers, 7);
    let another = ConfigStore::new(path.clone());
    stale.set("max_workers", "20").unwrap();
    another.set("timeout_seconds", "45").unwrap();
    let current = ConfigStore::new(path.clone()).load().unwrap().0;
    assert_eq!(current.max_workers, 20);
    assert_eq!(current.timeout_seconds, 45);
    let malformed = b"{\"max_workers\": 8,,,\n";
    Store::new(&path)
        .lock()
        .unwrap()
        .write_bytes(malformed)
        .unwrap();
    let backups = std::thread::scope(|scope| {
        let first = scope.spawn(|| ConfigStore::new(path.clone()).recover(true));
        let second = scope.spawn(|| ConfigStore::new(path.clone()).recover(true));
        [
            first.join().unwrap().unwrap(),
            second.join().unwrap().unwrap(),
        ]
    });
    let backups: Vec<_> = backups.into_iter().flatten().collect();
    assert_eq!(backups.len(), 1);
    assert_eq!(
        std::fs::read(path.parent().unwrap().join(&backups[0])).unwrap(),
        malformed
    );
    assert_eq!(stale.load().unwrap().0.max_workers, 8);
    assert_eq!(
        std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
        3
    );
    for entry in std::fs::read_dir(path.parent().unwrap()).unwrap() {
        assert!(
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")
        );
    }
}

#[test]
fn preloaded_configuration_cannot_overwrite_corruption_written_after_the_load() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/config-recovery");
    std::fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    let path = scratch.path().join("private/config.json");
    let store = ConfigStore::new(&path);
    store.set("max_workers", "7").unwrap();
    assert_eq!(store.load().unwrap().0.max_workers, 7);
    let malformed = b"{\"max_workers\": 8,,,\n";
    Store::new(&path)
        .lock()
        .unwrap()
        .write_bytes(malformed)
        .unwrap();
    for action in 0..4 {
        let result = match action {
            0 => store.set("max_workers", "4"),
            1 => store.unset("default_account"),
            2 => store.migrate().map(|_| ()),
            _ => store.reset(),
        };
        assert!(matches!(result, Err(Error::Corrupt(_))));
        assert_eq!(std::fs::read(&path).unwrap(), malformed);
    }
    let copies: Vec<_> = std::fs::read_dir(path.parent().unwrap())
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
    assert_eq!(copies.len(), 1);
    assert_eq!(std::fs::read(&copies[0]).unwrap(), malformed);
    assert_eq!(
        std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
        3
    );
}

#[test]
fn a_newer_configuration_is_never_reset_or_recovered_with_current_defaults() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/config-future");
    std::fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    let path = scratch.path().join("private/config.json");
    let store = ConfigStore::new(path.clone());
    for bytes in [
        serde_json::to_vec(&json!({"version":STORE_VERSION+1,"data":{"max_workers":7}})).unwrap(),
        br#"{"version":3,"version":2,"data":{"max_workers":7}}"#.to_vec(),
        br#"{"version":2,"version":3,"data":{"max_workers":7}}"#.to_vec(),
        br#"{"version":3,"version":2,"data":{"max_workers":7}}"#.to_vec(),
        br#"{"version":2,"version":3,"data":{"max_workers":7}}"#.to_vec(),
    ] {
        Store::new(&path)
            .lock()
            .unwrap()
            .write_bytes(&bytes)
            .unwrap();
        assert!(matches!(store.reset(), Err(Error::Corrupt(_))));
        assert!(matches!(store.recover(true), Err(Error::Corrupt(_))));
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert_eq!(
            std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
            2
        );
    }
}
