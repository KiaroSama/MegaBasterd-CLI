//! A held configuration lock blocks mutation while damaged reads retain safe diagnosis.
#![allow(clippy::unwrap_used)]

use std::{fs, path::Path, time::Duration};

use super::{ConfigStore, Store};
use crate::error::Error;

#[test]
fn held_configuration_lock_refuses_every_entry_point_without_partial_writes_and_allows_retry() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/config-transactions");
    fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    for (case, contents) in [
        None,
        Some(br#"{"version":2,"data":{"max_workers":7}}"#.as_slice()),
        Some(b"{\"connect_proxy_password\":\"synthetic-lock-secret\",,,".as_slice()),
        Some(b"{\"max_workers\": 8,,,\n".as_slice()),
    ]
    .into_iter()
    .enumerate()
    {
        let path = scratch.path().join(format!("case-{case}/config.json"));
        let owner = Store::new(&path).lock().unwrap();
        if let Some(contents) = contents {
            owner.write_bytes(contents).unwrap();
        }
        let store = ConfigStore {
            store: Store::new(&path).with_timeout(Duration::ZERO),
        };
        for action in 0..8 {
            let result = match action {
                0 => store.load().map(|_| ()),
                1 => store.load_for_command().map(|_| ()),
                2 => store.set("max_workers", "9"),
                3 => store.unset("default_account"),
                4 => store.migrate().map(|_| ()),
                5 => store.reset(),
                6 => store.recover(false).map(|_| ()),
                _ => store.recover(true).map(|_| ()),
            };
            let error = result.unwrap_err();
            let message = error.to_string();
            if case >= 2 && action < 2 {
                assert!(matches!(error, Error::Corrupt(_)));
                assert_eq!(error.code(), "storage_corrupt");
                assert!(message.contains("could not be written or verified"));
                assert!(!message.contains("copy was preserved"));
            } else {
                assert!(
                    matches!(error, Error::Busy(_)),
                    "case {case} action {action}"
                );
                assert_eq!(error.code(), "resource_busy");
                assert!(message.contains("retry when the other operation finishes"));
            }
            assert_eq!(error.exit_code(), 1);
            assert!(!message.contains("synthetic-lock-secret"));
            match contents {
                Some(contents) => assert_eq!(fs::read(&path).unwrap(), contents),
                None => assert!(!path.exists()),
            }
            let mut names: Vec<_> = fs::read_dir(path.parent().unwrap())
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect();
            names.sort();
            let expected = if contents.is_some() {
                vec!["config.json", "config.json.lock"]
            } else {
                vec!["config.json.lock"]
            };
            assert_eq!(
                names,
                expected
                    .into_iter()
                    .map(std::ffi::OsString::from)
                    .collect::<Vec<_>>()
            );
        }
        drop(owner);
        if case >= 2 {
            assert!(matches!(
                store.set("max_workers", "9"),
                Err(Error::Corrupt(_))
            ));
            assert_eq!(fs::read(&path).unwrap(), contents.unwrap());
            let backup = store.recover(true).unwrap().unwrap();
            assert_eq!(
                fs::read(path.parent().unwrap().join(backup)).unwrap(),
                contents.unwrap()
            );
        }
        store.set("max_workers", "9").unwrap();
        let (config, warnings) = ConfigStore::new(&path).load().unwrap();
        assert_eq!(config.max_workers, 9);
        assert!(warnings.is_empty());
        let document: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(document["version"], crate::storage::files::STORE_VERSION);
        assert_eq!(document["data"]["max_workers"], 9);
        assert_eq!(
            fs::read_dir(path.parent().unwrap()).unwrap().count(),
            if case >= 2 { 3 } else { 2 }
        );
    }
}
