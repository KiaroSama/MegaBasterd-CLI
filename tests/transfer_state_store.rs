//! Versioned transfer documents preserve rejected bytes and reuse one persistent lock name.
#![allow(clippy::unwrap_used)]

use std::{ffi::OsStr, path::Path};

use megabasterd_cli::{
    error::Error,
    platform::secure_files::{PrivateDirectory, file_identity},
    storage::{
        files::{STORE_VERSION, Store},
        transfer_state::{States, TransferState},
    },
};
use serde_json::{Value, json};

fn scratch() -> private_tempfile::TempDir {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/transfer-state-store");
    std::fs::create_dir_all(&base).unwrap();
    private_tempfile::tempdir_in(base).unwrap()
}

fn state(destination: &Path) -> TransferState {
    TransferState::new(
        "download",
        "public:fixture",
        destination,
        1024 * 1024,
        &[1; 32],
    )
    .unwrap()
}

#[test]
fn state_roundtrip_replacement_and_clear_preserve_only_the_persistent_sidecar() {
    let scratch = scratch();
    let path = scratch.path().join("private/transfer.json");
    let states = States::new(&path);
    assert!(states.load().unwrap().is_none());
    let mut original = state(&scratch.path().join("output.bin"));
    states.save(&original).unwrap();
    let empty = states.load().unwrap().unwrap();
    assert!(original.compatible(&empty));
    assert!(empty.completed.is_empty());
    let envelope: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(envelope["version"], STORE_VERSION);
    assert_eq!(envelope["data"]["completed"], json!({}));
    original.completed.insert(0, [0xaa; 16]);
    original.completed.insert(1, [0xbb; 16]);
    states.save(&original).unwrap();
    let loaded = states.load().unwrap().unwrap();
    assert!(original.compatible(&loaded));
    assert_eq!(loaded.completed, original.completed);
    let envelope: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(envelope["version"], STORE_VERSION);
    assert_eq!(
        envelope["data"]["completed"]["0"],
        json!([0xaa_u8; 16].as_slice())
    );

    let directory = PrivateDirectory::open(path.parent().unwrap()).unwrap();
    let sidecar = directory
        .open_private(OsStr::new("transfer.json.lock"), false)
        .unwrap();
    let sidecar_identity = file_identity(&sidecar).unwrap();
    let mut replacement = original.clone();
    replacement.completed.remove(&1);
    replacement.completed.insert(2, [0xcc; 16]);
    // A transfer owner writes one whole validated snapshot, not a union with old coverage.
    states.save(&replacement).unwrap();
    states.save(&replacement).unwrap();
    let loaded = states.load().unwrap().unwrap();
    assert_eq!(loaded.completed.keys().copied().collect::<Vec<_>>(), [0, 2]);
    assert_eq!(loaded.completed[&2], [0xcc; 16]);
    replacement.completed.insert(2, [0xdd; 16]);
    states.save(&replacement).unwrap();
    assert_eq!(states.load().unwrap().unwrap().completed.len(), 2);
    assert_eq!(states.load().unwrap().unwrap().completed[&2], [0xdd; 16]);
    assert_eq!(
        std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
        2
    );

    states.clear().unwrap();
    states.clear().unwrap();
    assert!(!path.exists());
    assert!(states.load().unwrap().is_none());
    let current = directory
        .open_private(OsStr::new("transfer.json.lock"), false)
        .unwrap();
    assert_eq!(file_identity(&current).unwrap(), sidecar_identity);
    let names: Vec<_> = std::fs::read_dir(path.parent().unwrap())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(names, [std::ffi::OsString::from("transfer.json.lock")]);
}

#[test]
fn malformed_or_future_state_is_preserved_by_load_save_and_clear() {
    let scratch = scratch();
    let path = scratch.path().join("private/transfer.json");
    let store = Store::new(&path);
    let states = States::new(&path);
    let valid = state(&scratch.path().join("output.bin"));
    states.save(&valid).unwrap();
    assert!(valid.compatible(&states.load().unwrap().unwrap()));
    let data = serde_json::to_value(&valid).unwrap();
    let mut unknown = data.clone();
    unknown["future_field"] = json!({"nested": 1});
    let mut keyless = valid.clone();
    keyless.key_hash.clear();
    let mut invalid_coverage = valid.clone();
    invalid_coverage.completed.insert(4, [0; 16]);
    let mut invalid_kind = valid.clone();
    invalid_kind.kind = "teleport".into();
    let mut invalid_destination = valid.clone();
    invalid_destination.destination.clear();
    let mut documents = vec![
        b"{{{ broken".to_vec(),
        b"\xff\xfe not utf-8".to_vec(),
        b"null".to_vec(),
        b"[1,2,3]".to_vec(),
        b"true".to_vec(),
        b"42".to_vec(),
        b"\"text\"".to_vec(),
        serde_json::to_vec(&json!({"version":STORE_VERSION,"data":null})).unwrap(),
        serde_json::to_vec(&json!({"version":STORE_VERSION,"data":{"missing":"fields"}})).unwrap(),
        serde_json::to_vec(&json!({"version":STORE_VERSION,"data":unknown})).unwrap(),
        serde_json::to_vec(
            &json!({"version":STORE_VERSION,"data":data,"future_field":{"nested":1}}),
        )
        .unwrap(),
        serde_json::to_vec(&json!({"version":STORE_VERSION+1,"data":data})).unwrap(),
        serde_json::to_vec(&json!({"version":STORE_VERSION+1,"new_schema":{"nested":true}}))
            .unwrap(),
        serde_json::to_vec(&json!({"version":999,"data":data})).unwrap(),
    ];
    for invalid in [keyless, invalid_coverage, invalid_kind, invalid_destination] {
        documents
            .push(serde_json::to_vec(&json!({"version":STORE_VERSION,"data":invalid})).unwrap());
    }
    for original in documents {
        store.lock().unwrap().write_bytes(&original).unwrap();
        for action in 0..3 {
            let result = match action {
                0 => states.load().map(|_| ()),
                1 => states.save(&valid),
                _ => states.clear(),
            };
            let error = result.unwrap_err();
            assert!(matches!(error, Error::Corrupt(_)));
            if let Some(version) = serde_json::from_slice::<Value>(&original)
                .ok()
                .and_then(|value| value.get("version").and_then(Value::as_u64))
                .filter(|version| *version > STORE_VERSION)
            {
                assert!(
                    error
                        .to_string()
                        .contains(&format!("format version {version}"))
                );
            }
            assert_eq!(std::fs::read(&path).unwrap(), original);
        }
        let mut names: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        names.sort();
        assert_eq!(
            names,
            [
                std::ffi::OsString::from("transfer.json"),
                std::ffi::OsString::from("transfer.json.lock")
            ]
        );
    }
}

#[test]
fn duplicate_decoded_keys_cannot_authorize_state_load_replace_clear_or_discard() {
    let scratch = scratch();
    let path = scratch.path().join("private/transfer.json");
    let states = States::new(&path);
    let store = Store::new(&path);
    let mut valid = state(&scratch.path().join("output.bin"));
    valid.kind = "upload".into();
    valid.completed.insert(0, [0xaa; 16]);
    states.save(&valid).unwrap();
    let canonical = std::fs::read(&path).unwrap();
    let data = serde_json::to_string(&valid).unwrap();
    let mac = serde_json::to_string(&[0xaa_u8; 16]).unwrap();
    let duplicate_kind = data.replacen("\"kind\":", "\"kind\":\"download\",\"kind\":", 1);
    let duplicate_mac = data.replace(
        &format!("\"completed\":{{\"0\":{mac}}}"),
        &format!("\"completed\":{{\"0\":[],\"\\u0030\":{mac}}}"),
    );
    assert_ne!(duplicate_kind, data);
    assert_ne!(duplicate_mac, data);
    for document in [
        format!(
            "{{\"version\":{},\"version\":{STORE_VERSION},\"data\":{data}}}",
            STORE_VERSION + 1
        ),
        format!("{{\"version\":{STORE_VERSION},\"version\":{STORE_VERSION},\"data\":{data}}}"),
        format!("{{\"version\":{STORE_VERSION},\"data\":null,\"d\\u0061ta\":{data}}}"),
        format!("{{\"version\":{STORE_VERSION},\"data\":{duplicate_kind}}}"),
        format!("{{\"version\":{STORE_VERSION},\"data\":{duplicate_mac}}}"),
    ] {
        // The old Value reader loses each earlier value and accepts the remaining valid state.
        let collapsed: Value = serde_json::from_str(&document).unwrap();
        assert_eq!(collapsed["version"], STORE_VERSION);
        let accepted: TransferState = serde_json::from_value(collapsed["data"].clone()).unwrap();
        accepted.validate().unwrap();
        assert!(accepted.compatible(&valid));
        assert_eq!(accepted.completed, valid.completed);
        store
            .lock()
            .unwrap()
            .write_bytes(document.as_bytes())
            .unwrap();
        for action in 0..4 {
            let error = match action {
                0 => states.load().map(|_| ()),
                1 => states.save(&valid),
                2 => states.clear(),
                _ => states.discard_unregistered_upload(&valid),
            }
            .unwrap_err();
            assert!(matches!(error, Error::Corrupt(_)));
            assert_eq!(error.code(), "storage_corrupt");
            assert_eq!(error.exit_code(), 1);
            assert_eq!(std::fs::read(&path).unwrap(), document.as_bytes());
            let mut names = std::fs::read_dir(path.parent().unwrap())
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<Vec<_>>();
            names.sort();
            assert_eq!(
                names,
                ["transfer.json", "transfer.json.lock"].map(std::ffi::OsString::from)
            );
        }
        store.lock().unwrap().write_bytes(&canonical).unwrap();
        assert!(valid.compatible(&states.load().unwrap().unwrap()));
        states.save(&valid).unwrap();
        states.discard_unregistered_upload(&valid).unwrap();
        assert!(!path.exists());
        states.save(&valid).unwrap();
        states.clear().unwrap();
        assert!(!path.exists());
    }
}

#[test]
fn malformed_saved_mac_cannot_replace_previously_valid_coverage() {
    let scratch = scratch();
    let path = scratch.path().join("private/transfer.json");
    let states = States::new(&path);
    let store = Store::new(&path);
    let mut original = state(&scratch.path().join("output.bin"));
    original.completed.insert(0, [0xaa; 16]);
    states.save(&original).unwrap();
    let committed = std::fs::read(&path).unwrap();
    for mac in [
        json!([]),
        json!(vec![0; 8]),
        json!(vec![0; 15]),
        json!(vec![0; 17]),
        json!(vec![0; 32]),
        json!("aa"),
        json!(42),
    ] {
        let mut malformed = serde_json::to_value(&original).unwrap();
        malformed["completed"]["1"] = mac;
        assert!(serde_json::from_value::<TransferState>(malformed.clone()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), committed);
        assert_eq!(
            states.load().unwrap().unwrap().completed,
            original.completed
        );
        let payload =
            serde_json::to_vec(&json!({"version":STORE_VERSION,"data":malformed})).unwrap();
        store.lock().unwrap().write_bytes(&payload).unwrap();
        assert!(matches!(states.load(), Err(Error::Corrupt(_))));
        assert!(matches!(states.clear(), Err(Error::Corrupt(_))));
        assert_eq!(std::fs::read(&path).unwrap(), payload);
        store.lock().unwrap().write_bytes(&committed).unwrap();
    }
    assert_eq!(
        std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
        2
    );
}

#[path = "common/private_tempfile.rs"]
mod private_tempfile;
