//! Stored resume values fail at the document boundary, without erasing their evidence.
#![allow(clippy::unwrap_used)]

use std::{fs, path::Path};

use megabasterd_cli::{
    crypto::{chunks::MAX_FILE_SIZE, wire::b64_url_encode},
    error::Error,
    storage::{
        files::Store,
        transfer_state::{States, TransferState},
    },
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn state(path: &Path) -> TransferState {
    let mut state = TransferState::new("upload", "fixture", path, 17, &[1; 16]).unwrap();
    state.upload_url = Some("https://gfs270n123.userstorage.mega.co.nz/ul/fake".into());
    state.completion_token = Some("TOKEN".into());
    state.source_identity = Some("synthetic-held-source-identity".into());
    let mut envelope = b"MBV2\x0f\x08\x01".to_vec();
    envelope.extend_from_slice(&[0; 44]);
    state.sealed_upload_key = Some(b64_url_encode(&envelope));
    state
}

#[test]
fn malformed_saved_transfer_fields_refuse_before_load_save_or_clear_can_change_the_document() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/state-metadata");
    fs::create_dir_all(&base).unwrap();
    let scratch = private_tempfile::tempdir_in(base).unwrap();
    let path = scratch.path().join("private/transfer.json");
    let valid = state(&path);
    let data = serde_json::to_value(&valid).unwrap();
    let mut variants = Vec::new();
    for value in [
        json!(42),
        json!(""),
        json!("not token!"),
        json!("-17"),
        json!("a".repeat(4097)),
    ] {
        variants.push(("completion_token", value));
    }
    for value in [
        json!(8080),
        json!(""),
        json!("http://gfs.userstorage.mega.co.nz/ul"),
        json!("https://127.0.0.1/ul"),
        json!("https://169.254.169.254/ul"),
        json!("https://[::1]/ul"),
        json!("https://[fd00::1]/ul"),
        json!("https://localhost/ul"),
        json!("https://storage.example.invalid/ul"),
        json!("https://a:b@gfs.userstorage.mega.co.nz/ul"),
        json!("https://attacker.example/ul"),
        json!("https://mega.co.nz.attacker.example/ul"),
    ] {
        variants.push(("upload_url", value));
    }
    for value in [
        json!(42),
        json!([]),
        json!(""),
        json!("not-base64!"),
        json!(b64_url_encode(&[0; 51])),
    ] {
        variants.push(("sealed_upload_key", value));
    }
    for value in [json!([]), json!({}), json!(42)] {
        variants.push(("source_identity", value));
    }
    for value in [
        json!(MAX_FILE_SIZE + 1),
        json!(-1),
        json!(true),
        json!("17"),
        Value::Null,
    ] {
        variants.push(("size", value));
    }
    variants.push(("key_hash", json!("zz".repeat(32))));
    variants.push(("source_hash", json!("zz".repeat(32))));
    for field in ["source_hash", "destination"] {
        for value in [Value::Null, json!(42), json!([]), json!("")] {
            variants.push((field, value));
        }
    }
    for value in [
        Value::Null,
        json!([]),
        json!("0"),
        json!({"-1":vec![0;16]}),
        json!({"zero":vec![0;16]}),
        json!({"1":vec![0;16]}),
    ] {
        variants.push(("completed", value));
    }
    let mut documents: Vec<_> = variants
        .into_iter()
        .map(|(field, value)| {
            let mut malformed = data.clone();
            malformed[field] = value;
            (field, malformed)
        })
        .collect();
    for field in ["size", "source_hash", "destination", "completed"] {
        let mut malformed = data.clone();
        assert!(malformed.as_object_mut().unwrap().remove(field).is_some());
        documents.push((field, malformed));
    }
    let store = Store::new(&path);
    let states = States::new(&path);
    for (field, malformed) in documents {
        if let Ok(state) = serde_json::from_value::<TransferState>(malformed.clone()) {
            assert!(
                matches!(state.validate(), Err(Error::Corrupt(_))),
                "{field}"
            );
        }
        let bytes = serde_json::to_vec(&json!({"version":2,"data":malformed})).unwrap();
        store.lock().unwrap().write_bytes(&bytes).unwrap();
        for action in 0..3 {
            let result = match action {
                0 => states.load().map(|_| ()),
                1 => states.save(&valid),
                _ => states.clear(),
            };
            let error = result.unwrap_err();
            assert!(matches!(error, Error::Corrupt(_)), "{field}: {error}");
            assert_eq!(error.code(), "storage_corrupt");
            assert_eq!(error.exit_code(), 1);
            assert_eq!(fs::read(&path).unwrap(), bytes);
            assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 2);
        }
    }
}

#[test]
fn supported_native_upload_fields_roundtrip_without_plaintext_crypto_material_or_extra_files() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/state-metadata");
    fs::create_dir_all(&base).unwrap();
    let scratch = private_tempfile::tempdir_in(base).unwrap();
    let path = scratch.path().join("private/transfer.json");
    let source = scratch.path().join("payload.bin");
    fs::write(&source, [0x78; 128]).unwrap();
    let destination = scratch.path().join("payload.bin.upload");
    fs::create_dir(&destination).unwrap();
    let sentinel = destination.join("preserve.bin");
    fs::write(&sentinel, b"upload destination must stay untouched").unwrap();
    let mut state = state(&destination);
    state.source_hash = hex::encode(Sha256::digest(source.to_string_lossy().as_bytes()));
    state.size = 128;
    state.completed.insert(0, [0xa5; 16]);
    state.validate().unwrap();
    let states = States::new(&path);
    states.save(&state).unwrap();
    let loaded = states.load().unwrap().unwrap();
    assert_eq!(
        serde_json::to_value(&loaded).unwrap(),
        serde_json::to_value(&state).unwrap()
    );
    assert_eq!(
        loaded.upload_url.as_deref(),
        Some("https://gfs270n123.userstorage.mega.co.nz/ul/fake")
    );
    assert_eq!(loaded.completion_token.as_deref(), Some("TOKEN"));
    for token in ["abc", "nothex", "raw_token-WithDash"] {
        state.completion_token = Some(token.into());
        states.save(&state).unwrap();
        let loaded = states.load().unwrap().unwrap();
        assert_eq!(loaded.completion_token.as_deref(), Some(token));
        assert_eq!(loaded.completed, state.completed);
    }
    let document: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert!(document["data"].get("aes_key").is_none());
    assert!(document["data"].get("nonce").is_none());
    assert_eq!(fs::read(&source).unwrap(), [0x78; 128]);
    assert!(destination.is_dir());
    assert_eq!(
        fs::read(&sentinel).unwrap(),
        b"upload destination must stay untouched"
    );
    assert_eq!(fs::read_dir(&destination).unwrap().count(), 1);
    assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 2);

    let implementation = include_str!("../src/storage/transfer_state.rs");
    let save = implementation
        .split_once("pub fn save(&self, state: &TransferState) -> Result<()> {")
        .unwrap()
        .1
        .split_once("pub fn discard_unregistered_upload(")
        .unwrap()
        .0;
    assert!(!save.contains("destination"));
    assert!(!save.contains("File::open") && !save.contains("OpenOptions"));
    assert!(save.contains("locked.save(state)"));
}

#[path = "common/private_tempfile.rs"]
mod private_tempfile;
