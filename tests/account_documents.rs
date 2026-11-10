#![allow(clippy::unwrap_used)]

use std::{fs, path::Path};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use megabasterd_cli::{
    error::Error,
    storage::{accounts::Accounts, files::Store, vault::Vault},
};
use serde_json::{Value, json};

fn fixture() -> tempfile::TempDir {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/account-documents");
    fs::create_dir_all(&base).unwrap();
    tempfile::tempdir_in(base).unwrap()
}

fn entry() -> Value {
    // Structurally valid native envelope only; this synthetic tag need not decrypt.
    let mut raw = b"MBV2\x0f\x08\x01".to_vec();
    raw.extend_from_slice(&[0; 44]);
    json!({"email":"user@example.com", "enc_password":URL_SAFE_NO_PAD.encode(raw)})
}

fn document(account: Value) -> Value {
    json!({"accounts":[account], "default_email":"user@example.com"})
}

fn assert_refused_unchanged(path: &Path, bytes: &[u8]) {
    Store::new(path).lock().unwrap().write_bytes(bytes).unwrap();
    let accounts = Accounts::new(path);
    assert!(matches!(accounts.list(), Err(Error::Corrupt(_))));
    for mutation in 0..4 {
        let result = match mutation {
            0 => accounts.set_default("user@example.com"),
            1 => accounts.remove("user@example.com").map(|_| ()),
            2 => accounts.quota("user@example.com", 100, 10),
            _ => accounts
                .add(
                    "new@example.com",
                    "pw",
                    None,
                    false,
                    &Vault::new("passphrase"),
                )
                .map(|_| ()),
        };
        assert!(matches!(result, Err(Error::Corrupt(_))));
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
    assert!(!fs::read_dir(path.parent().unwrap()).unwrap().any(|item| {
        item.unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")
    }));
}

#[test]
fn malformed_account_roots_and_native_versions_cannot_become_a_writable_empty_vault() {
    let scratch = fixture();
    let path = scratch.path().join("private/accounts.json");
    for bytes in [
        b"{\"accounts\": [,,,".as_slice(),
        b"[1, 2, 3]",
        b"null",
        b"\"hello\"",
        b"42",
        b"\xff\xfe not utf-8",
    ] {
        assert_refused_unchanged(&path, bytes);
    }
    for data in [
        json!([]),
        json!([[], null]),
        Value::Null,
        json!("hello"),
        json!(42),
    ] {
        assert_refused_unchanged(
            &path,
            &serde_json::to_vec(&json!({"version":2,"data":data})).unwrap(),
        );
    }
    for version in [json!(true), json!("2"), json!(99)] {
        assert_refused_unchanged(
            &path,
            &serde_json::to_vec(&json!({"version":version,"data":document(entry())})).unwrap(),
        );
    }
}

#[test]
fn malformed_account_fields_and_ambiguous_identifiers_are_refused_before_every_mutation() {
    let scratch = fixture();
    let path = scratch.path().join("private/accounts.json");
    let mut cases = vec![
        json!({"accounts":{},"default_email":null}),
        document(json!("nope")),
        document(json!([
            "user@example.com",
            entry()["enc_password"],
            null,
            null,
            null,
            null,
            null
        ])),
    ];
    for field in ["email", "enc_password"] {
        let mut account = entry();
        account.as_object_mut().unwrap().remove(field);
        cases.push(document(account));
    }
    for (field, value) in [
        ("email", json!("   ")),
        ("email", json!(123)),
        ("enc_password", json!("!!! not base64 !!!")),
        ("enc_password", json!("c2hvcnQ")),
        ("label", json!(7)),
        ("quota_total", json!(-1)),
        ("quota_used", json!(1u64 << 61)),
        ("quota_total", json!(true)),
        ("quota_total", json!("lots")),
        ("surprise", json!("value")),
        ("last_used_iso", json!(20260101)),
        ("notes", json!([])),
    ] {
        let mut account = entry();
        account[field] = value;
        cases.push(document(account));
    }
    for changed in ["user@example.com", "User@Example.Com"] {
        let mut other = entry();
        other["email"] = json!(changed);
        cases.push(json!({"accounts":[entry(),other],"default_email":null}));
    }
    for label in ["WORK", " WORK "] {
        let mut first = entry();
        first["label"] = json!("work");
        let mut second = entry();
        second["email"] = json!("b@example.com");
        second["label"] = json!(label);
        cases.push(json!({"accounts":[first,second],"default_email":null}));
    }
    for damage in 0..4 {
        let mut raw = b"MBV2\x0f\x08\x01".to_vec();
        raw.extend_from_slice(&[0; 44]);
        match damage {
            0 => raw[0] = b'X',
            1 => raw[4] = 255,
            2 => {
                raw.pop();
            }
            _ => (),
        }
        let mut account = entry();
        let encoded = URL_SAFE_NO_PAD.encode(raw);
        account["enc_password"] = json!(if damage == 3 {
            format!("{encoded},")
        } else {
            encoded
        });
        cases.push(document(account));
    }
    for default in [json!("ghost@example.com"), json!([1])] {
        let mut data = document(entry());
        data["default_email"] = default;
        cases.push(data);
    }
    let mut unknown = document(entry());
    unknown["future_field"] = json!("preserve rather than discard");
    cases.push(unknown);
    for data in cases {
        assert_refused_unchanged(
            &path,
            &serde_json::to_vec(&json!({"version":2,"data":data})).unwrap(),
        );
    }
    let mut too_large = document(entry());
    too_large["accounts"][0]["quota_used"] =
        serde_json::from_str("1180591620717411303424").unwrap();
    assert_refused_unchanged(
        &path,
        &serde_json::to_vec(&json!({"version":2,"data":too_large})).unwrap(),
    );
}

#[test]
fn valid_native_accounts_reload_and_preserve_case_insensitive_labels_and_quota_boundaries() {
    let scratch = fixture();
    let path = scratch.path().join("private/accounts.json");
    let mut account = entry();
    account["label"] = json!("Primary");
    account["quota_total"] = json!(1u64 << 60);
    account["quota_used"] = json!(0);
    let data = document(account);
    Store::new(&path).lock().unwrap().save(&data).unwrap();
    let accounts = Accounts::new(&path);
    assert_eq!(
        accounts.list().unwrap().default_email.as_deref(),
        Some("user@example.com")
    );
    assert_eq!(
        accounts.find(Some("PRIMARY")).unwrap().email,
        "user@example.com"
    );
    accounts.set_default("pRiMaRy").unwrap();
    let before = fs::read(&path).unwrap();
    assert!(matches!(
        accounts.quota("user@example.com", (1u64 << 60) + 1, 0),
        Err(Error::Corrupt(_))
    ));
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(accounts.remove("primary").unwrap(), "user@example.com");
    assert!(accounts.list().unwrap().accounts.is_empty());
    assert!(accounts.list().unwrap().default_email.is_none());
}

#[test]
fn corrupt_account_content_is_backed_up_once_per_episode_without_overwriting_a_different_backup() {
    let scratch = fixture();
    let path = scratch.path().join("private/accounts.json");
    let accounts = Accounts::new(&path);
    let first = b"{ broken first account document";
    let second = b"{ broken second account document";
    let mut copies = Vec::new();
    for bytes in [first.as_slice(), second.as_slice()] {
        Store::new(&path)
            .lock()
            .unwrap()
            .write_bytes(bytes)
            .unwrap();
        for _ in 0..2 {
            let error = accounts.list().err().unwrap();
            assert!(
                matches!(&error, Error::Corrupt(message) if message.contains("recovery copy was preserved"))
            );
            assert_eq!(fs::read(&path).unwrap(), bytes);
        }
        let name = Store::new(&path).lock().unwrap().preserve().unwrap();
        let backup = path.parent().unwrap().join(name);
        assert_eq!(fs::read(&backup).unwrap(), bytes);
        copies.push(backup);
    }
    assert_ne!(copies[0], copies[1]);
    assert_eq!(fs::read(&copies[0]).unwrap(), first);
    assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 4);
    fs::write(&copies[1], b"different recovery content").unwrap();
    let error = accounts.list().err().unwrap();
    assert!(
        matches!(&error, Error::Corrupt(message) if message.contains("recovery copy was preserved"))
    );
    assert_eq!(fs::read(&copies[1]).unwrap(), b"different recovery content");
    let name = Store::new(&path).lock().unwrap().preserve().unwrap();
    let alternative = path.parent().unwrap().join(name);
    assert!(!copies.contains(&alternative));
    assert_eq!(fs::read(alternative).unwrap(), second);
    assert_eq!(fs::read(&path).unwrap(), second);
}

#[test]
fn stale_account_objects_reload_corruption_instead_of_overwriting_the_previous_credentials() {
    let scratch = fixture();
    let path = scratch.path().join("private/accounts.json");
    let accounts = Accounts::new(&path);
    Store::new(&path)
        .lock()
        .unwrap()
        .save(&document(entry()))
        .unwrap();
    assert_eq!(accounts.list().unwrap().accounts.len(), 1);
    assert_refused_unchanged(&path, b"{ broken since we loaded");
    assert!(matches!(
        accounts.set_default("user@example.com"),
        Err(Error::Corrupt(_))
    ));
    assert_eq!(fs::read(&path).unwrap(), b"{ broken since we loaded");
}
