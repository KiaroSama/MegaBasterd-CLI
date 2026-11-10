//! Fresh native session replacement preserves unusable or foreign saved data.
#![allow(clippy::unwrap_used)]

use std::{fs, path::Path};

use megabasterd_cli::{
    error::Error,
    platform::secure_files::PrivateDirectory,
    protocol::auth::Session,
    storage::{files::Store, paths::Paths, sessions::Sessions, vault::Vault},
};
use serde_json::json;

fn session(sid: &str) -> Session {
    Session {
        sid: sid.into(),
        master_key: [0x42; 16],
        rsa_private_key: None,
        user_handle: "synthetic-user".into(),
        email: "fixture@example.invalid".into(),
    }
}

#[test]
fn passive_commands_cannot_explicitly_invalidate_a_cached_remote_session() {
    let code = |source: &str| {
        assert!(
            !source.contains("/*") && !source.contains("*/"),
            "Block comments require a reviewed session contract update"
        );
        source
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .flat_map(str::split_whitespace)
            .collect::<String>()
    };
    let account = code(include_str!("../src/cli/accounts.rs"));
    for allowed in ["Account::Logout", ".end_cached(", "\"sml\""] {
        assert!(
            account.contains(allowed),
            "missing logout control: {allowed}"
        );
    }
    for (name, source) in [
        ("cloud/share", include_str!("../src/cli/cloud.rs")),
        ("upload", include_str!("../src/cli/upload.rs")),
        ("queue", include_str!("../src/cli/queue.rs")),
        ("download", include_str!("../src/cli/download.rs")),
        ("stream", include_str!("../src/cli/stream.rs")),
        ("context", include_str!("../src/cli/context.rs")),
        (
            "queue executor",
            include_str!("../src/cli/queue_transfer.rs"),
        ),
    ] {
        let source = code(source);
        for forbidden in [".end_cached(", ".logout(", "\"sml\""] {
            assert!(
                !source.contains(forbidden),
                "{name} explicitly invalidates a cached remote session: {forbidden}"
            );
        }
    }
}

#[test]
fn session_requires_a_passphrase_and_roundtrips_every_secret_field_encrypted() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/session-storage");
    fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    let paths = Paths {
        root: scratch.path().to_owned(),
        user: scratch.path().join("private user/native-v2"),
        logs: scratch.path().join("private logs"),
        output: scratch.path().join("output"),
    };
    let mut original = session("session-id");
    let path = paths.session(&original.email);
    assert_eq!(path, paths.session(&original.email.to_uppercase()));
    let basename = path.file_stem().unwrap().to_str().unwrap();
    assert_eq!(basename.len(), 64);
    assert!(basename.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert!(!basename.contains("fixture") && !basename.contains("example"));
    let sessions = Sessions::new(&path);
    original.master_key = [1; 16];
    original.rsa_private_key = Some(vec![2; 8]);
    assert!(matches!(
        sessions.remember(&original, &Vault::new("")),
        Err(Error::Auth(_))
    ));
    assert!(!path.exists());
    assert!(matches!(
        sessions.end_cached(&original.email, &Vault::new(""), |_| panic!(
            "missing passphrase must not reach logout"
        )),
        Err(Error::Auth(_))
    ));
    assert!(fs::read_dir(scratch.path()).unwrap().next().is_none());
    let vault = Vault::new("synthetic roundtrip passphrase");
    sessions.remember(&original, &vault).unwrap();
    let bytes = fs::read(&path).unwrap();
    let raw = std::str::from_utf8(&bytes).unwrap();
    assert!(!raw.contains("master_key") && !raw.contains("session-id"));
    assert!(!raw.contains(&original.email));
    let private = PrivateDirectory::open(path.parent().unwrap()).unwrap();
    let checked = private
        .open_private(path.file_name().unwrap(), false)
        .unwrap();
    assert_eq!(checked.metadata().unwrap().len(), bytes.len() as u64);
    drop(checked);
    drop(private);
    let mut entries: Vec<_> = fs::read_dir(path.parent().unwrap())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    entries.sort();
    let data_name = path.file_name().unwrap().to_owned();
    let mut lock_name = data_name.clone();
    lock_name.push(".lock");
    let mut expected = vec![data_name, lock_name.clone()];
    expected.sort();
    assert_eq!(entries, expected);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o600);
    }
    let sealed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let encrypted = sealed["data"]["encrypted"].as_str().unwrap();
    for incorrect in ["", "wrong passphrase"] {
        assert!(matches!(
            Vault::new(incorrect).open(encrypted, b"session:fixture@example.invalid"),
            Err(Error::Auth(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }
    let plaintext = vault
        .open(encrypted, b"session:fixture@example.invalid")
        .unwrap();
    let loaded: Session = serde_json::from_slice(&plaintext).unwrap();
    assert_eq!(loaded.sid, original.sid);
    assert_eq!(loaded.master_key, original.master_key);
    assert_eq!(loaded.rsa_private_key, original.rsa_private_key);
    assert_eq!(loaded.user_handle, original.user_handle);
    assert_eq!(loaded.email, original.email);

    assert!(sessions.has_cached().unwrap());
    sessions.forget().unwrap();
    assert!(!path.exists() && !sessions.has_cached().unwrap());
    sessions.forget().unwrap();
    assert!(!sessions.has_cached().unwrap());
    let remaining: Vec<_> = fs::read_dir(path.parent().unwrap())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(remaining, [lock_name]);
}

#[test]
fn native_session_replacement_refuses_corrupt_future_foreign_and_wrong_vault_files_unchanged() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/session-storage");
    fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    let vault = Vault::new("synthetic correct passphrase");
    let account = session("current-sid");
    for (index, raw) in [
        br#""encrypted""#.as_slice(),
        br#"["encrypted"]"#,
        b"123",
        b"null",
        b"true",
        br#""anything""#,
        b"[]",
        br#"{"version":2,"encrypted":42}"#,
        b"not JSON",
        br#"{"version":99,"data":{"encrypted":"future-do-not-replace"}}"#,
        br#"{"version":2,"data":{"encrypted":17}}"#,
        br#"{"version":2,"data":{"encrypted":"malformed"}}"#,
    ]
    .into_iter()
    .enumerate()
    {
        let path = scratch.path().join(format!("corrupt-{index}.json"));
        Store::new(&path).lock().unwrap().write_bytes(raw).unwrap();
        assert!(matches!(
            Sessions::new(&path).remember(&account, &vault),
            Err(Error::Corrupt(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), raw);
    }
    let path = scratch.path().join("valid.json");
    let store = Sessions::new(&path);
    store.remember(&account, &vault).unwrap();
    let original = fs::read(&path).unwrap();
    let document: serde_json::Value = serde_json::from_slice(&original).unwrap();
    let mut unknown_envelope = document.clone();
    unknown_envelope["future_field"] = json!({"nested": 1});
    let mut unknown_sealed = document.clone();
    unknown_sealed["data"]["future_field"] = json!({"nested": 1});
    let mut unknown_plaintext = serde_json::to_value(&account).unwrap();
    unknown_plaintext["future_field"] = json!({"nested": 1});
    let unknown_content = json!({"version":2,"data":{"encrypted":vault.seal(
        &serde_json::to_vec(&unknown_plaintext).unwrap(),
        b"session:fixture@example.invalid"
    ).unwrap()}});
    for malformed in [unknown_envelope, unknown_sealed, unknown_content] {
        let raw = serde_json::to_vec(&malformed).unwrap();
        Store::new(&path).lock().unwrap().write_bytes(&raw).unwrap();
        assert!(matches!(
            store.remember(&session("replacement-sid"), &vault),
            Err(Error::Corrupt(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), raw);
        assert!(matches!(
            store.end_cached(&account.email, &vault, |_| panic!(
                "unknown saved fields must not reach remote logout"
            )),
            Err(Error::Corrupt(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), raw);
    }
    Store::new(&path)
        .lock()
        .unwrap()
        .write_bytes(&original)
        .unwrap();
    assert!(matches!(
        store.remember(&session("replacement-sid"), &Vault::new("wrong passphrase")),
        Err(Error::Auth(_))
    ));
    assert_eq!(fs::read(&path).unwrap(), original);
    let mut foreign = session("foreign-sid");
    foreign.email = "other@example.invalid".into();
    assert!(matches!(
        store.remember(&foreign, &vault),
        Err(Error::Auth(_))
    ));
    assert_eq!(fs::read(&path).unwrap(), original);
    store.remember(&session("replacement-sid"), &vault).unwrap();
    let current = Store::new(&path)
        .lock()
        .unwrap()
        .load::<serde_json::Value>()
        .unwrap()
        .unwrap();
    let plaintext = vault
        .open(
            current["encrypted"].as_str().unwrap(),
            b"session:fixture@example.invalid",
        )
        .unwrap();
    let loaded: Session = serde_json::from_slice(&plaintext).unwrap();
    assert_eq!(loaded.sid, "replacement-sid");
    assert_eq!(loaded.master_key, account.master_key);
    // A valid envelope with an invalid plaintext root is also saved data, not permission to reset.
    let bad =
        json!({"encrypted":vault.seal(b"[1,2,3]", b"session:fixture@example.invalid").unwrap()});
    Store::new(&path).lock().unwrap().save(&bad).unwrap();
    let before = fs::read(&path).unwrap();
    assert!(matches!(
        store.remember(&account, &vault),
        Err(Error::Corrupt(_))
    ));
    assert_eq!(fs::read(&path).unwrap(), before);
    assert!(!fs::read_dir(scratch.path()).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")
    }));
}
