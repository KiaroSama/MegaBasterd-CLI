//! Private commits retry bounded transient replacement failures without losing saved bytes.
#![allow(clippy::unwrap_used)]

use std::{
    ffi::OsStr,
    fs,
    io::{Read, Write},
    path::Path,
    time::Duration,
};

use super::Store;
use crate::{
    error::Error,
    protocol::auth::Session,
    storage::{sessions::Sessions, vault::Vault},
};
use serde_json::{Value, json};

#[test]
fn failed_recovery_write_removes_only_its_new_partial_copy_and_a_retry_can_preserve() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/private-commit");
    fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    let path = scratch.path().join("accounts.json");
    let original = b"{ controlled malformed account file";
    let locked = Store::new(&path).lock().unwrap();
    locked.write_bytes(original).unwrap();
    let failed = locked.preserve_with_write(|file, bytes| {
        file.write_all(&bytes[..5])?;
        Err(std::io::Error::other("controlled partial backup write").into())
    });
    assert!(matches!(failed, Err(Error::Io(_))));
    assert_eq!(fs::read(&path).unwrap(), original);
    assert_eq!(fs::read_dir(scratch.path()).unwrap().count(), 2);
    let name = locked.preserve().unwrap();
    assert_eq!(fs::read(scratch.path().join(&name)).unwrap(), original);
    let mut invoked = false;
    assert_eq!(
        locked
            .preserve_with_write(|_, _| {
                invoked = true;
                panic!("existing verified backup must not be overwritten")
            })
            .unwrap(),
        name
    );
    assert!(!invoked);
    assert_eq!(fs::read_dir(scratch.path()).unwrap().count(), 3);
}

#[test]
fn replacement_errors_and_unwind_preserve_live_bytes_and_remove_the_owned_stage() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/private-commit");
    fs::create_dir_all(&base).unwrap();
    for (existing, name) in [false, true].into_iter().flat_map(|existing| {
        ["state.json", "config.json", "accounts.json"].map(|name| (existing, name))
    }) {
        for mode in ["permission", "io", "validation", "canceled", "unwind"] {
            let scratch = tempfile::tempdir_in(&base).unwrap();
            let path = scratch.path().join(name);
            let store = Store::new(&path);
            let locked = store.lock().unwrap();
            let original = existing.then_some(b"previous validated bytes".as_slice());
            if let Some(bytes) = original {
                locked.write_bytes(bytes).unwrap();
            }
            let replacement = b"new staged bytes";
            let mut calls = 0;
            let mut waits = Vec::new();
            let mut stage_name = None;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                locked.write_bytes_with_replace_and_wait(
                    replacement,
                    |directory, stage, destination| {
                        calls += 1;
                        assert_eq!(destination, OsStr::new(name));
                        let mut file = directory.open_private(stage, false).unwrap();
                        let mut bytes = Vec::new();
                        file.read_to_end(&mut bytes).unwrap();
                        assert_eq!(bytes, replacement);
                        if let Some(previous) = &stage_name {
                            assert_eq!(previous, stage);
                        } else {
                            stage_name = Some(stage.to_owned());
                        }
                        assert_eq!(fs::read(&path).ok().as_deref(), original);
                        assert_eq!(
                            fs::read_dir(scratch.path()).unwrap().count(),
                            2 + usize::from(existing)
                        );
                        assert!(matches!(
                            Store::new(&path).with_timeout(Duration::ZERO).lock(),
                            Err(Error::Busy(_))
                        ));
                        match mode {
                            "permission" => Err(std::io::Error::new(
                                std::io::ErrorKind::PermissionDenied,
                                "controlled replace refusal",
                            )
                            .into()),
                            "io" => Err(std::io::Error::other("disk full").into()),
                            "validation" => Err(Error::invalid("controlled unsafe replacement")),
                            "canceled" => Err(Error::Canceled),
                            "unwind" => panic!("controlled replacement unwind"),
                            _ => unreachable!(),
                        }
                    },
                    |delay| waits.push(delay),
                )
            }));
            assert_eq!(calls, if mode == "permission" { 5 } else { 1 });
            assert_eq!(
                waits,
                if mode == "permission" {
                    vec![50, 100, 150, 200]
                        .into_iter()
                        .map(Duration::from_millis)
                        .collect::<Vec<_>>()
                } else {
                    Vec::new()
                }
            );
            match mode {
                "unwind" => {
                    let payload = result.unwrap_err();
                    assert_eq!(
                        payload.downcast_ref::<&str>(),
                        Some(&"controlled replacement unwind")
                    );
                }
                "permission" => assert!(
                    matches!(result.unwrap(), Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied && error.to_string() == "controlled replace refusal")
                ),
                "io" => assert!(
                    matches!(result.unwrap(), Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::Other && error.to_string() == "disk full")
                ),
                "validation" => assert!(
                    matches!(result.unwrap(), Err(Error::Invalid(reason)) if reason == "controlled unsafe replacement")
                ),
                "canceled" => assert!(matches!(result.unwrap(), Err(Error::Canceled))),
                _ => unreachable!(),
            }
            assert_eq!(fs::read(&path).ok().as_deref(), original);
            assert_eq!(
                fs::read_dir(scratch.path()).unwrap().count(),
                1 + usize::from(existing)
            );
            locked.write_bytes(replacement).unwrap();
            assert_eq!(fs::read(&path).unwrap(), replacement);
            assert_eq!(fs::read_dir(scratch.path()).unwrap().count(), 2);
        }
    }
}

#[test]
fn transient_private_replacement_reuses_one_complete_stage_until_the_fourth_attempt_succeeds() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/private-commit");
    fs::create_dir_all(&base).unwrap();
    let codes = [
        None,
        #[cfg(windows)]
        Some(windows_sys::Win32::Foundation::ERROR_SHARING_VIOLATION as i32),
        #[cfg(windows)]
        Some(windows_sys::Win32::Foundation::ERROR_LOCK_VIOLATION as i32),
    ];
    for (name, original, replacement) in [
        (
            "config.json",
            br#"{"version":2,"data":{"max_workers":7}}"#.as_slice(),
            br#"{"version":2,"data":{"max_workers":9}}"#.as_slice(),
        ),
        (
            "accounts.json",
            br#"{"version":2,"data":{"accounts":[],"default_email":null}}"#.as_slice(),
            br#"{"version":2,"data":{"accounts":[],"default_email":""}}"#.as_slice(),
        ),
    ] {
        for code in codes {
            let scratch = tempfile::tempdir_in(&base).unwrap();
            let path = scratch.path().join(name);
            let locked = Store::new(&path).lock().unwrap();
            locked.write_bytes(original).unwrap();
            let mut calls = 0;
            let mut waits = Vec::new();
            let mut stage_name = None;
            let mut stage_identity = None;
            locked
                .write_bytes_with_replace_and_wait(
                    replacement,
                    |directory, stage, destination| {
                        calls += 1;
                        assert_eq!(destination, OsStr::new(name));
                        assert_eq!(fs::read(&path).unwrap(), original);
                        assert_eq!(fs::read_dir(scratch.path()).unwrap().count(), 3);
                        let mut staged = directory.open_private(stage, false).unwrap();
                        let identity =
                            crate::platform::secure_files::file_identity(&staged).unwrap();
                        let mut actual = Vec::new();
                        staged.read_to_end(&mut actual).unwrap();
                        assert_eq!(actual, replacement);
                        if let Some(previous) = &stage_name {
                            assert_eq!(previous, stage);
                            assert_eq!(stage_identity.as_ref(), Some(&identity));
                        } else {
                            stage_name = Some(stage.to_owned());
                            stage_identity = Some(identity);
                        }
                        assert!(matches!(
                            Store::new(&path).with_timeout(Duration::ZERO).lock(),
                            Err(Error::Busy(_))
                        ));
                        // The verification handle denies delete-sharing on Windows.
                        drop(staged);
                        if calls <= 3 {
                            return Err(match code {
                                Some(code) => std::io::Error::from_raw_os_error(code),
                                None => std::io::Error::new(
                                    std::io::ErrorKind::PermissionDenied,
                                    "controlled transient replacement refusal",
                                ),
                            }
                            .into());
                        }
                        directory.replace(stage, destination)
                    },
                    |delay| waits.push(delay),
                )
                .unwrap();
            assert_eq!(calls, 4);
            assert_eq!(waits, [50, 100, 150].map(Duration::from_millis));
            assert_eq!(fs::read(&path).unwrap(), replacement);
            assert_eq!(fs::read_dir(scratch.path()).unwrap().count(), 2);
            let value = locked.load::<Value>().unwrap().unwrap();
            if name == "config.json" {
                assert_eq!(value["max_workers"], 9);
            } else {
                assert_eq!(value, json!({"accounts":[],"default_email":""}));
            }
        }
    }
}

#[test]
fn failed_private_commit_preserves_the_previous_session_and_removes_only_its_stage() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/private-commit");
    fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    let vault = Vault::new("synthetic commit passphrase");
    let email = "commit@example.invalid";
    let session = Session {
        sid: "original-session-id".into(),
        master_key: [1; 16],
        rsa_private_key: Some(vec![2; 8]),
        user_handle: "synthetic-user".into(),
        email: email.into(),
    };
    for existing in [false, true] {
        let path = scratch.path().join(if existing {
            "existing.json"
        } else {
            "absent.json"
        });
        let sessions = Sessions::new(&path);
        if existing {
            sessions.remember(&session, &vault).unwrap();
        }
        let original = fs::read(&path).ok();
        let store = Store::new(&path);
        let locked = store.lock().unwrap();
        let mut updated = session.clone();
        updated.sid = "replacement-session-id".into();
        let replacement = json!({"version":2,"data":{"encrypted":vault.seal(
            &serde_json::to_vec(&updated).unwrap(),
            b"session:commit@example.invalid",
        ).unwrap()}});
        let payload = serde_json::to_vec(&replacement).unwrap();
        let mut attempted = false;
        let result = locked.write_bytes_with_replace(&payload, |directory, stage, destination| {
            attempted = true;
            assert_eq!(destination, path.file_name().unwrap());
            let mut staged = directory.open_private(stage, false).unwrap();
            let mut actual = Vec::new();
            staged.read_to_end(&mut actual).unwrap();
            assert_eq!(
                actual, payload,
                "fault must follow a complete real staging write"
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                assert_eq!(staged.metadata().unwrap().mode() & 0o7777, 0o600);
            }
            assert!(matches!(
                Store::new(&path).with_timeout(Duration::ZERO).lock(),
                Err(Error::Busy(_))
            ));
            Err(std::io::Error::other("controlled replacement failure").into())
        });
        assert!(attempted);
        assert!(
            matches!(result, Err(Error::Io(error)) if error.to_string()=="controlled replacement failure")
        );
        assert_eq!(fs::read(&path).ok(), original);
        assert!(!fs::read_dir(scratch.path()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")
        }));
        assert!(
            path.with_extension("json.lock").is_file(),
            "persistent lock sidecar must survive"
        );
        if existing {
            let sealed = locked.load::<Value>().unwrap().unwrap();
            let plaintext = vault
                .open(
                    sealed["encrypted"].as_str().unwrap(),
                    b"session:commit@example.invalid",
                )
                .unwrap();
            let restored: Session = serde_json::from_slice(&plaintext).unwrap();
            assert_eq!(restored.sid, session.sid);
            assert_eq!(restored.master_key, session.master_key);
            assert_eq!(restored.rsa_private_key, session.rsa_private_key);
        }
        drop(locked);
        assert!(
            Store::new(&path)
                .with_timeout(Duration::ZERO)
                .lock()
                .is_ok()
        );
    }
}
