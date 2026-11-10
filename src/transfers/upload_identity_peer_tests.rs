//! Actual empty-upload finalization rejects changed sources and preserves native deletion guards.
#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn zero_byte_source_growth_after_send_never_registers_or_retains_resumable_coverage() {
    let scratch = scratch();
    let source = source(scratch.path(), 0);
    let states = scratch.path().join("private state");
    let vault = Vault::new("synthetic upload passphrase");
    let ((), calls) = test_peer::with_peer(
        |request| {
            if request.path.starts_with("/native-peer-upload/") {
                assert_eq!(request.path, "/native-peer-upload/slot/0");
                assert!(request.body.is_empty());
                // Change the same held object; no replacement or sharing-mode bypass.
                std::fs::write(&source, b"grew!").unwrap();
                return Some(Response {
                    status: 200,
                    headers: vec![],
                    body: TOKEN.as_bytes().to_vec(),
                });
            }
            assert_eq!(
                command(request),
                json!({"a":"u","s":0}),
                "changed empty source reached registration or requested another slot"
            );
            Some(api(json!({"p":SLOT})))
        },
        |address| {
            let mut cloud = cloud(address);
            let error = transfer(&mut cloud, &source, &states, &vault)
                .err()
                .unwrap();
            assert!(matches!(error, Error::Integrity(message)
                if message == "Local file changed while it was being uploaded; no remote node was registered"));
            assert_eq!(std::fs::read(&source).unwrap(), b"grew!");
            let paths: Vec<_> = std::fs::read_dir(&states)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect();
            assert!(
                paths
                    .iter()
                    .all(|path| path.extension().is_none_or(|extension| extension != "json"))
            );
            let leases: Vec<_> = paths
                .iter()
                .filter(|path| {
                    path.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .ends_with(".lease.lock")
                })
                .collect();
            assert_eq!(leases.len(), 1);
            assert!(
                crate::storage::files::Store::new(leases[0].with_extension(""))
                    .with_timeout(std::time::Duration::ZERO)
                    .lock()
                    .is_ok()
            );
        },
    );
    assert_eq!(calls.len(), 2, "changed empty upload retried or registered");
}

#[derive(Clone, Copy, Debug)]
enum PathChange {
    Replace,
    Remove,
}

#[test]
fn empty_source_path_changes_are_rejected_or_prevented_by_the_native_held_handle() {
    use crate::platform::secure_files::file_identity;
    use std::fs::{File, FileTimes, OpenOptions};

    for change in [PathChange::Replace, PathChange::Remove] {
        let scratch = scratch();
        let source = source(scratch.path(), 0);
        let moved = scratch.path().join("original-held.bin");
        let replacement = scratch.path().join("other-empty.bin");
        std::fs::write(&replacement, b"").unwrap();
        let original = File::open(&source).unwrap();
        let original_id = file_identity(&original).unwrap();
        let modified = original.metadata().unwrap().modified().unwrap();
        let other = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&replacement)
            .unwrap();
        other
            .set_times(FileTimes::new().set_modified(modified))
            .unwrap();
        assert_ne!(file_identity(&other).unwrap(), original_id);
        let states = scratch.path().join("private state");
        let vault = Vault::new("synthetic path mutation passphrase");
        let mut bodies = 0;
        let mut registrations = 0;
        let ((), calls) = test_peer::with_peer(
            |request| {
                if request.path.starts_with("/native-peer-upload/") {
                    bodies += 1;
                    assert_eq!(bodies, 1);
                    assert_eq!(request.path, "/native-peer-upload/slot/0");
                    assert!(request.body.is_empty());
                    let changed = match change {
                        PathChange::Replace => std::fs::rename(&source, &moved),
                        PathChange::Remove => std::fs::remove_file(&source),
                    };
                    #[cfg(unix)]
                    {
                        changed.unwrap();
                        if matches!(change, PathChange::Replace) {
                            // Both objects stay live; equal bytes/mtime cannot hide replacement.
                            std::fs::rename(&replacement, &source).unwrap();
                            let current = File::open(&source).unwrap();
                            assert_ne!(file_identity(&current).unwrap(), original_id);
                            assert_eq!(current.metadata().unwrap().len(), 0);
                            assert_eq!(current.metadata().unwrap().modified().unwrap(), modified);
                        } else {
                            assert!(!source.exists());
                        }
                    }
                    #[cfg(windows)]
                    {
                        // The production source open denies delete sharing, including renaming away.
                        assert_eq!(changed.unwrap_err().raw_os_error(), Some(32));
                        assert!(!moved.exists());
                        assert_eq!(
                            file_identity(&File::open(&source).unwrap()).unwrap(),
                            original_id
                        );
                    }
                    assert_eq!(file_identity(&original).unwrap(), original_id);
                    return Some(Response {
                        status: 200,
                        headers: vec![],
                        body: TOKEN.as_bytes().to_vec(),
                    });
                }
                let value = command(request);
                Some(match value["a"].as_str().unwrap() {
                    "u" => {
                        assert_eq!(value["s"], 0);
                        api(json!({"p":SLOT}))
                    }
                    "p" => {
                        registrations += 1;
                        assert!(cfg!(windows), "changed Unix source reached registration");
                        assert_eq!(registrations, 1);
                        assert_eq!(value["t"], "target");
                        let node = &value["n"][0];
                        assert_eq!(node["h"], TOKEN);
                        let raw = wire::aes_key_wrap_decrypt(
                            &wire::b64_url_decode(node["k"].as_str().unwrap()).unwrap(),
                            &MASTER,
                        )
                        .unwrap();
                        assert_eq!(raw.len(), 32);
                        let key = keys::unpack_file_key(&wire::bytes_to_a32(&raw)).unwrap();
                        let attrs = wire::decrypt_attributes(
                            &wire::b64_url_decode(node["a"].as_str().unwrap()).unwrap(),
                            key.aes_key.as_slice(),
                        )
                        .unwrap();
                        assert_eq!(attrs["n"], NAME);
                        api(json!({"f":[{"h":"AQIDBAUG"}]}))
                    }
                    _ => panic!("unexpected empty-source path-change action"),
                })
            },
            |address| {
                let result = transfer(&mut cloud(address), &source, &states, &vault);
                #[cfg(unix)]
                {
                    let error = result.err().unwrap();
                    let expected = match change {
                        PathChange::Replace => {
                            "Local file changed while it was being uploaded; its source path was replaced"
                        }
                        PathChange::Remove => {
                            "Local file disappeared during upload; no remote node was registered"
                        }
                    };
                    assert!(matches!(error, Error::Integrity(message) if message == expected));
                    if matches!(change, PathChange::Replace) {
                        assert_eq!(std::fs::read(&source).unwrap(), b"");
                        assert_eq!(std::fs::read(&moved).unwrap(), b"");
                    } else {
                        assert!(!source.exists());
                    }
                }
                #[cfg(windows)]
                {
                    let uploaded = result.unwrap();
                    assert_eq!((uploaded.handle.as_str(), uploaded.size), ("AQIDBAUG", 0));
                    uploaded.acknowledge().unwrap();
                    assert_eq!(std::fs::read(&source).unwrap(), b"");
                    assert_eq!(std::fs::read(&replacement).unwrap(), b"");
                }
                assert!(std::fs::read_dir(&states).unwrap().all(|entry| {
                    entry
                        .unwrap()
                        .path()
                        .extension()
                        .is_none_or(|extension| extension != "json")
                }));
            },
        );
        assert_eq!(bodies, 1);
        assert_eq!(registrations, usize::from(cfg!(windows)));
        assert_eq!(calls.len(), if cfg!(windows) { 3 } else { 2 });
        assert_eq!(file_identity(&original).unwrap(), original_id);
        drop(other);
        drop(original);
    }
}
