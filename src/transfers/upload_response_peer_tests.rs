//! Invalid upload slot and registration replies never become indexing failures or repeated mutations.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::storage::files::Store;
use std::time::Duration;

fn saved_paths(states: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(states)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect()
}

fn require_released_lease(states: &Path) {
    let paths: Vec<_> = std::fs::read_dir(states)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .ends_with(".lease.lock")
        })
        .collect();
    assert_eq!(paths.len(), 1);
    assert!(
        Store::new(paths[0].with_extension(""))
            .with_timeout(Duration::ZERO)
            .lock()
            .is_ok()
    );
}

#[test]
fn malformed_fresh_upload_slots_refuse_before_body_or_registration_for_empty_and_nonempty_sources()
{
    for size in [0, 17] {
        for malformed in [
            json!({}),
            json!({"q":"https://x"}),
            json!({"p":42}),
            json!({"p":null}),
            json!({"p":""}),
            json!({"p":["https://x"]}),
            json!(["https://x"]),
            json!("https://x"),
            Value::Null,
        ] {
            let scratch = scratch();
            let source = source(scratch.path(), size);
            let original = std::fs::read(&source).unwrap();
            let states = scratch.path().join("private state");
            let vault = Vault::new("synthetic upload passphrase");
            let ((), calls) = test_peer::with_peer(
                |request| {
                    assert_eq!(
                        command(request),
                        json!({"a":"u","s":size}),
                        "malformed slot reached a chunk or registration"
                    );
                    Some(api(malformed.clone()))
                },
                |address| {
                    let error = transfer(&mut cloud(address), &source, &states, &vault)
                        .err()
                        .unwrap();
                    assert!(matches!(error, Error::AmbiguousMutation(_)));
                    assert_eq!(error.exit_code(), 1);
                    assert!(saved_paths(&states).is_empty());
                    require_released_lease(&states);
                    assert_eq!(std::fs::read(&source).unwrap(), original);
                },
            );
            assert_eq!(calls.len(), 1, "unusable mutation reply was retried");
        }
    }
}

#[test]
fn malformed_refreshed_upload_slot_preserves_the_prior_state_and_never_registers() {
    for size in [0, 17] {
        let scratch = scratch();
        let source = source(scratch.path(), size);
        let original = std::fs::read(&source).unwrap();
        let states = scratch.path().join("private state");
        let vault = Vault::new("synthetic upload passphrase");
        let before_refresh = std::sync::OnceLock::new();
        let mut slots = 0;
        let ((), calls) = test_peer::with_peer(
            |request| {
                if request.path.starts_with("/native-peer-upload/") {
                    assert_eq!(request.path, "/native-peer-upload/slot/0");
                    assert_eq!(request.body.len(), size);
                    return Some(Response {
                        status: 403,
                        headers: vec![],
                        body: vec![],
                    });
                }
                assert_eq!(command(request), json!({"a":"u","s":size}));
                slots += 1;
                match slots {
                    1 => Some(api(json!({"p":SLOT}))),
                    2 => {
                        let paths = saved_paths(&states);
                        assert_eq!(paths.len(), 1);
                        before_refresh
                            .set((paths[0].clone(), std::fs::read(&paths[0]).unwrap()))
                            .unwrap();
                        Some(api(json!({})))
                    }
                    _ => panic!("unusable refreshed slot was retried"),
                }
            },
            |address| {
                let error = transfer(&mut cloud(address), &source, &states, &vault)
                    .err()
                    .unwrap();
                assert!(matches!(error, Error::AmbiguousMutation(_)));
                let (path, bytes) = before_refresh.get().unwrap();
                assert_eq!(&std::fs::read(path).unwrap(), bytes);
                let saved = States::new(path).load().unwrap().unwrap();
                assert!(saved.completed.is_empty() && saved.completion_token.is_none());
                assert_eq!(saved.upload_url.as_deref(), Some(SLOT));
                assert!(!saved.registration_started && saved.registered_handle.is_none());
                require_released_lease(&states);
                assert_eq!(std::fs::read(&source).unwrap(), original);
            },
        );
        assert_eq!(slots, 2);
        assert_eq!(calls.len(), 3);
    }
}

#[test]
fn every_unusable_registration_shape_preserves_its_sent_fence_without_replaying() {
    for malformed in [
        json!({}),
        json!({"f":[]}),
        json!({"f":[{}]}),
        json!({"f":[{"h":""}]}),
        json!({"f":[{"h":42}]}),
        json!({"f":"nope"}),
        json!("not-a-dict"),
    ] {
        let scratch = scratch();
        let source = source(scratch.path(), 17);
        let original = std::fs::read(&source).unwrap();
        let states = scratch.path().join("private state");
        let vault = Vault::new("synthetic upload passphrase");
        let ((), calls) = test_peer::with_peer(
            |request| {
                if request.path.starts_with("/native-peer-upload/") {
                    assert_eq!(request.path, "/native-peer-upload/slot/0");
                    assert_eq!(request.body.len(), 17);
                    return Some(Response {
                        status: 200,
                        headers: vec![],
                        body: TOKEN.as_bytes().to_vec(),
                    });
                }
                Some(match command(request)["a"].as_str().unwrap() {
                    "u" => api(json!({"p":SLOT})),
                    "p" => api(malformed.clone()),
                    _ => panic!("registration fixture contacted an unexpected action"),
                })
            },
            |address| {
                let mut cloud = cloud(address);
                assert!(matches!(
                    transfer(&mut cloud, &source, &states, &vault),
                    Err(Error::AmbiguousMutation(_))
                ));
                let paths = saved_paths(&states);
                assert_eq!(paths.len(), 1);
                let bytes = std::fs::read(&paths[0]).unwrap();
                let saved = States::new(&paths[0]).load().unwrap().unwrap();
                assert!(saved.registration_started);
                assert!(saved.registered_handle.is_none());
                assert_eq!(saved.completed.keys().copied().collect::<Vec<_>>(), [0]);
                assert_eq!(saved.completion_token.as_deref(), Some(TOKEN));
                assert!(matches!(
                    transfer(&mut cloud, &source, &states, &vault),
                    Err(Error::AmbiguousMutation(_))
                ));
                assert_eq!(std::fs::read(&paths[0]).unwrap(), bytes);
                require_released_lease(&states);
                assert_eq!(std::fs::read(&source).unwrap(), original);
            },
        );
        assert_eq!(calls.len(), 3, "unknown registration was replayed");
        assert_eq!(
            calls
                .iter()
                .filter(|request| request.path.starts_with("/cs?") && command(request)["a"] == "p")
                .count(),
            1
        );
    }
}
