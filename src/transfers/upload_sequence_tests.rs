//! Two actual uploads reuse one cloud client without inheriting the prior token or failed worker.
#![allow(clippy::unwrap_used)]

use super::*;
use std::sync::OnceLock;

fn snapshots(states: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    std::fs::read_dir(states)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .map(|path| {
            let bytes = std::fs::read(&path).unwrap();
            (path, bytes)
        })
        .collect()
}

#[test]
fn sequential_uploads_keep_tokens_per_file_and_a_fixed_failure_does_not_poison_the_next_source() {
    for first_fails in [false, true] {
        let scratch = scratch();
        let first = scratch.path().join("first.bin");
        let second = scratch.path().join("second.bin");
        std::fs::write(&first, b"first").unwrap();
        std::fs::write(&second, b"second").unwrap();
        let states = scratch.path().join("states");
        let vault = Vault::new("synthetic sequential upload passphrase");
        let mut slots = 0;
        let mut registrations = Vec::new();
        let first_snapshot: OnceLock<(PathBuf, Vec<u8>)> = OnceLock::new();
        let first_is_unchanged = || {
            let (path, bytes) = first_snapshot.get().unwrap();
            assert_eq!(&std::fs::read(path).unwrap(), bytes);
        };
        let ((), calls) = test_peer::with_peer(
            |request| {
                if request.path.starts_with("/native-peer-upload/sequential/") {
                    let first = request.path == "/native-peer-upload/sequential/1/0";
                    assert_eq!(request.body.len(), if first { 5 } else { 6 });
                    if !first {
                        first_is_unchanged();
                        let documents = snapshots(&states);
                        assert_eq!(documents.len(), 2);
                        let second_path = documents
                            .keys()
                            .find(|path| *path != &first_snapshot.get().unwrap().0)
                            .unwrap();
                        let saved = States::new(second_path).load().unwrap().unwrap();
                        assert_eq!(saved.size, 6);
                        assert!(saved.completed.is_empty());
                        assert!(saved.completion_token.is_none());
                        assert!(!saved.registration_started && saved.registered_handle.is_none());
                    }
                    return Some(Response {
                        status: if first && first_fails { 400 } else { 200 },
                        headers: vec![],
                        body: if first && first_fails {
                            vec![]
                        } else if first {
                            b"FIRST".to_vec()
                        } else {
                            b"SECOND".to_vec()
                        },
                    });
                }
                let value = command(request);
                Some(match value["a"].as_str().unwrap() {
                    "u" => {
                        slots += 1;
                        assert!(slots <= 2);
                        if slots == 2 {
                            first_is_unchanged();
                            assert_eq!(snapshots(&states).len(), 1);
                            assert_eq!(value["s"], 6);
                        }
                        api(
                            json!({"p":format!("https://upload.mega.nz/native-peer-upload/sequential/{slots}")}),
                        )
                    }
                    "p" => {
                        let node = &value["n"][0];
                        let token = node["h"].as_str().unwrap().to_owned();
                        let raw = wire::aes_key_wrap_decrypt(
                            &wire::b64_url_decode(node["k"].as_str().unwrap()).unwrap(),
                            &MASTER,
                        )
                        .unwrap();
                        let key = keys::unpack_file_key(&wire::bytes_to_a32(&raw)).unwrap();
                        let attrs = wire::decrypt_attributes(
                            &wire::b64_url_decode(node["a"].as_str().unwrap()).unwrap(),
                            key.aes_key.as_slice(),
                        )
                        .unwrap();
                        assert_eq!(
                            token,
                            if attrs["n"] == "first.bin" {
                                "FIRST"
                            } else {
                                "SECOND"
                            }
                        );
                        if attrs["n"] == "second.bin" {
                            first_is_unchanged();
                            let documents = snapshots(&states);
                            assert_eq!(documents.len(), 2);
                            let second_path = documents
                                .keys()
                                .find(|path| *path != &first_snapshot.get().unwrap().0)
                                .unwrap();
                            let saved = States::new(second_path).load().unwrap().unwrap();
                            assert_eq!(saved.completion_token.as_deref(), Some("SECOND"));
                            assert_eq!(saved.completed.keys().copied().collect::<Vec<_>>(), [0]);
                            assert!(
                                saved.registration_started && saved.registered_handle.is_none()
                            );
                        }
                        registrations.push((attrs["n"].as_str().unwrap().to_owned(), token));
                        api(json!({"f":[{"h":if slots == 1 {"FILE0001"} else {"FILE0002"}}]}))
                    }
                    _ => panic!("sequential upload emitted an unrelated action"),
                })
            },
            |address| {
                let mut cloud = cloud(address);
                let one = transfer_to(
                    &mut cloud,
                    &first,
                    &states,
                    &vault,
                    "target",
                    "first-operation",
                );
                let one = if first_fails {
                    assert!(matches!(one, Err(Error::Protocol(message))
                        if message == "Upload chunk returned HTTP 400"));
                    None
                } else {
                    let one = one.unwrap();
                    assert_eq!(one.handle, "FILE0001");
                    Some(one)
                };
                assert!(!cloud.api.control.is_canceled());
                let documents = snapshots(&states);
                assert_eq!(documents.len(), 1);
                let (path, bytes) = documents.into_iter().next().unwrap();
                let saved = States::new(&path).load().unwrap().unwrap();
                assert_eq!(saved.size, 5);
                assert_eq!(
                    saved.completion_token.as_deref(),
                    (!first_fails).then_some("FIRST")
                );
                assert_eq!(
                    saved.registered_handle.as_deref(),
                    (!first_fails).then_some("FILE0001")
                );
                if first_fails {
                    assert!(saved.completed.is_empty() && !saved.registration_started);
                } else {
                    assert_eq!(saved.completed.keys().copied().collect::<Vec<_>>(), [0]);
                    assert!(saved.registration_started);
                }
                first_snapshot.set((path, bytes)).unwrap();
                let two = transfer_to(
                    &mut cloud,
                    &second,
                    &states,
                    &vault,
                    "target",
                    "second-operation",
                )
                .unwrap();
                assert_eq!(two.handle, "FILE0002");
                assert_eq!(two.size, 6);
                first_is_unchanged();
                let documents = snapshots(&states);
                assert_eq!(documents.len(), 2);
                let second_path = documents
                    .keys()
                    .find(|path| *path != &first_snapshot.get().unwrap().0)
                    .unwrap();
                let saved = States::new(second_path).load().unwrap().unwrap();
                assert_eq!(saved.completion_token.as_deref(), Some("SECOND"));
                assert_eq!(saved.registered_handle.as_deref(), Some("FILE0002"));
                two.acknowledge().unwrap();
                first_is_unchanged();
                assert_eq!(snapshots(&states).len(), 1);
                if let Some(one) = one {
                    one.acknowledge().unwrap();
                    assert!(snapshots(&states).is_empty());
                }
                assert!(!cloud.api.control.is_canceled());
            },
        );
        assert_eq!(slots, 2);
        assert_eq!(
            registrations,
            if first_fails {
                vec![("second.bin".into(), "SECOND".into())]
            } else {
                vec![
                    ("first.bin".into(), "FIRST".into()),
                    ("second.bin".into(), "SECOND".into()),
                ]
            }
        );
        assert_eq!(calls.len(), if first_fails { 5 } else { 6 });
        assert_eq!(std::fs::read(first).unwrap(), b"first");
        assert_eq!(std::fs::read(second).unwrap(), b"second");
    }
}
