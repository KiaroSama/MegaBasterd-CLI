//! Real upload wire, source ownership, registration and retained-receipt tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{
    control::{Control, RateLimiter},
    upload::{Uploaded, upload},
};
use crate::crypto::{chunks, keys, wire};
use crate::error::Error;
use crate::protocol::{
    api::Api,
    auth::Session,
    cloud::Cloud,
    test_peer::{self, Request, Response},
};
use crate::storage::{transfer_state::States, vault::Vault};
use crate::terminal::progress::Progress;

#[path = "upload_cancel_peer_tests.rs"]
mod cancel_tests;
#[path = "upload_health_peer_tests.rs"]
mod health_tests;
#[path = "upload_identity_peer_tests.rs"]
mod identity_tests;
#[path = "upload_lease_peer_tests.rs"]
mod lease_tests;
#[path = "limiter_peer_tests.rs"]
mod limiter_tests;
#[path = "upload_progress_peer_tests.rs"]
mod progress_tests;
#[path = "upload_response_peer_tests.rs"]
mod response_tests;
#[path = "upload_restart_peer_tests.rs"]
mod restart_tests;
#[path = "upload_sequence_tests.rs"]
mod sequence_tests;

const MASTER: [u8; 16] = [9; 16];
const TOKEN: &str = "FCCyf3QV62uAsbARFKbVd8zWyqOQXPFgEL9i";
const SLOT: &str = "https://upload.mega.nz/native-peer-upload/slot";
const NAME: &str = "OAD -  09v2.mkv";

fn scratch() -> crate::test_support::TempDir {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/upload-peers");
    std::fs::create_dir_all(&root).unwrap();
    crate::test_support::tempdir_in(root).unwrap()
}

fn source(root: &Path, size: usize) -> PathBuf {
    let path = root.join(NAME);
    std::fs::write(
        &path,
        (0..size)
            .map(|i| ((13 * i + 7) % 256) as u8)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    path
}

fn cloud(address: std::net::SocketAddr) -> Cloud {
    Cloud::new(
        Api::test_peer(address).unwrap(),
        Session {
            sid: "synthetic-session".into(),
            master_key: MASTER,
            rsa_private_key: None,
            user_handle: "testuser".into(),
            email: "fixture@example.invalid".into(),
        },
    )
}

fn command(request: &Request) -> Value {
    assert_eq!(request.method, "POST");
    assert!(request.path.starts_with("/cs?"));
    assert_eq!(request.headers["content-type"], "application/json");
    let envelope: Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(envelope.as_array().unwrap().len(), 1);
    envelope[0].clone()
}

fn api(value: Value) -> Response {
    Response {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: serde_json::to_vec(&json!([value])).unwrap(),
    }
}

fn transfer(
    cloud: &mut Cloud,
    source: &Path,
    states: &Path,
    vault: &Vault,
) -> crate::error::Result<Uploaded> {
    transfer_to(cloud, source, states, vault, "target", "job-fixture")
}

fn transfer_to(
    cloud: &mut Cloud,
    source: &Path,
    states: &Path,
    vault: &Vault,
    target: &str,
    operation: &str,
) -> crate::error::Result<Uploaded> {
    let control = cloud.api.control.clone();
    let progress = Progress::new(false);
    let item = progress.add(NAME, std::fs::metadata(source)?.len())?;
    let result = upload(
        cloud,
        source,
        target,
        None,
        1,
        states,
        vault,
        true,
        Some(operation),
        &RateLimiter::new(0.0)?,
        &progress,
        item,
        &control,
    );
    let snapshot = progress.snapshot(item)?;
    if let Ok(uploaded) = &result {
        assert_eq!(snapshot.total, uploaded.size);
        assert_eq!(snapshot.completed, uploaded.size);
        assert_eq!(snapshot.status, crate::terminal::progress::Status::Complete);
    } else {
        assert_ne!(snapshot.status, crate::terminal::progress::Status::Complete);
    }
    result
}

#[test]
fn actual_upload_registers_full_key_and_name_once_and_recovers_its_confirmed_receipt() {
    for size in [0usize, 17, 131089] {
        let scratch = scratch();
        let source = source(scratch.path(), size);
        let states = scratch.path().join("private state");
        let vault = Vault::new("synthetic upload passphrase");
        let mut encrypted = BTreeMap::new();
        let mut registered_key = None;
        let (_, calls) = test_peer::with_peer(
            |request| {
                assert_eq!(request.method, "POST");
                if let Some(offset) = request.path.strip_prefix("/native-peer-upload/slot/") {
                    let offset = offset.parse::<u64>().unwrap();
                    assert!(encrypted.insert(offset, request.body.clone()).is_none());
                    return Some(Response {
                        status: 200,
                        headers: vec![],
                        body: if offset + request.body.len() as u64 == size as u64 {
                            TOKEN.as_bytes().to_vec()
                        } else {
                            vec![]
                        },
                    });
                }
                let command = command(request);
                match command["a"].as_str().unwrap() {
                    "u" => {
                        assert_eq!(command["s"], size);
                        Some(api(json!({"p":SLOT})))
                    }
                    "p" => {
                        assert_eq!(command["t"], "target");
                        assert_eq!(command["n"].as_array().unwrap().len(), 1);
                        let node = &command["n"][0];
                        assert_eq!(
                            node["h"], TOKEN,
                            "completion token must not be encoded twice"
                        );
                        assert_eq!(node["t"], 0);
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
                        let mut plain = Vec::new();
                        for (&offset, data) in &encrypted {
                            assert_eq!(offset as usize, plain.len());
                            plain.extend(
                                wire::ctr_crypt_at_offset(
                                    key.aes_key.as_slice(),
                                    &key.nonce,
                                    offset,
                                    data,
                                )
                                .unwrap(),
                            );
                        }
                        assert_eq!(plain.len(), size);
                        let vectors: Value = serde_json::from_str(include_str!(
                            "../../tests/fixtures/transfers/vectors.json"
                        ))
                        .unwrap();
                        let expected = vectors["vectors"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .find(|v| v["size"] == size)
                            .unwrap();
                        assert_eq!(
                            hex::encode(Sha256::digest(&plain)),
                            expected["plaintext_sha256"].as_str().unwrap()
                        );
                        let macs = chunks::iter_chunks(size as u64)
                            .unwrap()
                            .map(|c| {
                                chunks::chunk_mac(
                                    &plain[c.offset as usize..c.end().unwrap() as usize],
                                    key.aes_key.as_slice(),
                                    &key.nonce,
                                )
                                .unwrap()
                            })
                            .collect::<Vec<_>>();
                        assert_eq!(
                            chunks::condense_mac(
                                &chunks::combine_chunk_macs(&macs, key.aes_key.as_slice()).unwrap()
                            )
                            .unwrap(),
                            key.mac
                        );
                        registered_key = Some(raw);
                        Some(api(json!({"f":[{"h":"AQIDBAUG"}]})))
                    }
                    _ => panic!("unexpected upload API action"),
                }
            },
            |address| {
                let mut cloud = cloud(address);
                let first = transfer(&mut cloud, &source, &states, &vault).unwrap();
                assert_eq!(first.handle, "AQIDBAUG");
                assert_eq!(first.name, NAME);
                assert_eq!(first.size, size as u64);
                let key = first.raw_key.clone();
                drop(first); // Simulate interruption before the caller acknowledges local finalization.
                let recovered = transfer(&mut cloud, &source, &states, &vault).unwrap();
                assert_eq!(recovered.handle, "AQIDBAUG");
                assert_eq!(recovered.raw_key, key);
                recovered.acknowledge().unwrap();
                drop(recovered);
                assert_eq!(std::fs::read(&source).unwrap().len(), size);
                let state_files = std::fs::read_dir(&states)
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .filter(|p| p.extension().is_some_and(|e| e == "json"))
                    .collect::<Vec<_>>();
                assert!(
                    state_files.is_empty(),
                    "acknowledgement left a live receipt"
                );
            },
        );
        assert_eq!(
            calls
                .iter()
                .filter(|r| r.path.starts_with("/cs?") && command(r)["a"] == "u")
                .count(),
            1
        );
        assert_eq!(
            calls
                .iter()
                .filter(|r| r.path.starts_with("/cs?") && command(r)["a"] == "p")
                .count(),
            1
        );
        assert_eq!(registered_key.unwrap().len(), 32);
        let chunks = calls
            .iter()
            .filter(|r| r.path.starts_with("/native-peer-upload/"))
            .collect::<Vec<_>>();
        assert_eq!(chunks.len(), if size > 131072 { 2 } else { 1 });
        if size == 0 {
            assert!(chunks[0].body.is_empty());
        }
    }
}

#[test]
fn same_length_source_change_after_chunk_send_refuses_registration() {
    let scratch = scratch();
    let source = source(scratch.path(), 17);
    let states = scratch.path().join("private state");
    let vault = Vault::new("synthetic upload passphrase");
    let (_, calls) = test_peer::with_peer(
        |request| {
            if request.path.starts_with("/native-peer-upload/") {
                // Mutate the original held object, not merely metadata, before registration can run.
                std::fs::write(&source, [0xff; 17]).unwrap();
                return Some(Response {
                    status: 200,
                    headers: vec![],
                    body: TOKEN.as_bytes().to_vec(),
                });
            }
            let command = command(request);
            assert_eq!(
                command["a"], "u",
                "changed source reached remote node registration"
            );
            Some(api(json!({"p":SLOT})))
        },
        |address| {
            let error = transfer(&mut cloud(address), &source, &states, &vault)
                .err()
                .unwrap();
            assert!(matches!(error, Error::Integrity(_)));
            assert!(
                error
                    .to_string()
                    .contains("changed while it was being uploaded")
            );
            assert_eq!(std::fs::read(&source).unwrap(), [0xff; 17]);
            assert!(
                std::fs::read_dir(&states).unwrap().all(|entry| entry
                    .unwrap()
                    .path()
                    .extension()
                    .is_none_or(|extension| extension != "json")),
                "changed-source coverage must not survive as resumable upload state"
            );
        },
    );
    assert_eq!(calls.len(), 2);
}

#[test]
fn unknown_registration_outcome_is_not_replayed_on_a_new_invocation() {
    let scratch = scratch();
    let source = source(scratch.path(), 17);
    let states = scratch.path().join("private state");
    let vault = Vault::new("synthetic upload passphrase");
    let (_, calls) = test_peer::with_peer(
        |request| {
            if request.path.starts_with("/native-peer-upload/") {
                return Some(Response {
                    status: 200,
                    headers: vec![],
                    body: TOKEN.as_bytes().to_vec(),
                });
            }
            match command(request)["a"].as_str().unwrap() {
                "u" => Some(api(json!({"p":SLOT}))),
                "p" => None,
                _ => panic!("unexpected action"),
            }
        },
        |address| {
            let mut cloud = cloud(address);
            assert!(matches!(
                transfer(&mut cloud, &source, &states, &vault),
                Err(Error::AmbiguousMutation(_))
            ));
            assert!(matches!(
                transfer(&mut cloud, &source, &states, &vault),
                Err(Error::AmbiguousMutation(_))
            ));
        },
    );
    assert_eq!(calls.len(), 3);
    assert_eq!(
        calls
            .iter()
            .filter(|r| r.path.starts_with("/cs?") && command(r)["a"] == "p")
            .count(),
        1
    );
    let entries = std::fs::read_dir(states)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect::<Vec<_>>();
    assert_eq!(entries.len(), 1);
    let saved = States::new(&entries[0]).load().unwrap().unwrap();
    assert!(saved.registration_started && saved.registered_handle.is_none());
}

#[test]
fn interrupted_upload_resumes_only_missing_offsets_but_expired_slot_restarts_coverage() {
    for expired in [false, true] {
        let scratch = scratch();
        let source = source(scratch.path(), 131089);
        let states = scratch.path().join("private state");
        let vault = Vault::new("synthetic upload passphrase");
        let mut slots = 0;
        let mut tails = 0;
        let mut first_ciphertext = None;
        let (_, calls) = test_peer::with_peer(
            |request| {
                if request.path.starts_with("/native-peer-upload/") {
                    if request.path.ends_with("/0") {
                        if let Some(bytes) = &first_ciphertext {
                            assert_eq!(&request.body, bytes);
                        } else {
                            first_ciphertext = Some(request.body.clone());
                        }
                        return Some(Response {
                            status: 200,
                            headers: vec![],
                            body: vec![],
                        });
                    }
                    assert!(request.path.ends_with("/131072"));
                    tails += 1;
                    return Some(Response {
                        status: if tails == 1 {
                            if expired { 410 } else { 400 }
                        } else {
                            200
                        },
                        headers: vec![],
                        body: if tails > 1 {
                            TOKEN.as_bytes().to_vec()
                        } else {
                            vec![]
                        },
                    });
                }
                match command(request)["a"].as_str().unwrap() {
                    "u" => {
                        slots += 1;
                        Some(api(json!({"p":SLOT})))
                    }
                    "p" => Some(api(json!({"f":[{"h":"AQIDBAUG"}]}))),
                    _ => panic!("unexpected upload action"),
                }
            },
            |address| {
                let mut cloud = cloud(address);
                if !expired {
                    assert!(matches!(
                        transfer(&mut cloud, &source, &states, &vault),
                        Err(Error::Protocol(_))
                    ));
                    let saved_paths: Vec<_> = std::fs::read_dir(&states)
                        .unwrap()
                        .map(|entry| entry.unwrap().path())
                        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
                        .collect();
                    assert_eq!(saved_paths.len(), 1);
                    let saved = States::new(&saved_paths[0]).load().unwrap().unwrap();
                    assert_eq!(saved.completed.keys().copied().collect::<Vec<_>>(), vec![0]);
                    assert!(saved.source_identity.is_some());
                    assert!(saved.completion_token.is_none());
                }
                let uploaded = transfer(&mut cloud, &source, &states, &vault).unwrap();
                assert_eq!(uploaded.handle, "AQIDBAUG");
                assert_eq!(uploaded.size, 131089);
                uploaded.acknowledge().unwrap();
            },
        );
        let offsets = calls
            .iter()
            .filter(|r| r.path.starts_with("/native-peer-upload/"))
            .map(|r| r.path.rsplit('/').next().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            offsets,
            if expired {
                vec!["0", "131072", "0", "131072"]
            } else {
                vec!["0", "131072", "131072"]
            }
        );
        assert_eq!(slots, if expired { 2 } else { 1 });
        assert_eq!(
            calls
                .iter()
                .filter(|r| r.path.starts_with("/cs?") && command(r)["a"] == "p")
                .count(),
            1
        );
    }
}

#[test]
fn malformed_completion_body_never_records_a_token_or_registers_a_remote_node() {
    for (size, body) in [
        (17, Vec::new()),
        (17, vec![0xff]),
        (131089, TOKEN.as_bytes().to_vec()),
    ] {
        let scratch = scratch();
        let source = source(scratch.path(), size);
        let states = scratch.path().join("private state");
        let vault = Vault::new("synthetic upload passphrase");
        let (_, calls) = test_peer::with_peer(
            |request| {
                if request.path.starts_with("/native-peer-upload/") {
                    return Some(Response {
                        status: 200,
                        headers: vec![],
                        body: body.clone(),
                    });
                }
                assert_eq!(
                    command(request)["a"],
                    "u",
                    "malformed completion reached registration"
                );
                Some(api(json!({"p":SLOT})))
            },
            |address| {
                assert!(matches!(
                    transfer(&mut cloud(address), &source, &states, &vault),
                    Err(Error::Protocol(_))
                ));
            },
        );
        assert_eq!(calls.len(), 2, "deterministic token error was retried");
        let paths = std::fs::read_dir(&states)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "json"))
            .collect::<Vec<_>>();
        assert_eq!(paths.len(), 1);
        let saved = States::new(&paths[0]).load().unwrap().unwrap();
        assert!(saved.completion_token.is_none() && saved.completed.is_empty());
        assert!(!saved.registration_started);
    }
}

#[test]
fn same_queued_operation_refuses_account_or_target_replanning_before_a_second_slot() {
    let scratch = scratch();
    let source = source(scratch.path(), 17);
    let states = scratch.path().join("private state");
    let vault = Vault::new("synthetic upload passphrase");
    let mut registrations = 0;
    let (_, calls) = test_peer::with_peer(
        |request| {
            if request.path.starts_with("/native-peer-upload/") {
                return Some(Response {
                    status: 200,
                    headers: vec![],
                    body: TOKEN.as_bytes().to_vec(),
                });
            }
            match command(request)["a"].as_str().unwrap() {
                "u" => Some(api(json!({"p":SLOT}))),
                "p" => {
                    registrations += 1;
                    Some(api(json!({"f":[{"h":"AQIDBAUG"}]})))
                }
                _ => panic!("unexpected queued upload action"),
            }
        },
        |address| {
            let mut first_cloud = cloud(address);
            drop(transfer(&mut first_cloud, &source, &states, &vault).unwrap());
            let mut changed = cloud(address);
            changed.session.email = "different@example.invalid".into();
            changed.session.user_handle = "different-user".into();
            assert!(matches!(
                transfer(&mut changed, &source, &states, &vault),
                Err(Error::Corrupt(_))
            ));
            assert!(matches!(
                transfer_to(
                    &mut first_cloud,
                    &source,
                    &states,
                    &vault,
                    "other-target",
                    "job-fixture"
                ),
                Err(Error::Corrupt(_))
            ));
            let recovered = transfer(&mut first_cloud, &source, &states, &vault).unwrap();
            assert_eq!(recovered.handle, "AQIDBAUG");
            drop(recovered);
            let independent = transfer_to(
                &mut changed,
                &source,
                &states,
                &vault,
                "other-target",
                "new-job",
            )
            .unwrap();
            assert_eq!(independent.handle, "AQIDBAUG");
        },
    );
    assert_eq!(
        registrations, 2,
        "same operation was replayed or distinct job was suppressed"
    );
    assert_eq!(calls.len(), 6);
}

#[test]
fn canceled_upload_stops_before_remote_node_registration() {
    let scratch = scratch();
    let source = source(scratch.path(), 17);
    let states = scratch.path().join("private state");
    let vault = Vault::new("synthetic upload passphrase");
    let control = Control::new();
    let (_, calls) = test_peer::with_peer(
        |request| {
            if request.path.starts_with("/native-peer-upload/") {
                control.cancel();
                return Some(Response {
                    status: 200,
                    headers: vec![],
                    body: TOKEN.as_bytes().to_vec(),
                });
            }
            assert_eq!(command(request)["a"], "u");
            Some(api(json!({"p":SLOT})))
        },
        |address| {
            let mut cloud = cloud(address);
            cloud.api.transport =
                crate::protocol::transport::Transport::test_peer(address, control.clone()).unwrap();
            cloud.api.control = control.clone();
            let error = transfer(&mut cloud, &source, &states, &vault)
                .err()
                .unwrap();
            assert_eq!(error.exit_code(), 130);
        },
    );
    assert_eq!(calls.len(), 2);
}
