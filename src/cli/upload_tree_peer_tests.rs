//! Structured CLI orchestration against an actual bounded TLS/API upload peer.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{collections::HashMap, path::Path};

use serde_json::{Value, json};

use super::super::{
    args::{AccountOptions, Upload},
    context::Context,
};
use super::{Job, finalize, structured, tree_folder};
use crate::{
    crypto::wire,
    error::Error,
    protocol::{
        api::Api,
        auth::Session,
        cloud::Cloud,
        test_peer::{self, Request, Response},
    },
    storage::{
        transfer_state::{States, TransferState},
        vault::Vault,
    },
    terminal::progress::{Progress, Status},
    transfers::{
        control::RateLimiter, upload::confirmed_receipt, upload_tree, upload_tree_state::Journal,
    },
};

#[path = "upload_tree_failure_tests.rs"]
mod failure_tests;
#[path = "upload_finalization_peer_tests.rs"]
mod finalization_tests;
#[path = "upload_symlink_peer_tests.rs"]
mod symlink_tests;
#[path = "upload_timing_peer_tests.rs"]
mod timing_tests;

const MASTER: [u8; 16] = [9; 16];
const TOKEN: &str = "FCCyf3QV62uAsbARFKbVd8zWyqOQXPFgEL9i";
const SLOT: &str = "https://upload.mega.nz/native-peer-upload/tree";

fn scratch() -> tempfile::TempDir {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/upload-tree-peers");
    std::fs::create_dir_all(&base).unwrap();
    tempfile::tempdir_in(base).unwrap()
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
    let commands: Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(commands.as_array().unwrap().len(), 1);
    commands[0].clone()
}

fn response(value: Value) -> Response {
    Response {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: serde_json::to_vec(&json!([value])).unwrap(),
    }
}

fn options(path: &Path) -> Upload {
    Upload {
        paths: vec![path.to_owned()],
        auth: AccountOptions {
            account: None,
            vault_passphrase: None,
            mfa_code: None,
        },
        workers: Some(1),
        limit: None,
        rename: None,
        target: None,
        keep_structure: true,
        keep_going: false,
        auto_account: false,
        parallel: Some(1),
        share: true,
        share_password: None,
        json: true,
    }
}

#[test]
fn retry_reuses_remote_tree_and_file_receipts_without_repeating_successful_shares() {
    let scratch = scratch();
    let source = scratch.path().join("tree with spaces");
    std::fs::create_dir_all(source.join("empty child")).unwrap();
    std::fs::write(source.join("first.bin"), b"first").unwrap();
    std::fs::write(source.join("second.bin"), b"later").unwrap();
    let context = Context::test_context(scratch.path());
    let manifest = upload_tree::walk(&source, &context.control).unwrap();
    let command_line = options(&source);
    let states = scratch.path().join("private states");
    let vault = Vault::new("synthetic tree passphrase");
    let mut nodes = vec![json!({"h":"ROOT0001","t":2})];
    let mut folders = 0usize;
    let mut files = 0usize;
    let mut slots = 0usize;
    let mut shares: HashMap<String, usize> = HashMap::new();
    let (_, calls) = test_peer::with_peer(
        |request| {
            assert_eq!(request.method, "POST");
            if request.path.starts_with("/native-peer-upload/tree/") {
                assert_eq!(request.body.len(), 5);
                return Some(Response {
                    status: 200,
                    headers: vec![],
                    body: TOKEN.as_bytes().to_vec(),
                });
            }
            let value = command(request);
            Some(match value["a"].as_str().unwrap() {
                "f" => response(json!({"f":nodes})),
                "u" => {
                    slots += 1;
                    if slots == 2 {
                        response(json!(-11))
                    } else {
                        response(json!({"p":SLOT}))
                    }
                }
                "p" => {
                    let mut node = value["n"][0].clone();
                    let handle = if node["t"] == 1 {
                        folders += 1;
                        format!("FOLD{folders:04}")
                    } else {
                        files += 1;
                        assert_eq!(node["h"], TOKEN);
                        node["s"] = json!(5);
                        format!("FILE{files:04}")
                    };
                    node["h"] = json!(handle);
                    node["p"] = value["t"].clone();
                    nodes.push(node);
                    response(json!({"f":[{"h":handle}]}))
                }
                "l" => {
                    *shares
                        .entry(value["n"].as_str().unwrap().to_owned())
                        .or_default() += 1;
                    response(json!("AQIDBAUG"))
                }
                _ => panic!("unexpected structured upload API action"),
            })
        },
        |address| {
            let mut cloud = cloud(address);
            for retry in [false, true] {
                let progress = Progress::new(false);
                let item = progress.add("tree", manifest.bytes).unwrap();
                let job = Job {
                    path: source.clone(),
                    size: manifest.bytes,
                    tree: None,
                    item,
                };
                let result = structured(
                    &context,
                    &command_line,
                    &mut cloud,
                    &vault,
                    &job,
                    &manifest,
                    "ROOT0001",
                    1,
                    &states,
                    None,
                    &RateLimiter::new(0.0).unwrap(),
                    &progress,
                );
                if retry {
                    result.unwrap();
                    assert_eq!(progress.snapshot(item).unwrap().status, Status::Complete);
                } else {
                    assert!(matches!(result, Err(Error::Mega { code: -11, .. })));
                    assert_ne!(progress.snapshot(item).unwrap().status, Status::Complete);
                }
            }
        },
    );
    assert_eq!(folders, 2, "root and empty child must be created only once");
    assert_eq!(
        files, 2,
        "the first registered file must be recovered, not reuploaded"
    );
    assert_eq!(
        slots, 3,
        "one failed second-file slot and two successful slots"
    );
    assert_eq!(
        shares,
        HashMap::from([("FILE0001".into(), 1), ("FILE0002".into(), 1)])
    );
    assert_eq!(
        calls
            .iter()
            .filter(|r| r.path.starts_with("/native-peer-upload/tree/"))
            .count(),
        2
    );
}

#[test]
fn actual_structured_upload_registers_empty_and_nonempty_files_with_exact_manifest_and_results() {
    use super::super::auto_account_peer_tests::Capture;
    use crate::crypto::keys;
    use crate::terminal::output::Output;
    use sha2::{Digest, Sha256};
    let scratch = scratch();
    let source = scratch.path().join("tree");
    std::fs::create_dir_all(source.join("sub")).unwrap();
    std::fs::write(source.join("sub/empty.txt"), b"").unwrap();
    std::fs::write(source.join("data.bin"), [1; 1024]).unwrap();
    let mut context = Context::test_context(scratch.path());
    let stdout = Capture::default();
    context.output = Output::with_writers(true, true, stdout.clone(), Capture::default());
    let manifest = upload_tree::walk(&source, &context.control).unwrap();
    let mut files: Vec<_> = manifest
        .entries
        .iter()
        .filter(|e| !e.directory)
        .map(|e| (e.relative.clone(), e.size))
        .collect();
    files.sort();
    assert_eq!(
        files,
        vec![
            ("data.bin".into(), 1024),
            (Path::new("sub").join("empty.txt"), 0)
        ]
    );
    assert_eq!(manifest.bytes, 1024);
    assert_eq!(manifest.skipped, 0);
    let mut options = options(&source);
    options.share = false;
    let vault = Vault::new("synthetic zero-tree passphrase");
    let states = scratch.path().join("private states");
    let mut nodes = vec![json!({"h":"ROOT0001","t":2})];
    let mut sizes = Vec::new();
    let mut bodies = Vec::new();
    let mut names = Vec::new();
    let mut active_size = None;
    let mut folders = 0;
    let mut registered = 0;
    let ((), calls) = test_peer::with_peer(
        |request| {
            if request.path.starts_with("/native-peer-upload/tree/") {
                assert_eq!(request.path, "/native-peer-upload/tree/0");
                assert_eq!(request.body.len() as u64, active_size.take().unwrap());
                bodies.push(request.body.clone());
                return Some(Response {
                    status: 200,
                    headers: vec![],
                    body: TOKEN.as_bytes().to_vec(),
                });
            }
            let value = command(request);
            Some(match value["a"].as_str().unwrap() {
                "f" => response(json!({"f":nodes})),
                "u" => {
                    assert!(active_size.is_none());
                    let size = value["s"].as_u64().unwrap();
                    sizes.push(size);
                    active_size = Some(size);
                    response(json!({"p":SLOT}))
                }
                "p" => {
                    let mut node = value["n"][0].clone();
                    let raw = wire::aes_key_wrap_decrypt(
                        &wire::b64_url_decode(node["k"].as_str().unwrap()).unwrap(),
                        &MASTER,
                    )
                    .unwrap();
                    let (handle, aes_key) = if node["t"] == 1 {
                        folders += 1;
                        assert_eq!(raw.len(), 16);
                        (format!("FOLD{folders:04}"), raw.to_vec())
                    } else {
                        registered += 1;
                        assert_eq!(raw.len(), 32);
                        assert_eq!(node["h"], TOKEN);
                        let key = keys::unpack_file_key(&wire::bytes_to_a32(&raw)).unwrap();
                        let body = bodies.last().unwrap();
                        let plain =
                            wire::ctr_crypt_at_offset(key.aes_key.as_slice(), &key.nonce, 0, body)
                                .unwrap();
                        assert!(plain.is_empty() || plain == vec![1; 1024]);
                        node["s"] = json!(body.len());
                        (format!("FILE{registered:04}"), key.aes_key.to_vec())
                    };
                    let attrs = wire::decrypt_attributes(
                        &wire::b64_url_decode(node["a"].as_str().unwrap()).unwrap(),
                        &aes_key,
                    )
                    .unwrap();
                    let name = attrs["n"].as_str().unwrap();
                    if node["t"] == 0 {
                        assert_eq!(
                            name,
                            if bodies.last().unwrap().is_empty() {
                                "empty.txt"
                            } else {
                                "data.bin"
                            }
                        );
                        assert_eq!(
                            value["t"],
                            if name == "empty.txt" {
                                "FOLD0002"
                            } else {
                                "FOLD0001"
                            }
                        );
                        names.push(name.to_owned());
                    } else {
                        assert_eq!(name, if folders == 1 { "tree" } else { "sub" });
                        assert_eq!(
                            value["t"],
                            if folders == 1 { "ROOT0001" } else { "FOLD0001" }
                        );
                    }
                    node["h"] = json!(handle);
                    node["p"] = value["t"].clone();
                    nodes.push(node);
                    response(json!({"f":[{"h":handle}]}))
                }
                _ => panic!("empty-file tree emitted an unexpected action"),
            })
        },
        |address| {
            let mut cloud = cloud(address);
            let mut progress = Progress::new(false);
            let item = progress.add("tree", manifest.bytes).unwrap();
            let job = Job {
                path: source.clone(),
                size: manifest.bytes,
                tree: None,
                item,
            };
            structured(
                &context,
                &options,
                &mut cloud,
                &vault,
                &job,
                &manifest,
                "ROOT0001",
                1,
                &states,
                None,
                &RateLimiter::new(0.0).unwrap(),
                &progress,
            )
            .unwrap();
            let snapshot = progress.snapshot(item).unwrap();
            assert_eq!(
                (snapshot.total, snapshot.completed, snapshot.status),
                (1024, 1024, Status::Complete)
            );
            let totals = progress.totals().unwrap();
            assert_eq!(
                (
                    totals.total,
                    totals.completed,
                    totals.items,
                    totals.finished,
                    totals.failed
                ),
                (1024, 1024, 2, 2, 0)
            );
            assert!(progress.close(true).unwrap());
            assert_eq!(progress.totals().unwrap().status, Status::Complete);
            let mut saved = Vec::new();
            for entry in std::fs::read_dir(&states).unwrap() {
                let path = entry.unwrap().path();
                if path.extension().is_some_and(|e| e == "json")
                    && !path
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with("tree-")
                {
                    let state = States::new(&path).load().unwrap().unwrap();
                    assert!(state.registration_started && state.finalization_completed);
                    assert_eq!(state.completion_token.as_deref(), Some(TOKEN));
                    saved.push(state.size);
                }
            }
            saved.sort();
            assert_eq!(saved, [0, 1024]);
        },
    );
    sizes.sort();
    names.sort();
    assert_eq!(sizes, [0, 1024]);
    assert_eq!(names, ["data.bin", "empty.txt"]);
    assert_eq!((folders, registered, bodies.len()), (2, 2, 2));
    assert_eq!(bodies.iter().filter(|b| b.is_empty()).count(), 1);
    assert_eq!(std::fs::read(source.join("sub/empty.txt")).unwrap(), b"");
    assert_eq!(
        Sha256::digest(std::fs::read(source.join("data.bin")).unwrap()),
        Sha256::digest([1; 1024])
    );
    let bytes = stdout.0.lock().unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    let mut results: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    results.sort_by_key(|r| r["size"].as_u64().unwrap());
    assert_eq!(results.len(), 2);
    for (result, name, size) in [
        (&results[0], "empty.txt", 0),
        (&results[1], "data.bin", 1024),
    ] {
        assert_eq!(result["event"], "result");
        assert_eq!(result["status"], "success");
        assert_eq!(result["name"], name);
        assert_eq!(result["size"], size);
        assert_eq!(result["thumbnail"]["status"], "not_applicable");
    }
    assert!(calls.iter().all(|r| r.method == "POST"));
}

#[test]
fn thumbnail_failure_metadata_preserves_successful_upload_result_and_receipt() {
    let scratch = scratch();
    let source = scratch.path().join("image.png");
    std::fs::write(
        &source,
        include_bytes!("../../tests/fixtures/media/1x1-green.png"),
    )
    .unwrap();
    let mut context = Context::test_context(scratch.path());
    let result_log = scratch.path().join("private result log/upload.jsonl");
    context.config.upload_log_path = Some(result_log.to_str().unwrap().into());
    let mut options = options(&source);
    options.share = false;
    let receipt = scratch.path().join("private receipt/receipt.json");
    let mut state = TransferState::new("upload", "fixture", &receipt, 135, &[1; 16]).unwrap();
    state.completed.insert(0, [2; 16]);
    state.completion_token = Some(TOKEN.into());
    state.registration_started = true;
    state.registered_handle = Some("FILE0001".into());
    let states = States::new(&receipt);
    states.save(&state).unwrap();
    let saved_receipt = std::fs::read(&receipt).unwrap();
    let uploaded = confirmed_receipt(&state, &[1; 24], "image.png", &receipt).unwrap();
    let (_, calls) = test_peer::with_peer(
        |request| {
            let value = command(request);
            assert_eq!(value["a"], "ufa");
            Some(response(json!(-11)))
        },
        |address| {
            let mut cloud = cloud(address);
            finalize(&context, &options, &mut cloud, &source, &uploaded, 0.5).unwrap();
        },
    );
    assert_eq!(calls.len(), 1);
    let records = std::fs::read_to_string(result_log).unwrap();
    assert_eq!(records.lines().count(), 1);
    let record: Value = serde_json::from_str(records.trim()).unwrap();
    assert_eq!(record["status"], "success");
    assert_eq!(record["handle"], "FILE0001");
    assert_eq!(record["thumbnail"]["status"], "failed");
    assert_eq!(record["thumbnail"]["error_code"], "mega_error");
    assert!(
        record["thumbnail"]["warning"]
            .as_str()
            .unwrap()
            .contains("Access denied")
    );
    assert_eq!(uploaded.handle, "FILE0001");
    let completed = states.load().unwrap().unwrap();
    assert_eq!(completed.registered_handle.as_deref(), Some("FILE0001"));
    assert!(completed.finalization_started && completed.finalization_completed);
    assert_ne!(
        std::fs::read(&receipt).unwrap(),
        saved_receipt,
        "only finalization markers should advance"
    );
    let mut original: Value = serde_json::from_slice(&saved_receipt).unwrap();
    original["data"]["finalization_started"] = json!(true);
    original["data"]["finalization_completed"] = json!(true);
    original["data"]["revision"] = json!(2);
    let after: Value = serde_json::from_slice(&std::fs::read(&receipt).unwrap()).unwrap();
    assert_eq!(
        after, original,
        "keys, coverage and registration receipt must be preserved"
    );
}

#[test]
fn read_only_folder_preparation_failure_does_not_create_an_unknown_mutation_intent() {
    let scratch = scratch();
    let source = scratch.path().join("source");
    std::fs::create_dir(&source).unwrap();
    let context = Context::test_context(scratch.path());
    let manifest = upload_tree::walk(&source, &context.control).unwrap();
    let states = scratch.path().join("states");
    let mut journal = Journal::open(&states, &source, "binding", None, &manifest).unwrap();
    let mut listings = 0usize;
    let mut registrations = 0usize;
    let (_, calls) = test_peer::with_peer(
        |request| {
            let value = command(request);
            Some(match value["a"].as_str().unwrap() {
                "f" => {
                    listings += 1;
                    if listings == 1 {
                        response(json!(-11))
                    } else {
                        response(json!({"f":[{"h":"ROOT0001","t":2}]}))
                    }
                }
                "p" => {
                    registrations += 1;
                    let key = wire::b64_url_decode(value["n"][0]["k"].as_str().unwrap()).unwrap();
                    assert_eq!(wire::aes_key_wrap_decrypt(&key, &MASTER).unwrap().len(), 16);
                    response(json!({"f":[{"h":"FOLD0001"}]}))
                }
                _ => panic!("unexpected preparation action"),
            })
        },
        |address| {
            let mut cloud = cloud(address);
            assert!(matches!(
                tree_folder(
                    &mut journal,
                    &mut cloud,
                    Path::new(""),
                    "source",
                    "ROOT0001"
                ),
                Err(Error::Mega { code: -11, .. })
            ));
            assert_eq!(journal.folder_handle(Path::new("")).unwrap(), None);
            assert_eq!(
                tree_folder(
                    &mut journal,
                    &mut cloud,
                    Path::new(""),
                    "source",
                    "ROOT0001"
                )
                .unwrap(),
                "FOLD0001"
            );
            journal.acknowledge().unwrap();
        },
    );
    assert_eq!(listings, 2);
    assert_eq!(registrations, 1);
    assert_eq!(calls.len(), 3);
}
