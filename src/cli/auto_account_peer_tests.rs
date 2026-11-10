//! Automatic account eligibility through the actual parsed upload and encrypted session stores.
#![allow(clippy::unwrap_used)]

use std::{
    io::{self, Write},
    path::Path,
    sync::{Arc, Mutex},
};

use clap::Parser;
use serde_json::{Value, json};

use super::{args::Cli, context::Context, dispatch};
use crate::{
    crypto::{keys, wire},
    protocol::{
        api::Api,
        auth::Session,
        test_peer::{self, Response},
    },
    storage::{sessions::Sessions, vault::Vault},
    terminal::output::Output,
};

const A: &str = "a@example.invalid";
const B: &str = "b@example.invalid";
const MASTER: [u8; 16] = [9; 16];
const TOKEN: &str = "FCCyf3QV62uAsbARFKbVd8zWyqOQXPFgEL9i";

#[path = "auto_account_quota_tests.rs"]
mod quota_tests;

#[derive(Clone, Default)]
pub(super) struct Capture(pub(super) Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut output = self.0.lock().unwrap();
        if bytes.len() > (16 * 1024usize).saturating_sub(output.len()) {
            return Err(io::Error::other(
                "Automatic account fixture capture exceeded its limit",
            ));
        }
        output.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn response(value: Value) -> Response {
    Response {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: serde_json::to_vec(&json!([value])).unwrap(),
    }
}

#[test]
fn parsed_automatic_structured_failure_keeps_successful_nodes_on_one_account_without_distribution()
{
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/auto-account-tree");
    std::fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    let source = scratch.path().join("tree");
    std::fs::create_dir_all(source.join("sub")).unwrap();
    std::fs::write(source.join("a.bin"), b"data").unwrap();
    std::fs::write(source.join("sub/x.bin"), [b'x'; 10]).unwrap();
    seed_accounts(
        scratch.path(),
        &[
            (A, "session-a", 10u64 * 1024 * 1024 * 1024),
            (B, "session-b", 5u64 * 1024 * 1024 * 1024),
        ],
    );
    let stdout = Capture::default();
    let stderr = Capture::default();
    let mut nodes = vec![json!({"h":"ROOT0001","t":2})];
    let mut folders = Vec::new();
    let mut sizes = Vec::new();
    let mut body = Vec::new();
    let (code, calls) = test_peer::with_peer(
        |request| {
            assert_eq!(request.method, "POST");
            if request.path.starts_with("/native-peer-upload/tree-auto/") {
                assert_eq!(request.body.len(), 4);
                assert!(body.is_empty());
                body = request.body.clone();
                return Some(Response {
                    status: 200,
                    headers: vec![],
                    body: TOKEN.as_bytes().to_vec(),
                });
            }
            let commands: Value = serde_json::from_slice(&request.body).unwrap();
            assert_eq!(commands.as_array().unwrap().len(), 1);
            let command = &commands[0];
            let url = url::Url::parse(&format!("https://testserver.com{}", request.path)).unwrap();
            let sid = url
                .query_pairs()
                .find(|(key, _)| key == "sid")
                .unwrap()
                .1
                .into_owned();
            if command["a"] == "ug" {
                assert!(matches!(sid.as_str(), "session-a" | "session-b"));
                return Some(response(json!({"u":"testuser"})));
            }
            assert_eq!(sid, "session-a", "A partial tree must never move to B");
            Some(match command["a"].as_str().unwrap() {
                "f" => response(json!({"f":nodes})),
                "u" => {
                    let size = command["s"].as_u64().unwrap();
                    sizes.push(size);
                    if size == 4 {
                        response(json!({"p":"https://upload.mega.nz/native-peer-upload/tree-auto"}))
                    } else {
                        assert_eq!(size, 10);
                        response(json!(-24))
                    }
                }
                "p" => {
                    let mut node = command["n"][0].clone();
                    let raw = wire::aes_key_wrap_decrypt(
                        &wire::b64_url_decode(node["k"].as_str().unwrap()).unwrap(),
                        &MASTER,
                    )
                    .unwrap();
                    let (handle, attrs) = if node["t"] == 1 {
                        let attrs = wire::decrypt_attributes(
                            &wire::b64_url_decode(node["a"].as_str().unwrap()).unwrap(),
                            &raw,
                        )
                        .unwrap();
                        let name = attrs["n"].as_str().unwrap().to_owned();
                        assert_eq!(
                            command["t"],
                            if name == "tree" {
                                "ROOT0001"
                            } else {
                                assert_eq!(name, "sub");
                                "FOLD0001"
                            }
                        );
                        folders.push(name);
                        (format!("FOLD{:04}", folders.len()), attrs)
                    } else {
                        assert_eq!(node["h"], TOKEN);
                        assert_eq!(command["t"], "FOLD0001");
                        let key = keys::unpack_file_key(&wire::bytes_to_a32(&raw)).unwrap();
                        assert_eq!(
                            wire::ctr_crypt_at_offset(key.aes_key.as_slice(), &key.nonce, 0, &body)
                                .unwrap(),
                            b"data"
                        );
                        let attrs = wire::decrypt_attributes(
                            &wire::b64_url_decode(node["a"].as_str().unwrap()).unwrap(),
                            key.aes_key.as_slice(),
                        )
                        .unwrap();
                        assert_eq!(attrs["n"], "a.bin");
                        node["s"] = json!(4);
                        ("FILE0001".to_owned(), attrs)
                    };
                    assert!(attrs["n"].is_string());
                    node["h"] = json!(handle);
                    node["p"] = command["t"].clone();
                    nodes.push(node);
                    response(json!({"f":[{"h":handle}]}))
                }
                "uq" => {
                    response(json!({"mstrg":10u64*1024*1024*1024,"cstrg":10u64*1024*1024*1024}))
                }
                _ => panic!("Unexpected structured automatic-account action"),
            })
        },
        |address| {
            let mut context = Context::test_peer(
                scratch.path(),
                Api::test_peer(address).unwrap(),
                Output::with_writers(true, true, stdout.clone(), stderr.clone()),
            );
            let args: Vec<std::ffi::OsString> = vec![
                "mb".into(),
                "-q".into(),
                "upload".into(),
                source.clone().into_os_string(),
                "--auto-account".into(),
                "--keep-structure".into(),
                "--json".into(),
                "-w".into(),
                "1".into(),
                "--vault-passphrase".into(),
                "synthetic vault passphrase".into(),
            ];
            let command = Cli::try_parse_from(args).unwrap().command.unwrap();
            let code = dispatch(&mut context, command).unwrap();
            let state_directory = context.paths.user.join("Data/transfers/upload");
            let journal = std::fs::read_dir(&state_directory)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .find(|path| {
                    path.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with("tree-")
                        && path.extension().is_some_and(|e| e == "json")
                })
                .unwrap();
            let saved: Value = serde_json::from_slice(&std::fs::read(journal).unwrap()).unwrap();
            assert_eq!(saved["data"]["completed"], false);
            assert_eq!(saved["data"]["finalized_files"]["a.bin"], "FILE0001");
            assert_eq!(saved["data"]["folders"][""], "FOLD0001");
            assert_eq!(saved["data"]["folders"]["sub"], "FOLD0002");
            let receipts: Vec<_> = std::fs::read_dir(&state_directory)
                .unwrap()
                .map(|e| e.unwrap().path())
                .filter(|path| {
                    path.extension().is_some_and(|e| e == "json")
                        && !path
                            .file_name()
                            .unwrap()
                            .to_string_lossy()
                            .starts_with("tree-")
                })
                .collect();
            assert_eq!(receipts.len(), 1);
            let receipt = crate::storage::transfer_state::States::new(&receipts[0])
                .load()
                .unwrap()
                .unwrap();
            assert_eq!(receipt.registered_handle.as_deref(), Some("FILE0001"));
            assert!(receipt.finalization_completed);
            code
        },
    );
    assert_eq!(code, 1);
    assert_eq!(folders, vec!["tree", "sub"]);
    assert_eq!(sizes, vec![4, 10]);
    assert_eq!(body.len(), 4);
    assert!(calls.len() < 20);
    let text = String::from_utf8(stdout.0.lock().unwrap().clone()).unwrap();
    let records: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        records.iter().filter(|r| r["status"] == "success").count(),
        1
    );
    assert!(records.iter().any(|r| r["status"] == "failed"));
    assert_eq!(records[0]["handle"], "FILE0001");
    assert_eq!(std::fs::read(source.join("a.bin")).unwrap(), b"data");
    for capture in [&stdout, &stderr] {
        let text = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
        assert!(
            !text.contains("session-a")
                && !text.contains("session-b")
                && !text.contains("synthetic vault passphrase")
        );
    }
}

pub(super) fn seed_accounts(root: &Path, choices: &[(&str, &str, u64)]) {
    let context = Context::test_context(root);
    let vault = Vault::new("synthetic vault passphrase");
    for &(email, sid, total) in choices {
        context
            .accounts()
            .add(email, "synthetic password", None, false, &vault)
            .unwrap();
        context.accounts().quota(email, total, 0).unwrap();
        Sessions::new(context.paths.session(email))
            .remember(
                &Session {
                    sid: sid.into(),
                    master_key: MASTER,
                    rsa_private_key: None,
                    user_handle: "testuser".into(),
                    email: email.into(),
                },
                &vault,
            )
            .unwrap();
    }
}

#[test]
fn parsed_zero_byte_upload_excludes_unavailable_account_even_with_equal_zero_cached_balances() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/auto-account-peers");
    std::fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    let source = scratch.path().join("empty file.bin");
    std::fs::write(&source, b"").unwrap();
    seed_accounts(
        scratch.path(),
        &[(A, "available-session", 0), (B, "unavailable-session", 0)],
    );
    let stdout = Capture::default();
    let stderr = Capture::default();
    let (code, calls) = test_peer::with_peer(
        |request| {
            assert_eq!(request.method, "POST");
            if request.path.starts_with("/native-peer-upload/empty/") {
                assert!(request.body.is_empty());
                return Some(Response {
                    status: 200,
                    headers: vec![],
                    body: TOKEN.as_bytes().to_vec(),
                });
            }
            let commands: Value = serde_json::from_slice(&request.body).unwrap();
            assert_eq!(commands.as_array().unwrap().len(), 1);
            let command = &commands[0];
            let url = url::Url::parse(&format!("https://testserver.com{}", request.path)).unwrap();
            let sid = url
                .query_pairs()
                .find(|(key, _)| key == "sid")
                .unwrap()
                .1
                .into_owned();
            if command["a"] == "ug" {
                return Some(response(if sid == "unavailable-session" {
                    json!(-11)
                } else {
                    assert_eq!(sid, "available-session");
                    json!({"u":"testuser"})
                }));
            }
            assert_eq!(
                sid, "available-session",
                "Unavailable B must never start a transfer"
            );
            Some(match command["a"].as_str().unwrap() {
                "f" => response(json!({"f":[{"h":"ROOT0001","t":2}]})),
                "u" => {
                    assert_eq!(command["s"], 0);
                    response(json!({"p":"https://upload.mega.nz/native-peer-upload/empty"}))
                }
                "p" => {
                    assert_eq!(command["t"], "ROOT0001");
                    assert_eq!(command["n"].as_array().unwrap().len(), 1);
                    let node = &command["n"][0];
                    assert_eq!(node["h"], TOKEN);
                    assert_eq!(node["t"], 0);
                    let raw = wire::aes_key_wrap_decrypt(
                        &wire::b64_url_decode(node["k"].as_str().unwrap()).unwrap(),
                        &MASTER,
                    )
                    .unwrap();
                    let key = keys::unpack_file_key(&wire::bytes_to_a32(&raw)).unwrap();
                    assert_eq!(key.mac, [0u32; 2]);
                    let attrs = wire::decrypt_attributes(
                        &wire::b64_url_decode(node["a"].as_str().unwrap()).unwrap(),
                        key.aes_key.as_slice(),
                    )
                    .unwrap();
                    assert_eq!(attrs["n"], "empty file.bin");
                    response(json!({"f":[{"h":"FILE0001"}]}))
                }
                _ => panic!(
                    "Unexpected auto-account API action; no login, MFA, refresh or logout is expected"
                ),
            })
        },
        |address| {
            let mut context = Context::test_peer(
                scratch.path(),
                Api::test_peer(address).unwrap(),
                Output::with_writers(true, true, stdout.clone(), stderr.clone()),
            );
            let retained_b = std::fs::read(context.paths.session(B)).unwrap();
            let args: Vec<std::ffi::OsString> = vec![
                "mb".into(),
                "-q".into(),
                "upload".into(),
                source.clone().into_os_string(),
                "--auto-account".into(),
                "--json".into(),
                "-w".into(),
                "1".into(),
                "-P".into(),
                "1".into(),
                "--vault-passphrase".into(),
                "synthetic vault passphrase".into(),
            ];
            let command = Cli::try_parse_from(args).unwrap().command.unwrap();
            let result = dispatch(&mut context, command).unwrap();
            assert_eq!(std::fs::read(context.paths.session(B)).unwrap(), retained_b);
            assert_eq!(context.accounts().list().unwrap().accounts.len(), 2);
            result
        },
    );
    assert_eq!(code, 0);
    assert_eq!(
        calls.len(),
        6,
        "Two session probes and one listing/slot/body/registration"
    );
    let text = String::from_utf8(stdout.0.lock().unwrap().clone()).unwrap();
    let records: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["event"], "result");
    assert_eq!(records[0]["status"], "success");
    assert_eq!(records[0]["size"], 0);
    assert_eq!(records[0]["handle"], "FILE0001");
    assert_eq!(std::fs::metadata(source).unwrap().len(), 0);
    let diagnostic = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
    for output in [&text, &diagnostic] {
        assert!(!output.contains("synthetic password"));
        assert!(!output.contains("available-session"));
        assert!(!output.contains("synthetic vault passphrase"));
    }
}

#[test]
fn parsed_auto_account_retries_same_file_avoids_exhausted_accounts_and_bounds_all_full_failure() {
    for (quota_code, all_full, refresh_refused) in [
        (-17, false, false),
        (-24, false, false),
        (-17, true, false),
        (-24, false, true),
    ] {
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/auto-account-replan");
        std::fs::create_dir_all(&base).unwrap();
        let scratch = tempfile::tempdir_in(base).unwrap();
        let first = scratch.path().join("f1.bin");
        let second = scratch.path().join("f2.bin");
        std::fs::write(&first, b"data").unwrap();
        std::fs::write(&second, b"data").unwrap();
        seed_accounts(
            scratch.path(),
            &[
                (A, "session-a", 10u64 * 1024 * 1024 * 1024),
                (B, "session-b", 5u64 * 1024 * 1024 * 1024),
            ],
        );
        let stdout = Capture::default();
        let stderr = Capture::default();
        let mut attempted = Vec::new();
        let mut bodies = Vec::new();
        let mut names = Vec::new();
        let (code, calls) = test_peer::with_peer(
            |request| {
                assert_eq!(request.method, "POST");
                if request.path.starts_with("/native-peer-upload/replan/") {
                    assert!(!all_full, "A rejected upload must never send content");
                    assert_eq!(request.body.len(), 4);
                    bodies.push(request.body.clone());
                    return Some(Response {
                        status: 200,
                        headers: vec![],
                        body: TOKEN.as_bytes().to_vec(),
                    });
                }
                let commands: Value = serde_json::from_slice(&request.body).unwrap();
                assert_eq!(commands.as_array().unwrap().len(), 1);
                let command = &commands[0];
                let url =
                    url::Url::parse(&format!("https://testserver.com{}", request.path)).unwrap();
                let sid = url
                    .query_pairs()
                    .find(|(key, _)| key == "sid")
                    .unwrap()
                    .1
                    .into_owned();
                assert!(matches!(sid.as_str(), "session-a" | "session-b"));
                Some(match command["a"].as_str().unwrap() {
                    "ug" => response(json!({"u":"testuser"})),
                    "f" => response(json!({"f":[{"h":"ROOT0001","t":2}]})),
                    "u" => {
                        assert_eq!(command["s"], 4);
                        attempted.push(sid.clone());
                        if sid == "session-a" || all_full {
                            response(json!(quota_code))
                        } else {
                            response(
                                json!({"p":"https://upload.mega.nz/native-peer-upload/replan"}),
                            )
                        }
                    }
                    "uq" => {
                        assert_eq!(command, &json!({"a":"uq","strg":1,"xfer":1}));
                        assert!(sid == "session-a" || all_full);
                        if refresh_refused {
                            response(json!(-11))
                        } else {
                            response(
                                json!({"mstrg":10u64*1024*1024*1024,"cstrg":10u64*1024*1024*1024}),
                            )
                        }
                    }
                    "p" => {
                        assert!(!all_full);
                        assert_eq!(sid, "session-b");
                        assert_eq!(command["t"], "ROOT0001");
                        assert_eq!(command["n"].as_array().unwrap().len(), 1);
                        let node = &command["n"][0];
                        assert_eq!(node["h"], TOKEN);
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
                        names.push(attrs["n"].as_str().unwrap().to_owned());
                        assert_eq!(bodies.len(), names.len());
                        let plaintext = wire::ctr_crypt_at_offset(
                            key.aes_key.as_slice(),
                            &key.nonce,
                            0,
                            bodies.last().unwrap(),
                        )
                        .unwrap();
                        assert_eq!(plaintext, b"data");
                        let chunk = crate::crypto::chunks::chunk_mac(
                            b"data",
                            key.aes_key.as_slice(),
                            &key.nonce,
                        )
                        .unwrap();
                        let full = crate::crypto::chunks::combine_chunk_macs(
                            &[chunk],
                            key.aes_key.as_slice(),
                        )
                        .unwrap();
                        assert_eq!(key.mac, crate::crypto::chunks::condense_mac(&full).unwrap());
                        response(json!({"f":[{"h":format!("FILE{:04}",names.len())}]}))
                    }
                    _ => panic!(
                        "Replan must not repeat login/MFA, export, logout or unrelated actions"
                    ),
                })
            },
            |address| {
                let mut context = Context::test_peer(
                    scratch.path(),
                    Api::test_peer(address).unwrap(),
                    Output::with_writers(true, true, stdout.clone(), stderr.clone()),
                );
                let mut args: Vec<std::ffi::OsString> = vec![
                    "mb".into(),
                    "-q".into(),
                    "upload".into(),
                    first.clone().into_os_string(),
                ];
                if !all_full {
                    args.push(second.clone().into_os_string());
                }
                args.extend([
                    "--auto-account".into(),
                    "--json".into(),
                    "-w".into(),
                    "1".into(),
                    "-P".into(),
                    "1".into(),
                    "--vault-passphrase".into(),
                    "synthetic vault passphrase".into(),
                ]);
                let command = Cli::try_parse_from(args).unwrap().command.unwrap();
                let code = dispatch(&mut context, command).unwrap();
                if !refresh_refused {
                    let account = context.accounts().find(Some(A)).unwrap();
                    assert_eq!(account.quota_total, account.quota_used);
                }
                code
            },
        );
        assert_eq!(code, i32::from(all_full));
        assert_eq!(
            attempted,
            if all_full {
                vec!["session-a", "session-b"]
            } else {
                vec!["session-a", "session-b", "session-b"]
            }
        );
        assert_eq!(
            names,
            if all_full {
                Vec::<String>::new()
            } else {
                vec!["f1.bin".to_owned(), "f2.bin".to_owned()]
            }
        );
        let actions: Vec<_> = calls
            .iter()
            .filter(|r| r.path.starts_with("/cs?"))
            .map(|r| {
                serde_json::from_slice::<Value>(&r.body).unwrap()[0]["a"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        assert_eq!(actions.iter().filter(|a| a.as_str() == "ug").count(), 2);
        assert_eq!(
            actions.iter().filter(|a| a.as_str() == "uq").count(),
            if all_full { 2 } else { 1 }
        );
        assert_eq!(bodies.len(), if all_full { 0 } else { 2 });
        let text = String::from_utf8(stdout.0.lock().unwrap().clone()).unwrap();
        let records: Vec<Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(records.len(), if all_full { 1 } else { 2 });
        for record in records {
            assert_eq!(record["event"], "result");
            assert_eq!(
                record["status"],
                if all_full { "failed" } else { "success" }
            );
            if !all_full {
                assert_eq!(record["size"], 4);
            }
        }
        for capture in [&stdout, &stderr] {
            let text = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
            for secret in [
                "session-a",
                "session-b",
                "synthetic vault passphrase",
                "synthetic password",
            ] {
                assert!(!text.contains(secret));
            }
        }
        assert_eq!(std::fs::read(first).unwrap(), b"data");
        assert_eq!(std::fs::read(second).unwrap(), b"data");
    }
}
