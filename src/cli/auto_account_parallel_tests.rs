//! Actual concurrent automatic-account transfers, observed at the owned TLS boundary.
#![allow(clippy::unwrap_used)]

use clap::Parser;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::{Condvar, Mutex, mpsc},
    time::Duration,
};

use super::{
    args::Cli,
    auto_account_peer_tests::{Capture, seed_accounts},
    context::Context,
    dispatch,
};
use crate::{
    crypto::{keys, wire},
    protocol::{
        api::Api,
        test_peer::{self, Response},
    },
    terminal::output::Output,
    transfers::control::observe_limiters,
};

const MASTER: [u8; 16] = [9; 16];
const TOKEN: &str = "FCCyf3QV62uAsbARFKbVd8zWyqOQXPFgEL9i";

fn response(value: Value) -> Response {
    Response {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: serde_json::to_vec(&json!([value])).unwrap(),
    }
}

#[test]
fn parsed_parallel_auto_account_overlaps_transfers_isolates_sequences_and_reuses_authentication() {
    for quota_code in [None, Some(-17), Some(-24)] {
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/auto-account-parallel");
        std::fs::create_dir_all(&base).unwrap();
        let scratch = crate::test_support::tempdir_in(base).unwrap();
        seed_accounts(
            scratch.path(),
            &[
                ("a@example.invalid", "session-a", 128),
                ("b@example.invalid", "session-b", 128),
            ],
        );
        let files = if quota_code.is_some() { 3 } else { 6 };
        let mut paths = Vec::new();
        for index in 0..files {
            let path = scratch.path().join(format!("f{index}.bin"));
            std::fs::write(&path, [index as u8; 4]).unwrap();
            paths.push(path);
        }
        let stdout = Capture::default();
        let stderr = Capture::default();
        let arrivals = (Mutex::new(0usize), Condvar::new());
        let slots = Mutex::new(0usize);
        let attempts = Mutex::new(Vec::new());
        let rejected = Mutex::new(0usize);
        let bodies = Mutex::new(Vec::<Vec<u8>>::new());
        let registered = Mutex::new(BTreeMap::<String, Vec<u8>>::new());
        let (acquired, acquisitions) = mpsc::sync_channel(6);
        let (closed, closure) = mpsc::sync_channel(32);
        let (code, calls) = test_peer::with_raw_parallel_peer(
            |request, stream| {
                let mut send = |response| {
                    test_peer::respond(stream, response, true);
                    super::client_lifecycle_peer_tests::observe_close(stream);
                    closed.try_send(()).unwrap();
                };
                assert_eq!(request.method, "POST");
                if request.path.starts_with("/native-peer-upload/parallel/") {
                    assert_eq!(request.body.len(), 4);
                    bodies.lock().unwrap().push(request.body.clone());
                    return send(Response {
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
                let query: BTreeMap<_, _> = url
                    .query_pairs()
                    .map(|(k, v)| (k.into_owned(), v.into_owned()))
                    .collect();
                assert!(matches!(query["sid"].as_str(), "session-a" | "session-b"));
                send(match command["a"].as_str().unwrap() {
                    "ug" => {
                        assert_eq!(query["id"], "1");
                        response(json!({"u":"testuser"}))
                    }
                    "f" => {
                        assert_eq!(query["id"], "1");
                        response(json!({"f":[{"h":"ROOT0001","t":2}]}))
                    }
                    "u" => {
                        // Every per-transfer Api::fork starts its own f1/u2 sequence; a shared client drifts.
                        assert_eq!(query["id"], "2");
                        assert_eq!(command["s"], 4);
                        let number = {
                            let mut slots = slots.lock().unwrap();
                            *slots += 1;
                            *slots
                        };
                        let mut count = arrivals.0.lock().unwrap();
                        *count += 1;
                        arrivals.1.notify_all();
                        if *count < 2 {
                            let (ready, _) = arrivals
                                .1
                                .wait_timeout_while(count, Duration::from_secs(2), |count| {
                                    *count < 2
                                })
                                .unwrap();
                            assert!(
                                *ready >= 2,
                                "Parallel workers never reached two upload slots together"
                            );
                        }
                        attempts.lock().unwrap().push(query["sid"].clone());
                        if let Some(code) = quota_code.filter(|_| query["sid"] == "session-a") {
                            *rejected.lock().unwrap() += 1;
                            response(json!(code))
                        } else {
                            response(
                                json!({"p":format!("https://upload.mega.nz/native-peer-upload/parallel/{number}")}),
                            )
                        }
                    }
                    "uq" => {
                        assert!(quota_code.is_some());
                        assert_eq!(query["sid"], "session-a");
                        assert_eq!(query["id"], "3");
                        response(json!({"mstrg":128,"cstrg":128}))
                    }
                    "p" => {
                        if quota_code.is_some() {
                            assert_eq!(query["sid"], "session-b");
                        }
                        assert_eq!(query["id"], "3");
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
                        let name = attrs["n"].as_str().unwrap();
                        let index = name
                            .strip_prefix('f')
                            .unwrap()
                            .strip_suffix(".bin")
                            .unwrap()
                            .parse::<u8>()
                            .unwrap();
                        let expected = vec![index; 4];
                        let matches = bodies
                            .lock()
                            .unwrap()
                            .iter()
                            .filter(|bytes| {
                                wire::ctr_crypt_at_offset(
                                    key.aes_key.as_slice(),
                                    &key.nonce,
                                    0,
                                    bytes,
                                )
                                .unwrap()
                                    == expected
                            })
                            .count();
                        assert_eq!(
                            matches, 1,
                            "Registered key does not identify exactly one real body"
                        );
                        assert!(
                            registered
                                .lock()
                                .unwrap()
                                .insert(name.to_owned(), expected)
                                .is_none()
                        );
                        response(json!({"f":[{"h":format!("FILE{index:04}")}]}))
                    }
                    _ => panic!(
                        "Parallel transfer unexpectedly repeated authentication/MFA/logout/quota mutation"
                    ),
                })
            },
            |address| {
                let mut context = Context::test_peer(
                    scratch.path(),
                    Api::test_peer(address).unwrap(),
                    Output::with_writers(true, true, stdout.clone(), stderr.clone()),
                );
                let saved: Vec<_> = ["a@example.invalid", "b@example.invalid"]
                    .iter()
                    .map(|email| {
                        (
                            context.paths.session(email),
                            std::fs::read(context.paths.session(email)).unwrap(),
                        )
                    })
                    .collect();
                let mut args: Vec<std::ffi::OsString> =
                    vec!["mb".into(), "-q".into(), "upload".into()];
                args.extend(paths.iter().cloned().map(|p| p.into_os_string()));
                args.extend([
                    "--auto-account".into(),
                    "--json".into(),
                    "-w".into(),
                    "1".into(),
                    "-P".into(),
                    "2".into(),
                    "--limit".into(),
                    "1024".into(),
                    "--vault-passphrase".into(),
                    "synthetic vault passphrase".into(),
                ]);
                let command = Cli::try_parse_from(args).unwrap().command.unwrap();
                let result =
                    observe_limiters(acquired, || dispatch(&mut context, command)).unwrap();
                let expected = 2 + files * 4 + *rejected.lock().unwrap() * 3;
                for _ in 0..expected {
                    closure.recv_timeout(Duration::from_secs(2)).unwrap();
                }
                assert!(closure.try_recv().is_err());
                for (path, bytes) in saved {
                    assert_eq!(std::fs::read(path).unwrap(), bytes);
                }
                result
            },
        );
        assert_eq!(code, 0);
        let acquired: Vec<_> = acquisitions.try_iter().collect();
        assert_eq!(acquired.len(), files);
        assert!(
            acquired
                .iter()
                .all(|&(id, bytes)| id == acquired[0].0 && bytes == 4)
        );
        let rejects = *rejected.lock().unwrap();
        assert_eq!(calls.len(), 2 + files * 4 + rejects * 3);
        assert_eq!(*slots.lock().unwrap(), files + rejects);
        assert!(rejects <= files);
        if quota_code.is_some() {
            assert!(
                rejects >= 1,
                "Quota reroute variant never reached account A"
            );
            let attempted = attempts.lock().unwrap();
            assert_eq!(
                attempted
                    .iter()
                    .filter(|sid| sid.as_str() == "session-b")
                    .count(),
                files
            );
        } else {
            assert_eq!(rejects, 0);
        }
        let initial: Vec<_> = calls
            .iter()
            .filter(|r| r.path.starts_with("/cs?"))
            .filter(|r| serde_json::from_slice::<Value>(&r.body).unwrap()[0]["a"] == "ug")
            .collect();
        assert_eq!(initial.len(), 2);
        let probed: BTreeSet<_> = initial
            .iter()
            .map(|request| {
                url::Url::parse(&format!("https://testserver.com{}", request.path))
                    .unwrap()
                    .query_pairs()
                    .find(|(key, _)| key == "sid")
                    .unwrap()
                    .1
                    .into_owned()
            })
            .collect();
        assert_eq!(
            probed,
            BTreeSet::from(["session-a".to_owned(), "session-b".to_owned()])
        );
        let names: BTreeSet<_> = registered.lock().unwrap().keys().cloned().collect();
        assert_eq!(
            names,
            (0..files)
                .map(|i| format!("f{i}.bin"))
                .collect::<BTreeSet<_>>()
        );
        let text = String::from_utf8(stdout.0.lock().unwrap().clone()).unwrap();
        let records: Vec<Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(records.len(), files);
        assert!(
            records
                .iter()
                .all(|r| r["status"] == "success" && r["size"] == 4)
        );
        for capture in [&stdout, &stderr] {
            let text = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
            for secret in ["session-a", "session-b", "synthetic vault passphrase"] {
                assert!(!text.contains(secret));
            }
        }
    }
}
