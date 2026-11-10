//! Actual upload elapsed includes an expired slot, its retry, and registration response time.
#![allow(clippy::unwrap_used)]

use std::{collections::BTreeMap, time::Instant};

use super::*;
use crate::cli::auto_account_peer_tests::Capture;
use crate::terminal::output::Output;
use crate::transfers::control::Control;

#[test]
fn upload_result_elapsed_includes_expired_slot_retry_and_remote_registration() {
    let scratch = scratch();
    let source = scratch.path().join("timed upload.bin");
    std::fs::write(&source, [1; 1024]).unwrap();
    let stdout = Capture::default();
    let mut context = Context::test_context(scratch.path());
    context.output = Output::with_writers(true, true, stdout.clone(), Capture::default());
    let mut options = options(&source);
    options.keep_structure = false;
    options.share = false;
    let vault = Vault::new("synthetic timing passphrase");
    let states = scratch.path().join("private timed state");
    let mut progress = Progress::new(false);
    let item = progress.add("timed upload.bin", 1024).unwrap();
    let job = Job {
        path: source.clone(),
        size: 1024,
        tree: None,
        item,
    };
    let mut slots = 0;
    let mut bodies = Vec::new();
    let mut registrations = 0;
    let (wall, calls) = test_peer::with_peer(
        |request| {
            assert_eq!(request.method, "POST");
            if request.path.starts_with("/native-peer-upload/tree/") {
                assert_eq!(request.path, "/native-peer-upload/tree/0");
                assert_eq!(request.body.len(), 1024);
                bodies.push(request.body.clone());
                return Some(Response {
                    status: if bodies.len() == 1 { 403 } else { 200 },
                    headers: vec![],
                    body: if bodies.len() == 1 {
                        vec![]
                    } else {
                        TOKEN.as_bytes().to_vec()
                    },
                });
            }
            let value = command(request);
            Some(match value["a"].as_str().unwrap() {
                "f" => response(json!({"f":[{"h":"ROOT0001","t":2}]})),
                "u" => {
                    slots += 1;
                    assert!(slots <= 2);
                    assert_eq!(value["s"], 1024);
                    response(json!({"p":SLOT}))
                }
                "p" => {
                    registrations += 1;
                    assert_eq!((slots, bodies.len(), registrations), (2, 2, 1));
                    assert_eq!(
                        bodies[0], bodies[1],
                        "slot refresh changed upload key or plaintext"
                    );
                    assert_eq!(value["t"], "ROOT0001");
                    let node = &value["n"][0];
                    assert_eq!(node["h"], TOKEN);
                    let raw = wire::aes_key_wrap_decrypt(
                        &wire::b64_url_decode(node["k"].as_str().unwrap()).unwrap(),
                        &MASTER,
                    )
                    .unwrap();
                    let key =
                        crate::crypto::keys::unpack_file_key(&wire::bytes_to_a32(&raw)).unwrap();
                    let plain = wire::ctr_crypt_at_offset(
                        key.aes_key.as_slice(),
                        &key.nonce,
                        0,
                        &bodies[1],
                    )
                    .unwrap();
                    assert_eq!(plain, [1; 1024]);
                    let attrs = wire::decrypt_attributes(
                        &wire::b64_url_decode(node["a"].as_str().unwrap()).unwrap(),
                        key.aes_key.as_slice(),
                    )
                    .unwrap();
                    assert_eq!(attrs["n"], "timed upload.bin");
                    assert_eq!(progress.snapshot(item).unwrap().completed, 1024);
                    // Model external registration latency with the existing cancellable timer.
                    RateLimiter::new(4.0 / 1024.0)
                        .unwrap()
                        .acquire(1, &Control::new())
                        .unwrap();
                    response(json!({"f":[{"h":"FILE0001"}]}))
                }
                _ => panic!("unexpected timed-upload API action"),
            })
        },
        |address| {
            let clients = BTreeMap::from([("fixture@example.invalid".into(), cloud(address))]);
            // Two real 1024-byte attempts at5KiB/s reserve at least400ms in total.
            let limiter = RateLimiter::new(5.0).unwrap();
            let start = Instant::now();
            super::super::run_one(
                &context,
                &options,
                &clients,
                None,
                Some("fixture@example.invalid"),
                &vault,
                &job,
                None,
                1,
                &states,
                None,
                &limiter,
                &progress,
            )
            .unwrap();
            start.elapsed().as_secs_f64()
        },
    );
    assert_eq!(
        (slots, bodies.len(), registrations, calls.len()),
        (2, 2, 1, 6)
    );
    let text = String::from_utf8(stdout.0.lock().unwrap().clone()).unwrap();
    let records: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records.len(), 1);
    let result = &records[0];
    assert_eq!(result["event"], "result");
    assert_eq!(result["type"], "upload");
    assert_eq!(result["status"], "success");
    assert_eq!(result["size"], 1024);
    assert_eq!(result["handle"], "FILE0001");
    let elapsed = result["elapsed_seconds"].as_f64().unwrap();
    assert!(
        elapsed.is_finite() && elapsed >= 0.64,
        "missing retry or registration time: {elapsed}"
    );
    assert!(
        (elapsed - wall).abs() < 2.0,
        "elapsed={elapsed}, wall={wall}"
    );
    assert_eq!(progress.snapshot(item).unwrap().status, Status::Complete);
    assert!(progress.close(true).unwrap());
    assert_eq!(std::fs::read(&source).unwrap(), [1; 1024]);
    assert!(std::fs::read_dir(&states).unwrap().all(|entry| {
        entry
            .unwrap()
            .path()
            .extension()
            .is_none_or(|ext| ext != "json")
    }));
}
