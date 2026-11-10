//! Parallel parsed downloads isolate API sequences and close successful and refused TLS responses.
#![allow(clippy::unwrap_used)]

use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
    path::Path,
    sync::{Condvar, Mutex, OnceLock, mpsc},
    time::Duration,
};

use clap::Parser;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{args::Cli, auto_account_peer_tests::Capture, context::Context, dispatch};
use crate::{
    crypto::wire,
    protocol::{api::Api, test_peer},
    terminal::output::Output,
    transfers::control::observe_limiters,
};

const HANDLES: [&str; 2] = ["FILE0001", "FILE0002"];
const SID: &str = "synthetic-download-session";

type Stream = rustls::StreamOwned<rustls::ServerConnection, test_peer::DeadlineSocket>;

fn reply_and_require_eof(
    stream: &mut Stream,
    status: u16,
    headers: &[(&str, &str)],
    body: &[u8],
    unread: bool,
) {
    write!(
        stream,
        "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: keep-alive\r\n",
        if unread { 4096 } else { body.len() }
    )
    .unwrap();
    for (name, value) in headers {
        write!(stream, "{name}: {value}\r\n").unwrap();
    }
    stream.write_all(b"\r\n").unwrap();
    stream.write_all(body).unwrap();
    stream.flush().unwrap();
    match stream.read(&mut [0]) {
        Ok(0) => (),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
            ) =>
        {
            ()
        }
        other => panic!("download response remained open: {other:?}"),
    }
}

fn scenario(folder: bool, sibling_fails: bool) {
    let vectors: Value =
        serde_json::from_str(include_str!("../../tests/fixtures/transfers/vectors.json")).unwrap();
    let vector = &vectors["vectors"][1];
    assert_eq!(vector["size"], 17);
    let raw_key = hex::decode(vector["raw_key"].as_str().unwrap()).unwrap();
    let attribute_key = hex::decode(vector["aes_key"].as_str().unwrap()).unwrap();
    let wrapping_key: Vec<u8> = (0..16).collect();
    let attributes: Vec<_> = ["a.bin", "b.bin"]
        .iter()
        .map(|name| {
            wire::b64_url_encode(
                &wire::encrypt_attributes(&json!({"n":name}), &attribute_key).unwrap(),
            )
        })
        .collect();
    let node_key =
        wire::b64_url_encode(&wire::aes_key_wrap_encrypt(&raw_key, &wrapping_key).unwrap());
    let listing = json!({"f":[
        {"h":"rootAAAA","p":"outsideX","t":1,
         "k":format!("own:{}",wire::b64_url_encode(&wire::aes_key_wrap_encrypt(&wrapping_key, &wrapping_key).unwrap())),
         "a":wire::b64_url_encode(&wire::encrypt_attributes(&json!({"n":"bundle"}), &wrapping_key).unwrap())},
        {"h":HANDLES[0],"p":"rootAAAA","t":0,"s":17,"k":format!("own:{node_key}"),"a":attributes[0]},
        {"h":HANDLES[1],"p":"rootAAAA","t":0,"s":17,"k":format!("own:{node_key}"),"a":attributes[1]}
    ]});
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/download-isolation");
    std::fs::create_dir_all(&root).unwrap();
    let scratch = tempfile::tempdir_in(root).unwrap();
    let stdout = Capture::default();
    let stderr = Capture::default();
    let cdn = OnceLock::new();
    let tickets = Mutex::new(BTreeMap::<String, usize>::new());
    let arrivals = (Mutex::new(BTreeSet::new()), Condvar::new());
    let (closed, closure) = mpsc::sync_channel(16);
    let (acquired, acquisitions) = mpsc::sync_channel(2);
    let expected_calls = if folder { 9 } else { 8 };
    let (code, calls) = test_peer::with_raw_parallel_peer(
        |request, stream| {
            assert!(!request.headers.contains_key("authorization"));
            assert!(!request.headers.contains_key("proxy-authorization"));
            if request.path.starts_with("/cs?") {
                assert_eq!(request.method, "POST");
                let url =
                    url::Url::parse(&format!("https://testserver.com{}", request.path)).unwrap();
                let query: BTreeMap<_, _> = url.query_pairs().collect();
                assert_eq!(query["sid"], SID);
                assert_eq!(query["ak"], "BdARkQSQ");
                let commands: Value = serde_json::from_slice(&request.body).unwrap();
                assert_eq!(commands.as_array().unwrap().len(), 1);
                let command = &commands[0];
                let response = if command["a"] == "f" {
                    assert!(folder);
                    assert_eq!(query["id"], "1");
                    assert_eq!(query["n"], "SHARE123");
                    assert_eq!(command, &json!({"a":"f","c":1,"r":1,"ca":1}));
                    listing.clone()
                } else {
                    let handle = command[if folder { "n" } else { "p" }].as_str().unwrap();
                    let index = HANDLES.iter().position(|value| *value == handle).unwrap();
                    assert_eq!(
                        command,
                        &json!({"a":"g","g":1,"ssl":2,
                        (if folder {"n"} else {"p"}):handle})
                    );
                    let mut tickets = tickets.lock().unwrap();
                    let count = tickets.entry(handle.to_owned()).or_default();
                    *count += 1;
                    assert!(
                        *count <= 2,
                        "download unexpectedly requested a third ticket"
                    );
                    let sequence = if folder {
                        *count
                    } else if *count == 1 {
                        index + 1
                    } else {
                        1
                    };
                    assert_eq!(query["id"], sequence.to_string());
                    if folder {
                        assert_eq!(query["n"], "SHARE123");
                    } else {
                        assert!(!query.contains_key("n"));
                    }
                    json!({"s":17,"at":attributes[index],
                        "g":format!("{}/cdn/{handle}/{}",cdn.get().unwrap(),
                            if *count == 1 { "initial" } else { "refreshed" })})
                };
                reply_and_require_eof(
                    stream,
                    200,
                    &[("Content-Type", "application/json")],
                    &serde_json::to_vec(&json!([response])).unwrap(),
                    false,
                );
            } else {
                assert_eq!(request.method, "GET");
                assert!(request.body.is_empty());
                assert_eq!(request.headers["range"], "bytes=0-16");
                let parts: Vec<_> = request.path.split('/').collect();
                assert_eq!(parts.len(), 4);
                assert_eq!(parts[1], "cdn");
                assert!(HANDLES.contains(&parts[2]));
                match parts[3] {
                    "initial" => {
                        let mut arrived = arrivals.0.lock().unwrap();
                        assert!(arrived.insert(parts[2].to_owned()));
                        arrivals.1.notify_all();
                        let (arrived, _) = arrivals
                            .1
                            .wait_timeout_while(arrived, Duration::from_secs(2), |arrived| {
                                arrived.len() < 2
                            })
                            .unwrap();
                        assert_eq!(arrived.len(), 2, "downloads never overlapped at the CDN");
                        drop(arrived);
                        reply_and_require_eof(stream, 403, &[], &[], true);
                    }
                    "refreshed" if !sibling_fails || parts[2] == HANDLES[0] => {
                        reply_and_require_eof(
                            stream,
                            206,
                            &[("Content-Range", "bytes 0-16/17")],
                            include_bytes!("../../tests/fixtures/transfers/ciphertext-17.bin"),
                            false,
                        )
                    }
                    "refreshed" => reply_and_require_eof(stream, 400, &[], &[], true),
                    _ => panic!("unexpected CDN ticket path"),
                }
            }
            closed.try_send(()).unwrap();
        },
        |address| {
            cdn.set(format!("https://testserver.com:{}", address.port()))
                .unwrap();
            let mut api = Api::test_peer(address).unwrap();
            api.set_session(SID);
            let mut context = Context::test_peer(
                scratch.path(),
                api,
                Output::with_writers(true, true, stdout.clone(), stderr.clone()),
            );
            let output = scratch.path().join("output with spaces");
            let mut arguments = vec![
                "mb".into(),
                "-q".into(),
                "download".into(),
                "--json".into(),
                "--parallel".into(),
                "2".into(),
                "--workers".into(),
                "1".into(),
                "--limit".into(),
                "1024".into(),
                "-o".into(),
                output.into_os_string(),
            ];
            if folder {
                arguments.push(
                    format!(
                        "https://mega.nz/folder/SHARE123#{}",
                        wire::b64_url_encode(&wrapping_key)
                    )
                    .into(),
                );
            } else {
                arguments.extend(HANDLES.iter().map(|handle| {
                    format!(
                        "https://mega.nz/file/{handle}#{}",
                        wire::b64_url_encode(&raw_key)
                    )
                    .into()
                }));
            }
            let command = Cli::try_parse_from(arguments).unwrap().command.unwrap();
            let code = observe_limiters(acquired, || dispatch(&mut context, command)).unwrap();
            // The original context and its API are still alive for every peer-side EOF assertion.
            for _ in 0..expected_calls {
                closure.recv_timeout(Duration::from_secs(2)).unwrap();
            }
            assert!(!context.control.is_canceled());
            code
        },
    );
    assert_eq!(code, i32::from(sibling_fails));
    let acquired: Vec<_> = acquisitions.try_iter().collect();
    assert_eq!(acquired.len(), if sibling_fails { 1 } else { 2 });
    assert!(
        acquired
            .iter()
            .all(|&(id, bytes)| id == acquired[0].0 && bytes == 17)
    );
    assert_eq!(calls.len(), expected_calls);
    assert_eq!(
        *tickets.lock().unwrap(),
        BTreeMap::from([(HANDLES[0].to_owned(), 2), (HANDLES[1].to_owned(), 2),])
    );
    let output = scratch.path().join("output with spaces");
    let output = if folder {
        output.join("bundle")
    } else {
        output
    };
    assert_eq!(
        hex::encode(Sha256::digest(std::fs::read(output.join("a.bin")).unwrap())),
        vector["plaintext_sha256"]
    );
    if sibling_fails {
        assert!(!output.join("b.bin").exists());
    } else {
        assert_eq!(
            hex::encode(Sha256::digest(std::fs::read(output.join("b.bin")).unwrap())),
            vector["plaintext_sha256"]
        );
    }
    let bytes = stdout.0.lock().unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    assert!(!text.contains(SID));
    assert!(!text.contains(&wire::b64_url_encode(&raw_key)));
    let records: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let results: Vec<_> = records
        .iter()
        .filter(|record| record["event"] == "result")
        .collect();
    assert_eq!(results.len(), 2);
    for (name, status) in [
        ("a.bin", "success"),
        ("b.bin", if sibling_fails { "failed" } else { "success" }),
    ] {
        let result = results
            .iter()
            .find(|record| record["name"] == name)
            .unwrap();
        assert_eq!(result["status"], status);
    }
    if folder {
        assert_eq!(records.len(), 3);
        let summary = records
            .iter()
            .find(|record| record["event"] == "summary")
            .unwrap();
        assert_eq!(
            summary["status"],
            if sibling_fails { "failed" } else { "success" }
        );
        assert_eq!(summary["files"], if sibling_fails { 1 } else { 2 });
        assert_eq!(summary["total_bytes"], if sibling_fails { 17 } else { 34 });
    } else {
        assert_eq!(records.len(), 2);
    }
}

#[test]
fn parsed_parallel_public_downloads_isolate_refresh_sequences_close_all_responses_and_keep_success()
{
    scenario(false, true);
}

#[test]
fn parsed_parallel_folder_downloads_isolate_ticket_sequences_close_all_responses_and_keep_success()
{
    scenario(true, true);
}

#[test]
fn parsed_parallel_public_downloads_share_the_command_limiter() {
    scenario(false, false);
}

#[test]
fn parsed_parallel_folder_downloads_share_the_parent_limiter() {
    scenario(true, false);
}
