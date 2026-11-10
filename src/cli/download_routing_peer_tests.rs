//! The parsed download entry and expired-ticket refresh retain their explicit routing policy.
#![allow(clippy::unwrap_used)]

use std::{fs, path::Path};

use clap::Parser;
use serde_json::{Value, json};

use super::{args::Cli, auto_account_peer_tests::Capture, context::Context, dispatch};
use crate::{
    error::Error,
    protocol::{
        api::Api,
        containers, links, metadata,
        test_peer::{self, Response},
    },
    storage::proxies::{Pool, Routing},
    terminal::output::Output,
};

fn route(api: &mut Api, address: std::net::SocketAddr, available: bool) {
    let proxies = if available {
        vec![format!("http://127.0.0.1:{}", address.port())]
    } else {
        vec![]
    };
    api.transport.routing = Routing {
        explicit: None,
        pool: Some(Pool::new(proxies, vec![], None).unwrap()),
        force: true,
    };
}

fn assert_request(request: &test_peer::Request, method: &str) {
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/api");
    assert!(request.connect_target.is_some());
    assert!(!request.headers.contains_key("proxy-authorization"));
    assert_eq!(
        serde_json::from_slice::<Value>(&request.body).unwrap(),
        json!({"m":method,"link":format!("mc://{}/token",request.headers["host"])})
    );
}

#[test]
fn parsed_download_megacrypter_uses_its_selected_proxy_or_refuses_before_contact() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/download-routing");
    fs::create_dir_all(&base).unwrap();
    for available in [false, true] {
        let scratch = tempfile::tempdir_in(&base).unwrap();
        let stdout = Capture::default();
        let stderr = Capture::default();
        let ((), calls) = test_peer::with_connect_peer(
            |request| {
                assert!(available, "empty forced pool opened a request");
                assert_request(request, "info");
                Some(Response {
                    status: 503,
                    headers: vec![],
                    body: b"service-body-sentinel".to_vec(),
                })
            },
            |address| {
                let mut api = Api::test_peer(address).unwrap();
                route(&mut api, address, available);
                let mut context = Context::test_peer(
                    scratch.path(),
                    api,
                    Output::with_writers(true, true, stdout.clone(), stderr.clone()),
                );
                context.config.max_workers = 1;
                context.config.max_parallel_downloads = 1;
                let output = scratch.path().join("output with spaces");
                let command = Cli::try_parse_from([
                    "mb".into(),
                    "download".into(),
                    format!("mc://testserver.com:{}/token", address.port()).into(),
                    "--json".into(),
                    "-o".into(),
                    output.clone().into_os_string(),
                ])
                .unwrap()
                .command
                .unwrap();
                assert_eq!(dispatch(&mut context, command).unwrap(), 1);
                let records = String::from_utf8(stdout.0.lock().unwrap().clone()).unwrap();
                let records: Vec<Value> = records
                    .lines()
                    .map(|line| serde_json::from_str(line).unwrap())
                    .collect();
                assert_eq!(records.len(), 1);
                assert_eq!(records[0]["event"], "result");
                assert_eq!(records[0]["type"], "download");
                assert_eq!(records[0]["status"], "failed");
                assert_eq!(records[0]["error_code"], "protocol_error");
                let expected = if available {
                    "unsuccessful HTTP status"
                } else {
                    "direct connection was refused"
                };
                assert!(records[0]["error"].as_str().unwrap().contains(expected));
                let diagnostic = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
                assert!(diagnostic.contains(expected));
                assert!(!diagnostic.contains("panicked") && !diagnostic.contains("Traceback"));
                assert!(!output.exists());
                assert!(!context.paths.user.join("Data/transfers").exists());
                assert!(!context.paths.accounts().exists());
                assert!(!context.paths.logs.exists());
            },
        );
        assert_eq!(calls.len(), usize::from(available));
    }
}

#[test]
fn parsed_download_refuses_absurd_or_noninteger_sizes_before_claims_staging_or_cdn_work() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/download-routing");
    fs::create_dir_all(&base).unwrap();
    for (declared, expected_code) in [
        (json!(1u64 << 50), "invalid_input"),
        (
            json!(crate::crypto::chunks::MAX_FILE_SIZE + 1),
            "invalid_input",
        ),
        (json!(-1), "protocol_error"),
        (json!(true), "protocol_error"),
        (json!("12"), "protocol_error"),
        (Value::Null, "protocol_error"),
    ] {
        let scratch = tempfile::tempdir_in(&base).unwrap();
        let stdout = Capture::default();
        let stderr = Capture::default();
        let ((), calls) = test_peer::with_peer(
            |request| {
                assert_eq!(request.method, "POST");
                let endpoint =
                    url::Url::parse(&format!("https://testserver.com{}", request.path)).unwrap();
                assert_eq!(endpoint.path(), "/cs");
                assert_eq!(
                    serde_json::from_slice::<Value>(&request.body).unwrap(),
                    json!([{"a":"g","g":1,"ssl":2,"p":"FILEID"}])
                );
                assert!(!endpoint.query_pairs().any(|(key, _)| key == "sid"));
                Some(Response {
                    status: 200,
                    headers: vec![("Content-Type".into(), "application/json".into())],
                    body: serde_json::to_vec(&json!([{"s":declared,
                        "g":format!("https://{}/must-not-fetch", request.headers["host"])}]))
                    .unwrap(),
                })
            },
            |address| {
                let mut context = Context::test_peer(
                    scratch.path(),
                    Api::test_peer(address).unwrap(),
                    Output::with_writers(true, true, stdout.clone(), stderr.clone()),
                );
                let command = Cli::try_parse_from([
                    "mb",
                    "download",
                    "https://mega.nz/file/FILEID#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "--json",
                    "--no-verify",
                ])
                .unwrap()
                .command
                .unwrap();
                assert_eq!(dispatch(&mut context, command).unwrap(), 1);
                let text = String::from_utf8(stdout.0.lock().unwrap().clone()).unwrap();
                let record: Value = serde_json::from_str(&text).unwrap();
                assert_eq!(record["event"], "result");
                assert_eq!(record["status"], "failed");
                assert_eq!(record["error_code"], expected_code);
                assert_eq!(
                    fs::read_dir(scratch.path()).unwrap().count(),
                    0,
                    "rejected size created a claim, stage, account or transfer store"
                );
            },
        );
        assert_eq!(
            calls.len(),
            1,
            "rejected size reached CDN or retried metadata"
        );
    }
}

#[test]
fn parsed_download_quota_attempts_are_bounded_and_pool_escalation_does_not_wait() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/download-routing");
    fs::create_dir_all(&base).unwrap();
    for (attempts, rejections, expected_calls, expected_code) in [
        (0, 99, 1, "quota_exceeded"),
        (1, 99, 1, "quota_exceeded"),
        (2, 99, 2, "quota_exceeded"),
        (2, 1, 2, "mega_error"),
    ] {
        let scratch = tempfile::tempdir_in(&base).unwrap();
        let stdout = Capture::default();
        let stderr = Capture::default();
        let mut count = 0;
        let ((), calls) = test_peer::with_connect_peer(
            |request| {
                count += 1;
                assert!(count <= expected_calls, "quota attempt budget was extended");
                assert_eq!(request.method, "POST");
                assert!(request.connect_target.is_some());
                assert_eq!(
                    serde_json::from_slice::<Value>(&request.body).unwrap(),
                    json!([{"a":"g","g":1,"ssl":2,"p":"FILEID"}])
                );
                let endpoint =
                    url::Url::parse(&format!("https://testserver.com{}", request.path)).unwrap();
                assert_eq!(endpoint.path(), "/cs");
                assert!(!endpoint.query_pairs().any(|(key, _)| key == "sid"));
                Some(Response {
                    status: 200,
                    headers: vec![("Content-Type".into(), "application/json".into())],
                    body: serde_json::to_vec(&json!([if count <= rejections { -17 } else { -9 }]))
                        .unwrap(),
                })
            },
            |address| {
                let mut api = Api::test_peer(address).unwrap();
                route(&mut api, address, true);
                let mut context = Context::test_peer(
                    scratch.path(),
                    api,
                    Output::with_writers(true, true, stdout.clone(), stderr.clone()),
                );
                // The owned watchdog cancels a missed immediate retry after five seconds.
                context.config.quota_wait_seconds = 3600;
                context.config.quota_max_wait_loops = attempts;
                let control = context.control.clone();
                let (stopped, stop) = std::sync::mpsc::sync_channel(1);
                std::thread::scope(|scope| {
                    let cancel = scope.spawn(move || {
                        if stop
                            .recv_timeout(std::time::Duration::from_secs(5))
                            .is_err()
                        {
                            control.cancel();
                        }
                    });
                    let command = Cli::try_parse_from([
                        "mb",
                        "download",
                        "https://mega.nz/file/FILEID#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                        "--json",
                        "--no-verify",
                    ])
                    .unwrap()
                    .command
                    .unwrap();
                    let result = dispatch(&mut context, command);
                    let _ = stopped.send(());
                    cancel.join().unwrap();
                    assert_eq!(result.unwrap(), 1);
                });
                let record: Value = serde_json::from_slice(&stdout.0.lock().unwrap()).unwrap();
                assert_eq!(record["event"], "result");
                assert_eq!(record["status"], "failed");
                assert_eq!(record["error_code"], expected_code);
                assert_eq!(fs::read_dir(scratch.path()).unwrap().count(), 0);
            },
        );
        assert_eq!(count, expected_calls);
        assert_eq!(calls.len(), expected_calls);
    }
}

#[test]
fn parsed_download_direct_and_forced_manual_routes_publish_the_same_verified_source_bytes() {
    use crate::crypto::wire;
    use sha2::{Digest, Sha256};
    use std::sync::OnceLock;

    let vectors: Value =
        serde_json::from_str(include_str!("../../tests/fixtures/transfers/vectors.json")).unwrap();
    let vector = &vectors["vectors"][1];
    assert_eq!(vector["size"], 17);
    let ciphertext = include_bytes!("../../tests/fixtures/transfers/ciphertext-17.bin");
    assert_eq!(
        hex::encode(Sha256::digest(ciphertext)),
        vector["ciphertext_sha256"].as_str().unwrap()
    );
    let raw_key = hex::decode(vector["raw_key"].as_str().unwrap()).unwrap();
    let link = format!(
        "https://mega.nz/file/FILEID#{}",
        wire::b64_url_encode(&raw_key)
    );
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/download-routing");
    fs::create_dir_all(&base).unwrap();
    for manual in [false, true] {
        let scratch = tempfile::tempdir_in(&base).unwrap();
        let output = scratch.path().join("output with spaces");
        let stdout = Capture::default();
        let stderr = Capture::default();
        let cdn = OnceLock::new();
        let reply = |request: &test_peer::Request| {
            assert_eq!(request.connect_target.is_some(), manual);
            assert!(!request.headers.contains_key("proxy-authorization"));
            if request.path.starts_with("/cs?") {
                assert_eq!(request.method, "POST");
                let endpoint =
                    url::Url::parse(&format!("https://testserver.com{}", request.path)).unwrap();
                assert!(!endpoint.query_pairs().any(|(key, _)| key == "sid"));
                assert_eq!(
                    serde_json::from_slice::<Value>(&request.body).unwrap(),
                    json!([{"a":"g","g":1,"ssl":2,"p":"FILEID"}])
                );
                Some(Response {
                    status: 200,
                    headers: vec![],
                    body: serde_json::to_vec(&json!([{"s":17,"g":cdn.get().unwrap()}])).unwrap(),
                })
            } else {
                assert_eq!(request.method, "GET");
                assert_eq!(request.path, "/cdn");
                assert_eq!(request.headers["range"], "bytes=0-16");
                assert!(request.body.is_empty());
                Some(Response {
                    status: 206,
                    headers: vec![("Content-Range".into(), "bytes 0-16/17".into())],
                    body: ciphertext.to_vec(),
                })
            }
        };
        let run = |address: std::net::SocketAddr| {
            cdn.set(format!("https://testserver.com:{}/cdn", address.port()))
                .unwrap();
            let mut api = Api::test_peer(address).unwrap();
            api.transport.routing = Routing {
                explicit: manual.then(|| format!("http://127.0.0.1:{}", address.port())),
                pool: None,
                force: manual,
            };
            let mut context = Context::test_peer(
                scratch.path(),
                api,
                Output::with_writers(true, true, stdout.clone(), stderr.clone()),
            );
            let command = Cli::try_parse_from([
                "mb".into(),
                "-q".into(),
                "download".into(),
                link.clone().into(),
                "--json".into(),
                "-w".into(),
                "1".into(),
                "-P".into(),
                "1".into(),
                "-o".into(),
                output.clone().into_os_string(),
            ])
            .unwrap()
            .command
            .unwrap();
            assert_eq!(dispatch(&mut context, command).unwrap(), 0);
            let bytes = fs::read(output.join("FILEID")).unwrap();
            assert_eq!(bytes.len(), 17);
            assert_eq!(
                hex::encode(Sha256::digest(&bytes)),
                vector["plaintext_sha256"].as_str().unwrap()
            );
            assert!(
                bytes
                    .iter()
                    .enumerate()
                    .all(|(index, &byte)| byte == ((index * 13 + 7) % 256) as u8)
            );
            let record: Value = serde_json::from_slice(&stdout.0.lock().unwrap()).unwrap();
            assert_eq!(record["event"], "result");
            assert_eq!(record["status"], "success");
            assert_eq!(record["size"], 17);
            assert_eq!(record["integrity_ok"], true);
            assert!(!context.paths.accounts().exists() && !context.paths.logs.exists());
            let diagnostic = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
            assert!(!diagnostic.contains(wire::b64_url_encode(&raw_key).as_str()));
        };
        let ((), calls) = if manual {
            test_peer::with_connect_peer(reply, run)
        } else {
            test_peer::with_peer(reply, run)
        };
        assert_eq!(
            calls.len(),
            2,
            "successful routing retried or omitted a request"
        );
        assert!(
            calls
                .iter()
                .all(|request| request.connect_target.is_some() == manual)
        );
    }
}

#[test]
fn megacrypter_refresh_refuses_an_empty_forced_pool_and_uses_the_pool_when_available() {
    for available in [false, true] {
        let ((), calls) = test_peer::with_connect_peer(
            |request| {
                assert!(available, "empty forced refresh pool opened a request");
                assert_request(request, "dl");
                Some(Response {
                    status: 200,
                    headers: vec![],
                    body: b"{\"url\":\"https://cdn.example/refreshed\"}".to_vec(),
                })
            },
            |address| {
                let mut api = Api::test_peer(address).unwrap();
                route(&mut api, address, available);
                let link =
                    links::parse_link(&format!("mc://testserver.com:{}/token", address.port()))
                        .unwrap();
                let info = containers::decrypt_megacrypter_info(
                    &json!({"name":"sample.bin","size":0,
                        "key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}),
                    None,
                )
                .unwrap();
                let file = metadata::FileInfo::megacrypter(
                    link,
                    info,
                    "https://cdn.example/expired".into(),
                )
                .unwrap();
                let result = metadata::refresh(&mut api, &file);
                if available {
                    assert_eq!(result.unwrap(), "https://cdn.example/refreshed");
                } else {
                    assert!(
                        matches!(result, Err(Error::Protocol(message)) if message.contains("direct connection was refused"))
                    );
                }
                // The refresh consumes existing metadata; it never logs in or refetches its key.
                assert_eq!(file.name, "sample.bin");
                assert_eq!(file.size, 0);
                assert_eq!(file.url, "https://cdn.example/expired");
                assert_eq!(file.raw_key.as_slice(), &[0; 32]);
            },
        );
        assert_eq!(calls.len(), usize::from(available));
    }
}
