//! Parsed consumers use the same bounded underlying-link resolver and selected proxy.
#![allow(clippy::unwrap_used)]

use std::{fs, path::Path};

use clap::Parser;
use serde_json::{Value, json};

use super::{args::Cli, auto_account_peer_tests::Capture, context::Context, dispatch};
use crate::{
    error::Error,
    protocol::{
        api::Api,
        test_peer::{self, Response},
    },
    storage::proxies::{Pool, Routing},
    terminal::output::Output,
};

const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

#[test]
fn parsed_crypter_prints_the_underlying_link_after_bounded_fallback_without_exporting_password() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/megacrypter-cli");
    fs::create_dir_all(&base).unwrap();
    let scratch = crate::test_support::tempdir_in(base).unwrap();
    let stdout = Capture::default();
    let stderr = Capture::default();
    let mut methods = Vec::new();
    let ((), calls) = test_peer::with_connect_peer(
        |request| {
            assert_eq!(request.path, "/api");
            assert_eq!(request.method, "POST");
            assert!(request.connect_target.is_some());
            let method = if methods.is_empty() {
                "info"
            } else {
                "openlink"
            };
            assert_eq!(
                serde_json::from_slice::<Value>(&request.body).unwrap(),
                json!({"m":method,"link":format!("mc://{}/token",request.headers["host"])})
            );
            methods.push(method);
            Some(Response {
                status: 200,
                headers: vec![],
                body: serde_json::to_vec(&if method == "info" {
                    json!({})
                } else {
                    json!({"file_id":"ABC","file_key":"KEY"})
                })
                .unwrap(),
            })
        },
        |address| {
            let mut api = Api::test_peer(address).unwrap();
            api.transport.routing = Routing {
                explicit: None,
                pool: Some(
                    Pool::new(
                        vec![format!("http://127.0.0.1:{}", address.port())],
                        vec![],
                        None,
                    )
                    .unwrap(),
                ),
                force: true,
            };
            let mut context = Context::test_peer(
                scratch.path(),
                api,
                Output::with_writers(false, true, stdout.clone(), stderr.clone()),
            );
            let url = format!("mc://testserver.com:{}/token", address.port());
            let command = Cli::try_parse_from([
                "mb",
                "crypter",
                "resolve",
                &url,
                "--password",
                "local-password-sentinel",
            ])
            .unwrap()
            .command
            .unwrap();
            assert_eq!(dispatch(&mut context, command).unwrap(), 0);
        },
    );
    assert_eq!(methods, ["info", "openlink"]);
    assert_eq!(calls.len(), 2);
    assert_eq!(
        String::from_utf8(stdout.0.lock().unwrap().clone()).unwrap(),
        "https://mega.nz/file/ABC#KEY\n"
    );
    assert!(stderr.0.lock().unwrap().is_empty());
    assert_eq!(fs::read_dir(scratch.path()).unwrap().count(), 0);
}

#[test]
fn metadata_only_info_succeeds_and_transfer_consumers_do_not_repeat_a_rejected_dl_method() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/megacrypter-cli");
    fs::create_dir_all(&base).unwrap();
    for verb in ["download", "info", "stream"] {
        let scratch = crate::test_support::tempdir_in(&base).unwrap();
        let stdout = Capture::default();
        let stderr = Capture::default();
        let mut steps = Vec::new();
        let ((), calls) = test_peer::with_connect_peer(
            |request| {
                let method = ["info", "openlink", "dl"][steps.len()];
                assert_eq!(request.method, "POST");
                assert_eq!(request.path, "/api");
                assert!(request.connect_target.is_some());
                assert_eq!(
                    serde_json::from_slice::<Value>(&request.body).unwrap(),
                    json!({"m":method,"link":format!("mc://{}/token",request.headers["host"])})
                );
                steps.push(method);
                Some(Response {
                    status: if method == "openlink" { 404 } else { 200 },
                    headers: vec![],
                    body: serde_json::to_vec(&if method == "info" {
                        json!({"name":"plain.bin","size":17,"key":KEY,"pass":false})
                    } else {
                        json!({"error":-1,"private":"response-body-sentinel"})
                    })
                    .unwrap(),
                })
            },
            |address| {
                let mut api = Api::test_peer(address).unwrap();
                api.transport.routing = Routing {
                    explicit: None,
                    pool: Some(
                        Pool::new(
                            vec![format!("http://127.0.0.1:{}", address.port())],
                            vec![],
                            None,
                        )
                        .unwrap(),
                    ),
                    force: true,
                };
                let mut context = Context::test_peer(
                    scratch.path(),
                    api,
                    Output::with_writers(verb != "stream", true, stdout.clone(), stderr.clone()),
                );
                let url = format!("mc://testserver.com:{}/token", address.port());
                let mut arguments = vec!["mb", verb, &url];
                if verb != "stream" {
                    arguments.push("--json");
                }
                let command = Cli::try_parse_from(arguments).unwrap().command.unwrap();
                let result = dispatch(&mut context, command);
                let text = String::from_utf8(stdout.0.lock().unwrap().clone()).unwrap();
                if verb == "info" {
                    assert_eq!(result.unwrap(), 0);
                    let document: Value = serde_json::from_str(&text).unwrap();
                    assert_eq!(
                        document,
                        json!({"type":"MegaCrypter file","name":"plain.bin","size":17,"file_key":"available"})
                    );
                } else if verb == "download" {
                    assert_eq!(result.unwrap(), 1);
                    let record: Value = serde_json::from_str(&text).unwrap();
                    assert_eq!(record["status"], "failed");
                    assert_eq!(record["error_code"], "protocol_error");
                    assert!(
                        record["error"]
                            .as_str()
                            .unwrap()
                            .contains("no usable download URL")
                    );
                } else {
                    assert!(
                        matches!(result,Err(Error::Protocol(message)) if message.contains("no usable download URL"))
                    );
                    assert!(text.is_empty());
                }
                assert!(!text.contains(KEY));
                assert!(!text.contains("response-body-sentinel"));
                assert_eq!(fs::read_dir(scratch.path()).unwrap().count(), 0);
            },
        );
        assert_eq!(steps, ["info", "openlink", "dl"]);
        assert_eq!(calls.len(), 3);
    }
}

#[test]
fn download_info_and_stream_use_openlink_key_aliases_before_the_public_metadata_boundary() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/megacrypter-cli");
    fs::create_dir_all(&base).unwrap();
    for verb in ["download", "info", "stream"] {
        let scratch = crate::test_support::tempdir_in(&base).unwrap();
        let stdout = Capture::default();
        let stderr = Capture::default();
        let mut steps = Vec::new();
        let ((), calls) = test_peer::with_connect_peer(
            |request| {
                assert_eq!(request.method, "POST");
                assert!(request.connect_target.is_some());
                assert!(!request.headers.contains_key("proxy-authorization"));
                let body: Value = serde_json::from_slice(&request.body).unwrap();
                let response = match steps.len() {
                    0 | 1 => {
                        let method = if steps.is_empty() { "info" } else { "openlink" };
                        assert_eq!(request.path, "/api");
                        assert_eq!(
                            body,
                            json!({"m":method,"link":format!("mc://{}/token",request.headers["host"])})
                        );
                        steps.push(method);
                        if method == "info" {
                            json!({})
                        } else {
                            json!({"id":"FILEID","file_key":KEY})
                        }
                    }
                    2 => {
                        let url =
                            url::Url::parse(&format!("https://testserver.com{}", request.path))
                                .unwrap();
                        assert_eq!(url.path(), "/cs");
                        assert!(!url.query_pairs().any(|(key, _)| key == "sid"));
                        assert_eq!(body, json!([{"a":"g","g":1,"ssl":2,"p":"FILEID"}]));
                        steps.push("g");
                        json!([-9])
                    }
                    _ => panic!("consumer retried or contacted file bytes"),
                };
                Some(Response {
                    status: 200,
                    headers: vec![("Content-Type".into(), "application/json".into())],
                    body: serde_json::to_vec(&response).unwrap(),
                })
            },
            |address| {
                let mut api = Api::test_peer(address).unwrap();
                api.transport.routing = Routing {
                    explicit: None,
                    pool: Some(
                        Pool::new(
                            vec![format!("http://127.0.0.1:{}", address.port())],
                            vec![],
                            None,
                        )
                        .unwrap(),
                    ),
                    force: true,
                };
                let mut context = Context::test_peer(
                    scratch.path(),
                    api,
                    Output::with_writers(verb != "stream", true, stdout.clone(), stderr.clone()),
                );
                let url = format!("mc://testserver.com:{}/token", address.port());
                let mut arguments = vec!["mb", verb, &url];
                if verb != "stream" {
                    arguments.push("--json");
                }
                let command = Cli::try_parse_from(arguments).unwrap().command.unwrap();
                let result = dispatch(&mut context, command);
                if verb == "download" {
                    assert_eq!(result.unwrap(), 1);
                    let output = String::from_utf8(stdout.0.lock().unwrap().clone()).unwrap();
                    let records: Vec<Value> = output
                        .lines()
                        .map(|line| serde_json::from_str(line).unwrap())
                        .collect();
                    assert_eq!(records.len(), 1);
                    assert_eq!(records[0]["status"], "failed");
                    assert_eq!(records[0]["error_code"], "mega_error");
                } else {
                    assert!(matches!(result, Err(Error::Mega { code: -9, .. })));
                    assert!(stdout.0.lock().unwrap().is_empty());
                }
                assert!(!context.paths.accounts().exists());
                assert!(!context.paths.logs.exists());
                assert_eq!(fs::read_dir(scratch.path()).unwrap().count(), 0);
            },
        );
        assert_eq!(steps, ["info", "openlink", "g"]);
        assert_eq!(calls.len(), 3);
    }
}
