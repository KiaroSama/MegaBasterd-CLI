//! Parsed command returns release real TLS responses without ending a cached server session.
#![allow(clippy::unwrap_used)]

use std::{
    io::{self, Read, Write},
    path::Path,
    sync::mpsc,
    time::Duration,
};

use clap::Parser;
use serde_json::{Value, json};

use super::{
    args::Cli,
    auto_account_peer_tests::{Capture, seed_accounts},
    context::Context,
    dispatch,
};
use crate::{
    crypto::wire,
    error::Error,
    protocol::{api::Api, test_peer},
    storage::sessions::Sessions,
    terminal::output::Output,
};

const EMAIL: &str = "fixture@example.invalid";
const SID: &str = "synthetic-command-session";
const PASS: &str = "synthetic vault passphrase";

#[test]
fn account_verification_releases_responses_on_rejection_malformed_reply_missing_mfa_and_success() {
    let data: Value =
        serde_json::from_str(include_str!("../../tests/fixtures/crypto-vectors.json")).unwrap();
    let derived = hex::decode(data["kdf_v2"][2]["derived"].as_str().unwrap()).unwrap();
    let master = hex::decode(data["rsa"]["master_key"].as_str().unwrap()).unwrap();
    let salt =
        wire::b64_url_encode(&hex::decode(data["kdf_v2"][2]["salt"].as_str().unwrap()).unwrap());
    let login = json!({"u":"AQIDBAUGBwg",
        "k":wire::b64_url_encode(&wire::aes_key_wrap_encrypt(&master,&derived[..16]).unwrap()),
        "privk":wire::b64_url_encode(&hex::decode(data["rsa"]["wrapped_private"].as_str().unwrap()).unwrap()),
        "csid":wire::b64_url_encode(&hex::decode(data["rsa"]["csid"].as_str().unwrap()).unwrap())});
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/client-lifecycle");
    std::fs::create_dir_all(&base).unwrap();
    for mode in [
        "rejected",
        "malformed",
        "missing-mfa",
        "canceled-mfa",
        "success",
    ] {
        let scratch = crate::test_support::tempdir_in(&base).unwrap();
        let stdout = Capture::default();
        let stderr = Capture::default();
        let (closed, closure) = mpsc::sync_channel(3);
        let ((), calls) = test_peer::with_raw_peer(
            |request, stream| {
                assert_eq!(request.method, "POST");
                let payload: Value = serde_json::from_slice(&request.body).unwrap();
                assert_eq!(payload.as_array().unwrap().len(), 1);
                let url =
                    url::Url::parse(&format!("https://testserver.com{}", request.path)).unwrap();
                let result = match payload[0]["a"].as_str().unwrap() {
                    "us0" => {
                        assert_eq!(payload, json!([{"a":"us0","user":EMAIL}]));
                        assert!(!url.query_pairs().any(|(key, _)| key == "sid"));
                        match mode {
                            "rejected" => json!(-9),
                            "malformed" => json!({"v":"2"}),
                            _ => json!({"v":2,"s":salt}),
                        }
                    }
                    "us" => {
                        assert_eq!(
                            payload,
                            json!([{"a":"us","user":EMAIL,"uh":wire::b64_url_encode(&derived[16..])}])
                        );
                        assert!(!url.query_pairs().any(|(key, _)| key == "sid"));
                        if matches!(mode, "missing-mfa" | "canceled-mfa") {
                            json!(-26)
                        } else {
                            assert_eq!(mode, "success");
                            login.clone()
                        }
                    }
                    "ug" => {
                        assert_eq!(mode, "success");
                        assert_eq!(payload, json!([{"a":"ug"}]));
                        assert!(url.query_pairs().any(|(key, value)| key == "sid"
                            && value == data["rsa"]["sid"].as_str().unwrap()));
                        json!({"u":"AQIDBAUGBwg"})
                    }
                    _ => panic!("account verification sent an unrelated request or logout"),
                };
                respond_and_observe_close(stream, 200, result);
                closed.try_send(()).unwrap();
            },
            |address| {
                let mut context = Context::test_peer(
                    scratch.path(),
                    Api::test_peer(address).unwrap(),
                    Output::with_writers(
                        mode == "missing-mfa",
                        false,
                        stdout.clone(),
                        stderr.clone(),
                    ),
                );
                let super::args::Command::Account(command) = Cli::try_parse_from([
                    "mb",
                    "account",
                    "add",
                    EMAIL,
                    "--password",
                    "source-fixture",
                    "--vault-passphrase",
                    PASS,
                ])
                .unwrap()
                .command
                .unwrap() else {
                    unreachable!()
                };
                let mut confirmations = 0;
                let mut add_anyway = || {
                    confirmations += 1;
                    assert_eq!(
                        mode, "rejected",
                        "a non-rejection became unverified-save consent"
                    );
                    Ok(false)
                };
                let mut interrupted = 0;
                let result = if mode == "canceled-mfa" {
                    super::accounts::dispatch_with_mfa(
                        &mut context,
                        command,
                        &mut add_anyway,
                        |_| {
                            interrupted += 1;
                            Err(Error::Canceled)
                        },
                    )
                } else {
                    super::accounts::dispatch_with_confirmation(
                        &mut context,
                        command,
                        &mut add_anyway,
                    )
                };
                assert_eq!(interrupted, usize::from(mode == "canceled-mfa"));
                let requests = match mode {
                    "rejected" => {
                        result.unwrap();
                        assert_eq!(confirmations, 1);
                        1
                    }
                    "malformed" => {
                        assert!(matches!(result, Err(Error::Protocol(_))));
                        1
                    }
                    "missing-mfa" => {
                        assert!(
                            matches!(result, Err(Error::Auth(message)) if message.contains("--mfa-code"))
                        );
                        2
                    }
                    "canceled-mfa" => {
                        let error = result.unwrap_err();
                        assert!(matches!(&error, Error::Canceled));
                        assert_eq!(error.exit_code(), 130);
                        context.report_error(&error);
                        2
                    }
                    _ => {
                        result.unwrap();
                        assert!(context.paths.accounts().is_file());
                        assert!(context.paths.session(EMAIL).is_file());
                        assert_eq!(context.accounts().list().unwrap().accounts.len(), 1);
                        3
                    }
                };
                assert_eq!(confirmations, usize::from(mode == "rejected"));
                for _ in 0..requests {
                    closure.recv_timeout(Duration::from_secs(2)).unwrap();
                }
                if mode != "success" {
                    assert!(
                        !context.paths.user.exists(),
                        "failed verification created saved state"
                    );
                }
                assert!(!context.paths.output.exists() && !context.paths.logs.exists());
                assert!(stdout.0.lock().unwrap().is_empty());
            },
        );
        let actions: Vec<_> = calls
            .iter()
            .map(|request| {
                let payload: Value = serde_json::from_slice(&request.body).unwrap();
                payload[0]["a"].as_str().unwrap().to_owned()
            })
            .collect();
        assert_eq!(
            actions,
            match mode {
                "success" => vec!["us0", "us", "ug"],
                "missing-mfa" | "canceled-mfa" => vec!["us0", "us"],
                _ => vec!["us0"],
            }
        );
        let text = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
        if mode == "success" {
            assert!(text.contains("Account saved"));
        } else {
            assert!(!text.contains("Account saved") && !text.contains("session refreshed"));
        }
        for secret in [PASS, "source-fixture", data["rsa"]["sid"].as_str().unwrap()] {
            assert!(!text.contains(secret));
        }
    }
}

#[test]
fn account_verification_timeout_releases_each_attempt_without_consent_or_saved_state() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/client-lifecycle");
    std::fs::create_dir_all(&base).unwrap();
    let scratch = crate::test_support::tempdir_in(&base).unwrap();
    let stdout = Capture::default();
    let stderr = Capture::default();
    let (closed, closure) = mpsc::sync_channel(5);
    let (backoff, waits) = mpsc::sync_channel(4);
    let ((), calls) = test_peer::with_raw_peer(
        |request, stream| {
            assert_eq!(request.method, "POST");
            assert_eq!(
                serde_json::from_slice::<Value>(&request.body).unwrap(),
                json!([{"a":"us0","user":EMAIL}])
            );
            let url = url::Url::parse(&format!("https://testserver.com{}", request.path)).unwrap();
            assert!(!url.query_pairs().any(|(key, _)| key == "sid"));
            // Withhold headers: the real client deadline, not the peer, must close this socket.
            observe_close(stream);
            closed.try_send(()).unwrap();
        },
        |address| {
            let mut api = Api::test_peer(address).unwrap();
            api.transport.timeout = Duration::from_secs(1);
            api.observe_backoffs(backoff);
            let mut context = Context::test_peer(
                scratch.path(),
                api,
                Output::with_writers(false, false, stdout.clone(), stderr.clone()),
            );
            let super::args::Command::Account(command) = Cli::try_parse_from([
                "mb",
                "account",
                "add",
                EMAIL,
                "--password",
                "source-fixture",
                "--vault-passphrase",
                PASS,
            ])
            .unwrap()
            .command
            .unwrap() else {
                unreachable!()
            };
            let error = super::accounts::dispatch_with_confirmation(&mut context, command, || {
                panic!("transport uncertainty must not become unverified-save consent")
            })
            .unwrap_err();
            assert!(
                matches!(&error, Error::Timeout)
                    || matches!(&error, Error::Http(cause) if cause.is_timeout())
            );
            assert_eq!(error.exit_code(), 1);
            context.report_error(&error);
            for _ in 0..5 {
                closure.recv_timeout(Duration::from_secs(2)).unwrap();
            }
            assert_eq!(
                waits
                    .try_iter()
                    .map(|duration| duration.as_secs())
                    .collect::<Vec<_>>(),
                [2, 4, 8, 16]
            );
            assert!(!context.control.is_canceled());
            assert!(!context.paths.user.exists());
            assert!(!context.paths.output.exists() && !context.paths.logs.exists());
            assert!(stdout.0.lock().unwrap().is_empty());
            let text = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
            assert!(!text.contains("Account saved") && !text.contains("session refreshed"));
            assert!(!text.contains(PASS) && !text.contains("source-fixture"));
        },
    );
    assert_eq!(calls.len(), 5);
    let ids = calls
        .iter()
        .map(|request| {
            let url = url::Url::parse(&format!("https://testserver.com{}", request.path)).unwrap();
            url.query_pairs()
                .find(|(key, _)| key == "id")
                .unwrap()
                .1
                .into_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(ids, ["1", "2", "3", "4", "5"]);
}

#[test]
fn failed_upload_and_queue_logins_release_the_response_before_context_drop() {
    use crate::storage::queue::{JobStatus, Queue};

    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/client-lifecycle");
    std::fs::create_dir_all(&base).unwrap();
    for queued in [false, true] {
        let scratch = crate::test_support::tempdir_in(&base).unwrap();
        let source = scratch.path().join("upload source.bin");
        std::fs::write(&source, b"data").unwrap();
        seed_accounts(scratch.path(), &[(EMAIL, SID, 1024)]);
        let paths = Context::test_context(scratch.path()).paths;
        Sessions::new(paths.session(EMAIL)).forget().unwrap();
        let accounts = std::fs::read(paths.accounts()).unwrap();
        let stdout = Capture::default();
        let stderr = Capture::default();
        let (closed, closure) = mpsc::sync_channel(1);
        let ((), calls) = test_peer::with_raw_peer(
            |request, stream| {
                assert_eq!(request.method, "POST");
                assert_eq!(
                    serde_json::from_slice::<Value>(&request.body).unwrap(),
                    json!([{"a":"us0","user":EMAIL}])
                );
                let url =
                    url::Url::parse(&format!("https://testserver.com{}", request.path)).unwrap();
                assert!(!url.query_pairs().any(|(key, _)| key == "sid"));
                respond_and_observe_close(stream, 200, json!(-9));
                closed.try_send(()).unwrap();
            },
            |address| {
                let mut context = Context::test_peer(
                    scratch.path(),
                    Api::test_peer(address).unwrap(),
                    Output::with_writers(false, true, stdout.clone(), stderr.clone()),
                );
                let source_arg = source.to_str().unwrap();
                let command = if queued {
                    let add = Cli::try_parse_from([
                        "mb",
                        "-q",
                        "queue",
                        "add-upload",
                        source_arg,
                        "-a",
                        EMAIL,
                    ])
                    .unwrap()
                    .command
                    .unwrap();
                    assert_eq!(dispatch(&mut context, add).unwrap(), 0);
                    let before = Queue::new(context.paths.queue()).list().unwrap();
                    assert_eq!(before.len(), 1);
                    assert_eq!(before[0].status, JobStatus::Pending);
                    assert_eq!(before[0].lease_epoch, 0);
                    Cli::try_parse_from(["mb", "-q", "queue", "run", "--vault-passphrase", PASS])
                        .unwrap()
                        .command
                        .unwrap()
                } else {
                    Cli::try_parse_from([
                        "mb",
                        "-q",
                        "upload",
                        source_arg,
                        "-a",
                        EMAIL,
                        "--vault-passphrase",
                        PASS,
                    ])
                    .unwrap()
                    .command
                    .unwrap()
                };
                let error = dispatch(&mut context, command).unwrap_err();
                assert_eq!(error.exit_code(), 1);
                if queued {
                    assert!(
                        matches!(&error, Error::Protocol(message) if message == "1 queue job(s) failed.")
                    );
                    let queue = Queue::new(context.paths.queue());
                    let items = queue.list().unwrap();
                    assert_eq!(items.len(), 1);
                    assert_eq!(items[0].status, JobStatus::Failed);
                    assert_eq!(items[0].lease_epoch, 1);
                    assert!(items[0].run_id.is_none() && items[0].heartbeat_iso.is_none());
                    assert!(items[0].finished_iso.is_some());
                    let payload = queue.payload(&items[0]).unwrap();
                    assert_eq!(
                        std::path::Path::new(&payload.source),
                        source.canonicalize().unwrap()
                    );
                    assert_eq!(payload.account.as_deref(), Some(EMAIL));
                    assert!(payload.error.is_some());
                } else {
                    assert!(matches!(&error, Error::Mega { code: -9, .. }));
                    assert!(!context.paths.queue().exists());
                }
                context.report_error(&error);
                closure.recv_timeout(Duration::from_secs(2)).unwrap();
                assert_eq!(std::fs::read(context.paths.accounts()).unwrap(), accounts);
                assert!(!context.paths.session(EMAIL).exists());
                assert!(!context.paths.output.exists() && !context.paths.logs.exists());
                assert!(!context.control.is_canceled());
            },
        );
        assert_eq!(calls.len(), 1);
        assert_eq!(std::fs::read(&source).unwrap(), b"data");
        assert!(stdout.0.lock().unwrap().is_empty());
        let text = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
        assert!(text.contains("[ERROR]"));
        assert!(!text.contains("completed") && !text.contains("Account saved"));
        for secret in [PASS, SID, "synthetic password"] {
            assert!(!text.contains(secret));
        }
    }
}

pub(super) fn respond_and_observe_close(
    stream: &mut (impl Read + Write),
    status: u16,
    result: Value,
) {
    let body = serde_json::to_vec(&json!([result])).unwrap();
    write!(
        stream,
        "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        body.len()
    )
    .unwrap();
    stream.write_all(&body).unwrap();
    stream.flush().unwrap();
    observe_close(stream);
}

pub(super) fn observe_close(stream: &mut impl Read) {
    // The server does not close first: a timeout or another request on this socket fails.
    match stream.read(&mut [0; 1]) {
        Ok(0) => (),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
            ) => {}
        other => panic!("command retained a live HTTP response: {other:?}"),
    }
}

#[test]
fn public_info_and_failed_stream_setup_release_responses_before_context_drop() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/client-lifecycle");
    std::fs::create_dir_all(&base).unwrap();
    for mode in [
        "info-success",
        "info-rejected",
        "info-empty-folder",
        "stream-rejected",
    ] {
        let scratch = crate::test_support::tempdir_in(&base).unwrap();
        let stdout = Capture::default();
        let stderr = Capture::default();
        let (closed, closure) = mpsc::sync_channel(1);
        let ((), calls) = test_peer::with_raw_peer(
            |request, stream| {
                let payload: Value = serde_json::from_slice(&request.body).unwrap();
                assert_eq!(request.method, "POST");
                let url =
                    url::Url::parse(&format!("https://testserver.com{}", request.path)).unwrap();
                assert!(!url.query_pairs().any(|(key, _)| key == "sid"));
                let result = if mode == "info-empty-folder" {
                    assert_eq!(payload, json!([{"a":"f","c":1,"r":1,"ca":1}]));
                    assert!(
                        url.query_pairs()
                            .any(|(key, value)| key == "n" && value == "ABCDEFGH")
                    );
                    json!({"f":[]})
                } else {
                    assert_eq!(payload, json!([{"a":"g","g":1,"ssl":2,"p":"ABCDEFGH"}]));
                    if mode == "info-success" {
                        json!({"s":1024,"at":""})
                    } else {
                        json!(-9)
                    }
                };
                respond_and_observe_close(stream, 200, result);
                closed.try_send(()).unwrap();
            },
            |address| {
                let mut context = Context::test_peer(
                    scratch.path(),
                    Api::test_peer(address).unwrap(),
                    Output::with_writers(false, false, stdout.clone(), stderr.clone()),
                );
                let link = match mode {
                    "info-empty-folder" => "https://mega.nz/folder/ABCDEFGH#EBESExQVFhcYGRobHB0eHw",
                    "stream-rejected" => {
                        "https://mega.nz/file/ABCDEFGH#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                    }
                    _ => "https://mega.nz/file/ABCDEFGH",
                };
                let verb = if mode == "stream-rejected" {
                    "stream"
                } else {
                    "info"
                };
                let command = Cli::try_parse_from(["mb", verb, link])
                    .unwrap()
                    .command
                    .unwrap();
                let result = dispatch(&mut context, command);
                if matches!(mode, "info-rejected" | "stream-rejected") {
                    assert!(matches!(result, Err(Error::Mega { code: -9, .. })));
                    assert!(stdout.0.lock().unwrap().is_empty());
                    assert!(
                        stderr.0.lock().unwrap().is_empty(),
                        "setup failure announced a running service"
                    );
                } else {
                    assert_eq!(result.unwrap(), 0);
                    let text = String::from_utf8(stdout.0.lock().unwrap().clone()).unwrap();
                    assert!(text.contains(if mode == "info-success" {
                        "1024"
                    } else {
                        "Folder share"
                    }));
                }
                closure.recv_timeout(Duration::from_secs(2)).unwrap();
                assert_eq!(std::fs::read_dir(scratch.path()).unwrap().count(), 0);
                assert!(!context.control.is_canceled());
            },
        );
        assert_eq!(calls.len(), 1);
    }
}

#[test]
fn cloud_and_share_commands_release_responses_on_success_body_failure_and_login_rejection() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/client-lifecycle");
    std::fs::create_dir_all(&base).unwrap();
    for mode in [
        "cloud-success",
        "cloud-invalid-listing",
        "cloud-login-rejected",
        "share-login-rejected",
    ] {
        let scratch = crate::test_support::tempdir_in(&base).unwrap();
        seed_accounts(scratch.path(), &[(EMAIL, SID, 1024)]);
        let paths = Context::test_context(scratch.path()).paths;
        let login_rejected = mode.ends_with("login-rejected");
        if login_rejected {
            Sessions::new(paths.session(EMAIL)).forget().unwrap();
        }
        let before_accounts = std::fs::read(paths.accounts()).unwrap();
        let before_session = std::fs::read(paths.session(EMAIL)).ok();
        let stdout = Capture::default();
        let stderr = Capture::default();
        let (closed, closure) = mpsc::sync_channel(2);
        let ((), calls) = test_peer::with_raw_peer(
            |request, stream| {
                assert_eq!(request.method, "POST");
                let payload: Value = serde_json::from_slice(&request.body).unwrap();
                let url =
                    url::Url::parse(&format!("https://testserver.com{}", request.path)).unwrap();
                let result = if login_rejected {
                    assert_eq!(payload, json!([{"a":"us0","user":EMAIL}]));
                    assert!(!url.query_pairs().any(|(key, _)| key == "sid"));
                    json!(-9)
                } else {
                    assert!(
                        url.query_pairs()
                            .any(|(key, value)| key == "sid" && value == SID)
                    );
                    match payload[0]["a"].as_str().unwrap() {
                        "ug" => {
                            assert_eq!(payload, json!([{"a":"ug"}]));
                            json!({"u":"testuser"})
                        }
                        "f" => {
                            assert_eq!(payload, json!([{"a":"f","c":1}]));
                            if mode == "cloud-invalid-listing" {
                                json!({"f":"not-an-array"})
                            } else {
                                json!({"f":[{"h":"ROOT0001","t":2}]})
                            }
                        }
                        _ => panic!("ordinary cloud command ended or mutated its cached session"),
                    }
                };
                respond_and_observe_close(stream, 200, result);
                closed.try_send(()).unwrap();
            },
            |address| {
                let mut context = Context::test_peer(
                    scratch.path(),
                    Api::test_peer(address).unwrap(),
                    Output::with_writers(false, false, stdout.clone(), stderr.clone()),
                );
                let mut arguments = vec!["mb"];
                if mode == "share-login-rejected" {
                    arguments.extend(["share", "FOLDER01"]);
                } else {
                    arguments.push("ls");
                }
                arguments.extend(["--vault-passphrase", PASS]);
                let command = Cli::try_parse_from(arguments).unwrap().command.unwrap();
                let result = dispatch(&mut context, command);
                match mode {
                    "cloud-success" => {
                        assert_eq!(result.unwrap(), 0);
                        assert!(
                            String::from_utf8(stderr.0.lock().unwrap().clone())
                                .unwrap()
                                .contains("Cloud Drive is empty")
                        );
                    }
                    "cloud-invalid-listing" => assert!(matches!(result, Err(Error::Protocol(_)))),
                    _ => assert!(matches!(result, Err(Error::Mega { code: -9, .. }))),
                }
                for _ in 0..if login_rejected { 1 } else { 2 } {
                    closure.recv_timeout(Duration::from_secs(2)).unwrap();
                }
                assert_eq!(std::fs::read(paths.accounts()).unwrap(), before_accounts);
                assert_eq!(std::fs::read(paths.session(EMAIL)).ok(), before_session);
                assert!(stdout.0.lock().unwrap().is_empty());
                assert!(!paths.output.exists() && !paths.logs.exists());
            },
        );
        let actions: Vec<_> = calls
            .iter()
            .map(|request| {
                let payload: Value = serde_json::from_slice(&request.body).unwrap();
                payload[0]["a"].as_str().unwrap().to_owned()
            })
            .collect();
        assert_eq!(
            actions,
            if login_rejected {
                vec!["us0"]
            } else {
                vec!["ug", "f"]
            }
        );
        for capture in [&stdout, &stderr] {
            let text = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
            assert!(
                !text.contains(SID) && !text.contains(PASS) && !text.contains("synthetic password")
            );
        }
    }
}
