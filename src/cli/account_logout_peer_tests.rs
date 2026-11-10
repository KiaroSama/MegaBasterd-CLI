//! Explicit account logout ends only the selected cached session, never stored credentials.
#![allow(clippy::unwrap_used)]

use clap::Parser;
use serde_json::{Value, json};
use std::{fs, io::Write, path::Path, sync::mpsc, time::Duration};

use super::{
    args::Cli,
    auto_account_peer_tests::Capture,
    client_lifecycle_peer_tests::{observe_close, respond_and_observe_close},
    context::Context,
    dispatch,
};
use crate::{
    error::Error,
    protocol::{api::Api, auth::Session, test_peer},
    storage::{accounts::Accounts, files::Store, sessions::Sessions, vault::Vault},
    terminal::output::Output,
};

const EMAIL: &str = "logout-fixture@example.invalid";
const PASS: &str = "synthetic logout vault";

#[test]
fn parsed_logout_handles_missing_success_rejected_and_unreadable_sessions_without_fresh_login() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/account-logout");
    fs::create_dir_all(&base).unwrap();
    for mode in [
        "missing",
        "success",
        "rejected",
        "wrong-vault",
        "empty-passphrase",
        "future",
        "uncertain",
    ] {
        let scratch = tempfile::tempdir_in(&base).unwrap();
        let paths = Context::test_context(scratch.path()).paths;
        let accounts = Accounts::new(paths.accounts());
        let vault = Vault::new(PASS);
        accounts
            .add(EMAIL, "synthetic credential", None, true, &vault)
            .unwrap();
        if mode != "missing" {
            Sessions::new(paths.session(EMAIL))
                .remember(
                    &Session {
                        sid: "synthetic-logout-sid".into(),
                        master_key: [9; 16],
                        rsa_private_key: None,
                        user_handle: "synthetic-user".into(),
                        email: EMAIL.into(),
                    },
                    &vault,
                )
                .unwrap();
        }
        if mode == "future" {
            Store::new(paths.session(EMAIL))
                .lock()
                .unwrap()
                .write_bytes(br#"{"version":99,"data":{"encrypted":"preserve-future"}}"#)
                .unwrap();
        }
        let before_accounts = fs::read(paths.accounts()).unwrap();
        let before_session = fs::read(paths.session(EMAIL)).ok();
        let stdout = Capture::default();
        let stderr = Capture::default();
        let (closed, closure) = mpsc::sync_channel(1);
        let (_, calls) = test_peer::with_raw_peer(
            |request, stream| {
                assert!(matches!(mode, "success" | "rejected" | "uncertain"));
                let action: Value = serde_json::from_slice(&request.body).unwrap();
                assert_eq!(
                    action,
                    json!([{"a":"sml"}]),
                    "logout must not probe or log in first"
                );
                assert!(request.path.contains("sid=synthetic-logout-sid"));
                assert!(
                    matches!(
                        Store::new(paths.session(EMAIL))
                            .with_timeout(std::time::Duration::ZERO)
                            .lock(),
                        Err(Error::Busy(_))
                    ),
                    "logout must retain its cache lock until remote outcome and local cleanup"
                );
                respond_and_observe_close(
                    stream,
                    if mode == "uncertain" { 500 } else { 200 },
                    if mode == "rejected" {
                        json!(-11)
                    } else {
                        json!(0)
                    },
                );
                closed.try_send(()).unwrap();
            },
            |address| {
                let api = Api::test_peer(address).unwrap();
                let output = Output::with_writers(false, false, stdout.clone(), stderr.clone());
                let mut context = Context::test_peer(scratch.path(), api, output);
                let mut args = vec!["mb", "account", "logout", EMAIL];
                if mode != "missing" {
                    args.extend([
                        "--vault-passphrase",
                        match mode {
                            "wrong-vault" => "incorrect",
                            "empty-passphrase" => "",
                            _ => PASS,
                        },
                    ]);
                }
                let command = Cli::try_parse_from(args).unwrap().command.unwrap();
                let result = dispatch(&mut context, command);
                match mode {
                    "empty-passphrase" => assert!(matches!(result, Err(Error::Auth(_)))),
                    "future" => assert!(matches!(result, Err(Error::Corrupt(_)))),
                    "uncertain" => assert!(matches!(result, Err(Error::AmbiguousMutation(_)))),
                    _ => assert_eq!(result.unwrap(), 0),
                }
                if matches!(mode, "success" | "rejected" | "uncertain") {
                    closure.recv_timeout(Duration::from_secs(2)).unwrap();
                }
                if matches!(mode, "missing" | "success" | "rejected" | "wrong-vault") {
                    let repeat = Cli::try_parse_from(["mb", "account", "logout", EMAIL])
                        .unwrap()
                        .command
                        .unwrap();
                    assert_eq!(dispatch(&mut context, repeat).unwrap(), 0);
                    assert!(!paths.session(EMAIL).exists());
                }
                // The completed attempt must release the cache fence, including on uncertainty.
                let released = Store::new(paths.session(EMAIL))
                    .with_timeout(Duration::ZERO)
                    .lock()
                    .unwrap();
                drop(released);
                assert_eq!(fs::read(paths.accounts()).unwrap(), before_accounts);
                if matches!(mode, "future" | "uncertain" | "empty-passphrase") {
                    assert_eq!(
                        fs::read(paths.session(EMAIL)).unwrap(),
                        before_session.unwrap()
                    );
                } else {
                    assert!(!paths.session(EMAIL).exists());
                }
                assert!(stdout.0.lock().unwrap().is_empty());
                let messages = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
                if mode == "missing" {
                    assert!(
                        messages.contains("No stored session")
                            && messages.contains("account remove")
                    );
                }
                if mode == "wrong-vault" {
                    assert!(
                        messages.contains("could not be read")
                            && messages.contains("file removed only")
                    );
                }
                if mode == "rejected" {
                    assert!(messages.contains("cached session removed"));
                }
                for secret in ["synthetic-logout-sid", "synthetic credential", PASS] {
                    assert!(!messages.contains(secret));
                }
            },
        );
        assert_eq!(
            calls.len(),
            usize::from(matches!(mode, "success" | "rejected" | "uncertain"))
        );
    }
}

#[test]
fn sent_logout_uncertainty_releases_resources_without_replay_or_discarding_the_cache() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/account-logout");
    fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    let paths = Context::test_context(scratch.path()).paths;
    let vault = Vault::new(PASS);
    Accounts::new(paths.accounts())
        .add(EMAIL, "synthetic credential", None, true, &vault)
        .unwrap();
    Sessions::new(paths.session(EMAIL))
        .remember(
            &Session {
                sid: "synthetic-logout-sid".into(),
                master_key: [9; 16],
                rsa_private_key: None,
                user_handle: "synthetic-user".into(),
                email: EMAIL.into(),
            },
            &vault,
        )
        .unwrap();
    let before_accounts = fs::read(paths.accounts()).unwrap();
    let before_session = fs::read(paths.session(EMAIL)).unwrap();

    for fault in ["connection", "timeout", "http", "json", "shape", "gzip"] {
        let stdout = Capture::default();
        let stderr = Capture::default();
        let (closed, closure) = mpsc::sync_channel(1);
        let (backoff, waits) = mpsc::sync_channel(1);
        let ((), calls) = test_peer::with_raw_peer(
            |request, stream| {
                assert_eq!(request.method, "POST");
                assert_eq!(
                    serde_json::from_slice::<Value>(&request.body).unwrap(),
                    json!([{"a":"sml"}])
                );
                let url =
                    url::Url::parse(&format!("https://testserver.com{}", request.path)).unwrap();
                assert!(
                    url.query_pairs()
                        .any(|(key, value)| key == "sid" && value == "synthetic-logout-sid")
                );
                assert_eq!(
                    url.query_pairs().find(|(key, _)| key == "id").unwrap().1,
                    "1"
                );
                assert!(matches!(
                    Store::new(paths.session(EMAIL))
                        .with_timeout(Duration::ZERO)
                        .lock(),
                    Err(Error::Busy(_))
                ));
                match fault {
                    // Returning drops the peer socket after receiving the mutation, before headers.
                    "connection" => (),
                    "timeout" => observe_close(stream),
                    "http" => respond_and_observe_close(stream, 500, json!(0)),
                    _ => {
                        let body: &[u8] = match fault {
                            "json" => b"[",
                            "shape" => br#"{"unexpected":"object"}"#,
                            "gzip" => b"wrong",
                            _ => unreachable!(),
                        };
                        write!(stream,
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n{}\r\n",
                            body.len(),
                            if fault == "gzip" { "Content-Encoding: gzip\r\n" } else { "" }
                        ).unwrap();
                        stream.write_all(body).unwrap();
                        stream.flush().unwrap();
                        observe_close(stream);
                    }
                }
                closed.try_send(()).unwrap();
            },
            |address| {
                let mut api = Api::test_peer(address).unwrap();
                api.observe_backoffs(backoff);
                if fault == "timeout" {
                    api.transport.timeout = Duration::from_secs(1);
                }
                let mut context = Context::test_peer(
                    scratch.path(),
                    api,
                    Output::with_writers(false, false, stdout.clone(), stderr.clone()),
                );
                let command = Cli::try_parse_from([
                    "mb",
                    "account",
                    "logout",
                    EMAIL,
                    "--vault-passphrase",
                    PASS,
                ])
                .unwrap()
                .command
                .unwrap();
                let error = dispatch(&mut context, command).unwrap_err();
                assert!(matches!(&error, Error::AmbiguousMutation("sml")));
                assert_eq!(error.exit_code(), 1);
                assert!(!error.retryable_network());
                context.report_error(&error);
                closure.recv_timeout(Duration::from_secs(2)).unwrap();
                assert_eq!(waits.try_iter().count(), 0, "uncertain logout was retried");
                assert!(!context.control.is_canceled());
                assert_eq!(fs::read(paths.accounts()).unwrap(), before_accounts);
                assert_eq!(fs::read(paths.session(EMAIL)).unwrap(), before_session);
                let released = Store::new(paths.session(EMAIL))
                    .with_timeout(Duration::ZERO)
                    .lock()
                    .unwrap();
                drop(released);
                assert!(!paths.logs.exists() && !paths.output.exists());
                assert!(stdout.0.lock().unwrap().is_empty());
                let message = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
                assert!(message.contains("(sml)") && message.contains("not replayed"));
                for forbidden in [
                    "Sessions logged out",
                    "cached session removed",
                    "file removed only",
                    "synthetic-logout-sid",
                    "synthetic credential",
                    PASS,
                ] {
                    assert!(!message.contains(forbidden));
                }
            },
        );
        assert_eq!(
            calls.len(),
            1,
            "logout probed, logged in, or replayed its mutation"
        );
    }
}
