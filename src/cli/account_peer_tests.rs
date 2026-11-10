//! Parsed account verification preserves credentials while refreshing only the proven session.
#![allow(clippy::unwrap_used)]

use clap::Parser;
use serde_json::{Value, json};
use std::{fs, path::Path};

use super::{args::Cli, auto_account_peer_tests::Capture, context::Context, dispatch};
use crate::{
    crypto::wire,
    error::Error,
    protocol::{
        api::Api,
        test_peer::{self, Response},
    },
    storage::{accounts::Accounts, sessions::Sessions, vault::Vault},
    terminal::output::Output,
};

const EMAIL: &str = "fixture@example.invalid";
const PASSPHRASE: &str = "synthetic vault passphrase";

fn command(verify: bool) -> super::args::Command {
    let mut args = vec![
        "mb",
        "account",
        "add",
        "Fixture@Example.Invalid",
        "--password",
        "source-fixture",
        "--vault-passphrase",
        PASSPHRASE,
        "--label",
        "replacement label",
        "--default",
    ];
    if !verify {
        args.push("--no-verify");
    }
    Cli::try_parse_from(args).unwrap().command.unwrap()
}

#[test]
fn rejected_verification_declines_without_stores_and_only_explicit_consent_adds_unverified() {
    use std::io::Cursor;

    for (input, accepted) in [
        (b"n\n".as_slice(), false),
        (b"", false),
        (b"\n", false),
        (b"what\ny\n", true),
    ] {
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/account-add-peers");
        fs::create_dir_all(&base).unwrap();
        let scratch = tempfile::tempdir_in(base).unwrap();
        let stdout = Capture::default();
        let stderr = Capture::default();
        let (_, calls) = test_peer::with_peer(
            |request| {
                let body: Value = serde_json::from_slice(&request.body).unwrap();
                assert_eq!(body, json!([{"a":"us0","user":EMAIL}]));
                Some(Response {
                    status: 200,
                    headers: vec![],
                    body: b"[-9]".to_vec(),
                })
            },
            |address| {
                let output = Output::with_writers(false, false, stdout.clone(), stderr.clone());
                let mut context =
                    Context::test_peer(scratch.path(), Api::test_peer(address).unwrap(), output);
                let mut answers = Cursor::new(input);
                let mut prompted = 0;
                super::accounts::dispatch_with_confirmation(
                    &mut context,
                    match command(true) {
                        super::args::Command::Account(account) => account,
                        _ => unreachable!(),
                    },
                    || {
                        prompted += 1;
                        crate::terminal::prompts::confirmed_with_io(
                            "Add account anyway?",
                            false,
                            &mut answers,
                            &mut stderr.clone(),
                        )
                    },
                )
                .unwrap();
                assert_eq!(prompted, 1);
                assert!(!context.paths.session(EMAIL).exists());
                assert_eq!(
                    context.accounts().list().unwrap().accounts.len(),
                    usize::from(accepted)
                );
                assert_eq!(context.paths.accounts().is_file(), accepted);
                if accepted {
                    let stored = context.accounts().find(Some(EMAIL)).unwrap();
                    assert_eq!(
                        &*Accounts::password(&stored, &Vault::new(PASSPHRASE)).unwrap(),
                        "source-fixture"
                    );
                }
                assert!(stdout.0.lock().unwrap().is_empty());
                let messages = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
                assert!(messages.contains("Login verification failed"));
                assert!(
                    !messages.contains("session refreshed") && !messages.contains("source-fixture")
                );
                if !accepted {
                    assert!(messages.contains("Cancelled"));
                }
            },
        );
        assert_eq!(
            calls.len(),
            1,
            "failed verification must not log out or repeat login"
        );
    }
}

#[test]
fn parsed_account_batches_preserve_cache_and_distinguish_probe_cancel_from_logout_uncertainty() {
    use crate::protocol::auth::Session;

    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/account-add-peers");
    fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    let paths = Context::test_context(scratch.path()).paths;
    let vault = Vault::new(PASSPHRASE);
    let accounts = Accounts::new(paths.accounts());
    for email in [EMAIL, "other@example.invalid"] {
        accounts
            .add(email, "synthetic password", None, false, &vault)
            .unwrap();
        Sessions::new(paths.session(email))
            .remember(
                &Session {
                    sid: "synthetic-cached-sid".into(),
                    master_key: [7; 16],
                    rsa_private_key: None,
                    user_handle: "synthetic-user".into(),
                    email: email.into(),
                },
                &vault,
            )
            .unwrap();
    }
    let before_accounts = fs::read(paths.accounts()).unwrap();
    let before_sessions: Vec<_> = [EMAIL, "other@example.invalid"]
        .iter()
        .map(|email| fs::read(paths.session(email)).unwrap())
        .collect();
    for logout in [false, true] {
        for during_request in [false, true] {
            let stdout = Capture::default();
            let stderr = Capture::default();
            let (cancel, cancellation) =
                std::sync::mpsc::sync_channel::<crate::transfers::control::Control>(1);
            let ((), calls) = test_peer::with_raw_peer(
                move |request, stream| {
                    use std::io::Read;
                    assert!(during_request, "canceled batch reached the API");
                    let action: Value = serde_json::from_slice(&request.body).unwrap();
                    assert_eq!(action, json!([{"a":if logout { "sml" } else { "ug" }}]));
                    assert!(request.path.contains("sid=synthetic-cached-sid"));
                    cancellation
                        .recv_timeout(std::time::Duration::from_secs(2))
                        .unwrap()
                        .cancel();
                    // Withhold the response: the same API Control must interrupt real network I/O.
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
                        result => {
                            panic!("canceled account request retained its socket: {result:?}")
                        }
                    }
                },
                |address| {
                    let api = Api::test_peer(address).unwrap();
                    let output = Output::with_writers(false, false, stdout.clone(), stderr.clone());
                    let mut context = Context::test_peer(scratch.path(), api, output);
                    let control = context.control.clone();
                    cancel.send(control.clone()).unwrap();
                    let mut argv = vec![
                        "mb",
                        "account",
                        if logout { "logout" } else { "refresh-all" },
                        "--vault-passphrase",
                        PASSPHRASE,
                    ];
                    if logout {
                        argv.push("--all");
                    }
                    let command = Cli::try_parse_from(argv).unwrap().command.unwrap();
                    if !during_request {
                        control.cancel();
                    }
                    let result = dispatch(&mut context, command);
                    if logout && during_request {
                        assert!(matches!(result, Err(Error::AmbiguousMutation(_))));
                    } else {
                        assert!(matches!(result, Err(Error::Canceled)));
                    }
                    assert_eq!(fs::read(paths.accounts()).unwrap(), before_accounts);
                    for (index, email) in [EMAIL, "other@example.invalid"].iter().enumerate() {
                        assert_eq!(
                            fs::read(paths.session(email)).unwrap(),
                            before_sessions[index]
                        );
                    }
                    assert!(stdout.0.lock().unwrap().is_empty());
                    let messages = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
                    assert!(
                        !messages.contains("All account quotas refreshed")
                            && !messages.contains("Sessions logged out")
                    );
                },
            );
            assert_eq!(calls.len(), usize::from(during_request));
        }
    }
}

#[test]
fn optional_session_cache_failure_preserves_authentication_and_does_not_claim_a_refresh() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/account-add-peers");
    fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    let stdout = Capture::default();
    let stderr = Capture::default();
    let output = Output::with_writers(false, false, stdout.clone(), stderr.clone());
    let (_, calls) = test_peer::with_peer(
        |_| panic!("cache write must not contact MEGA"),
        |address| {
            let context =
                Context::test_peer(scratch.path(), Api::test_peer(address).unwrap(), output);
            let session = crate::protocol::auth::Session {
                sid: "synthetic-session".into(),
                master_key: [7; 16],
                rsa_private_key: None,
                user_handle: "synthetic-user".into(),
                email: EMAIL.into(),
            };
            let path = context.paths.session(EMAIL);
            fs::create_dir_all(&path).unwrap();
            fs::write(path.join("precious"), b"preserve this obstruction").unwrap();
            assert!(!context.remember_session(&session, &Vault::new(PASSPHRASE)));
            assert_eq!(
                fs::read(path.join("precious")).unwrap(),
                b"preserve this obstruction"
            );
            assert_eq!(session.sid, "synthetic-session");
            assert!(stdout.0.lock().unwrap().is_empty());
            let messages = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
            assert!(messages.contains("could not be cached") && messages.contains("next command"));
            assert!(
                !messages.contains("synthetic-session") && !messages.contains("session refreshed")
            );
        },
    );
    assert!(calls.is_empty());
}

#[test]
fn parsed_account_add_missing_mfa_fails_without_offering_unverified_storage_in_machine_mode() {
    let data: Value =
        serde_json::from_str(include_str!("../../tests/fixtures/crypto-vectors.json")).unwrap();
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/account-add-peers");
    fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    let stdout = Capture::default();
    let stderr = Capture::default();
    let ((), calls) = test_peer::with_peer(
        |request| {
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            let reply = match body[0]["a"].as_str().unwrap() {
                "us0" => json!({"v":2,"s":wire::b64_url_encode(
                    &hex::decode(data["kdf_v2"][2]["salt"].as_str().unwrap()).unwrap()
                )}),
                "us" => {
                    assert!(body[0].get("mfa").is_none());
                    json!(-26)
                }
                _ => panic!("missing MFA must not send another request"),
            };
            Some(Response {
                status: 200,
                headers: vec![],
                body: serde_json::to_vec(&json!([reply])).unwrap(),
            })
        },
        |address| {
            let output = Output::with_writers(true, false, stdout.clone(), stderr.clone());
            let mut context =
                Context::test_peer(scratch.path(), Api::test_peer(address).unwrap(), output);
            let super::args::Command::Account(account) = command(true) else {
                unreachable!()
            };
            let error = super::accounts::dispatch_with_confirmation(&mut context, account, || {
                panic!("missing MFA input must not become consent to save an unverified account")
            })
            .unwrap_err();
            assert!(matches!(&error, Error::Auth(message) if message.contains("--mfa-code")));
            assert_eq!(error.exit_code(), 1);
            context.report_error(&error);
            assert!(!context.paths.accounts().exists());
            assert!(!context.paths.session(EMAIL).exists());
            assert!(!context.paths.user.exists());
        },
    );
    let actions: Vec<_> = calls
        .iter()
        .map(|request| {
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            body[0]["a"].as_str().unwrap().to_owned()
        })
        .collect();
    assert_eq!(actions, ["us0", "us"]);
    let machine: Value = serde_json::from_slice(&stdout.0.lock().unwrap()).unwrap();
    assert_eq!(machine["error_code"], "auth_failed");
    assert!(machine["error"].as_str().unwrap().contains("--mfa-code"));
    let messages = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
    assert!(!messages.contains("Add account anyway"));
    assert!(!messages.contains("source-fixture") && !messages.contains(PASSPHRASE));
}

#[test]
fn parsed_verified_duplicate_keeps_account_bytes_and_refreshes_session_without_remote_logout() {
    let data: Value =
        serde_json::from_str(include_str!("../../tests/fixtures/crypto-vectors.json")).unwrap();
    let derived = hex::decode(data["kdf_v2"][2]["derived"].as_str().unwrap()).unwrap();
    let master = hex::decode(data["rsa"]["master_key"].as_str().unwrap()).unwrap();
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/account-add-peers");
    fs::create_dir_all(&base).unwrap();
    for (existing, cache_failure) in [(false, false), (true, false), (false, true), (true, true)] {
        let scratch = tempfile::tempdir_in(&base).unwrap();
        let paths = Context::test_context(scratch.path()).paths;
        let accounts = Accounts::new(paths.accounts());
        let vault = Vault::new(PASSPHRASE);
        let before = if existing {
            assert!(
                accounts
                    .add(
                        EMAIL,
                        "original account password",
                        Some("original label".into()),
                        false,
                        &vault
                    )
                    .unwrap()
            );
            accounts.quota(EMAIL, 8192, 2048).unwrap();
            assert!(
                accounts
                    .add(
                        "other@example.invalid",
                        "other password",
                        None,
                        true,
                        &vault
                    )
                    .unwrap()
            );
            Some(fs::read(paths.accounts()).unwrap())
        } else {
            None
        };
        if cache_failure {
            fs::create_dir_all(paths.session(EMAIL)).unwrap();
            fs::write(
                paths.session(EMAIL).join("precious"),
                b"preserve this obstruction",
            )
            .unwrap();
        }
        let stdout = Capture::default();
        let stderr = Capture::default();
        let ((), calls) = test_peer::with_peer(
            |request| {
                assert_eq!(request.method, "POST");
                let body: Value = serde_json::from_slice(&request.body).unwrap();
                assert_eq!(body.as_array().unwrap().len(), 1);
                let action = &body[0];
                let url =
                    url::Url::parse(&format!("https://testserver.com{}", request.path)).unwrap();
                let reply = match action["a"].as_str().unwrap() {
                    "us0" => {
                        assert_eq!(action["user"], EMAIL);
                        assert!(!url.query_pairs().any(|(key, _)| key == "sid"));
                        json!({"v":2,"s":wire::b64_url_encode(&hex::decode(data["kdf_v2"][2]["salt"].as_str().unwrap()).unwrap())})
                    }
                    "us" => {
                        assert_eq!(action["uh"], wire::b64_url_encode(&derived[16..]));
                        assert!(!url.query_pairs().any(|(key, _)| key == "sid"));
                        json!({"u":"AQIDBAUGBwg","k":wire::b64_url_encode(&wire::aes_key_wrap_encrypt(&master,&derived[..16]).unwrap()),
                            "privk":wire::b64_url_encode(&hex::decode(data["rsa"]["wrapped_private"].as_str().unwrap()).unwrap()),
                            "csid":wire::b64_url_encode(&hex::decode(data["rsa"]["csid"].as_str().unwrap()).unwrap())})
                    }
                    "ug" => {
                        assert!(url.query_pairs().any(|(key, value)| key == "sid"
                            && value == data["rsa"]["sid"].as_str().unwrap()));
                        json!({"u":"AQIDBAUGBwg"})
                    }
                    _ => panic!("account add must not log out or mutate the remote account"),
                };
                Some(Response {
                    status: 200,
                    headers: vec![("Content-Type".into(), "application/json".into())],
                    body: serde_json::to_vec(&json!([reply])).unwrap(),
                })
            },
            |address| {
                let api = Api::test_peer(address).unwrap();
                let output = Output::with_writers(false, false, stdout.clone(), stderr.clone());
                let mut context = Context::test_peer(scratch.path(), api, output);
                assert_eq!(dispatch(&mut context, command(true)).unwrap(), 0);
                let sealed = if cache_failure {
                    assert_eq!(
                        fs::read(paths.session(EMAIL).join("precious")).unwrap(),
                        b"preserve this obstruction"
                    );
                    let messages = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
                    assert!(messages.contains("could not be cached"));
                    assert!(!messages.contains("session refreshed"));
                    None
                } else {
                    assert!(paths.session(EMAIL).is_file());
                    let sealed = fs::read(paths.session(EMAIL)).unwrap();
                    let raw = std::str::from_utf8(&sealed).unwrap();
                    for secret in [
                        EMAIL,
                        "source-fixture",
                        PASSPHRASE,
                        data["rsa"]["sid"].as_str().unwrap(),
                        "master_key",
                    ] {
                        assert!(!raw.contains(secret));
                    }
                    assert!(
                        !paths
                            .session(EMAIL)
                            .file_name()
                            .unwrap()
                            .to_string_lossy()
                            .contains("fixture")
                    );
                    let mut restored_api = context.api(None).unwrap();
                    let restored = Sessions::new(paths.session(EMAIL))
                        .restore(EMAIL, &vault, &mut restored_api)
                        .unwrap()
                        .unwrap();
                    assert_eq!(restored.sid, data["rsa"]["sid"].as_str().unwrap());
                    assert_eq!(restored.master_key.as_slice(), master);
                    assert_eq!(restored.email, EMAIL);
                    assert_eq!(fs::read(paths.session(EMAIL)).unwrap(), sealed);
                    Some(sealed)
                };
                let stored = accounts.find(Some(EMAIL)).unwrap();
                assert_eq!(
                    &*Accounts::password(&stored, &vault).unwrap(),
                    if existing {
                        "original account password"
                    } else {
                        "source-fixture"
                    }
                );
                if let Some(before) = &before {
                    assert_eq!(fs::read(paths.accounts()).unwrap(), *before);
                    assert_eq!(stored.label.as_deref(), Some("original label"));
                    assert_eq!(
                        (stored.quota_total, stored.quota_used),
                        (Some(8192), Some(2048))
                    );
                    assert_eq!(
                        accounts.list().unwrap().default_email.as_deref(),
                        Some("other@example.invalid")
                    );
                    let message = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
                    assert!(
                        message.contains("already stored")
                            && message.contains(if cache_failure {
                                "session was not cached"
                            } else {
                                "session refreshed"
                            })
                    );
                } else {
                    assert_eq!(accounts.list().unwrap().accounts.len(), 1);
                }
                assert!(stdout.0.lock().unwrap().is_empty());
                let messages = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
                for secret in [
                    "source-fixture",
                    PASSPHRASE,
                    data["rsa"]["sid"].as_str().unwrap(),
                ] {
                    assert!(!messages.contains(secret));
                }
                let before_accounts = fs::read(paths.accounts()).unwrap();
                let before_session = sealed;
                assert!(
                    matches!(dispatch(&mut context, command(false)), Err(Error::Invalid(message)) if message.contains("already exists"))
                );
                assert_eq!(fs::read(paths.accounts()).unwrap(), before_accounts);
                if let Some(before_session) = before_session {
                    assert_eq!(fs::read(paths.session(EMAIL)).unwrap(), before_session);
                } else {
                    assert_eq!(
                        fs::read(paths.session(EMAIL).join("precious")).unwrap(),
                        b"preserve this obstruction"
                    );
                }
            },
        );
        assert_eq!(calls.len(), if cache_failure { 3 } else { 4 });
        let actions: Vec<_> = calls
            .iter()
            .map(|request| {
                let payload: Value = serde_json::from_slice(&request.body).unwrap();
                payload[0]["a"].as_str().unwrap().to_owned()
            })
            .collect();
        assert_eq!(
            actions,
            if cache_failure {
                vec!["us0", "us", "ug"]
            } else {
                vec!["us0", "us", "ug", "ug"]
            }
        );
    }
}
