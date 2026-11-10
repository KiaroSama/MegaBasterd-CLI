//! Optional quota rejection preserves saved data without retaining live responses.
#![allow(clippy::unwrap_used)]

use clap::Parser;
use serde_json::{Value, json};
use std::{fs, path::Path, sync::mpsc, time::Duration};

use crate::{
    cli::{
        args::Cli,
        auto_account_peer_tests::{Capture, seed_accounts},
        client_lifecycle_peer_tests::respond_and_observe_close,
        context::Context,
        dispatch,
    },
    error::Error,
    protocol::{api::Api, test_peer},
    terminal::output::Output,
};

const EMAIL: &str = "info-fixture@example.invalid";
const SID: &str = "synthetic-account-info-sid";
const PASS: &str = "synthetic vault passphrase";

#[test]
fn parsed_account_info_preserves_saved_quota_on_rejection_and_releases_responses() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/account-info");
    fs::create_dir_all(&base).unwrap();
    let scratch = crate::test_support::tempdir_in(base).unwrap();
    seed_accounts(scratch.path(), &[(EMAIL, SID, 4096)]);
    let paths = Context::test_context(scratch.path()).paths;
    Context::test_context(scratch.path())
        .accounts()
        .set_default(EMAIL)
        .unwrap();
    // Reuse one encrypted fixture, but never let the success control seed a failure's quota.
    for mode in [
        "quota-rejected",
        "quiet-default-quota-rejected",
        "user-rejected",
        "session-expired",
        "invalid-quota",
        "success",
    ] {
        let before_accounts = fs::read(paths.accounts()).unwrap();
        let before_session = fs::read(paths.session(EMAIL)).unwrap();
        let stdout = Capture::default();
        let stderr = Capture::default();
        let (closed, closure) = mpsc::sync_channel(3);
        let ((), calls) = test_peer::with_raw_peer(
            |request, stream| {
                assert_eq!(request.method, "POST");
                let payload: Value = serde_json::from_slice(&request.body).unwrap();
                let url =
                    url::Url::parse(&format!("https://testserver.com{}", request.path)).unwrap();
                let query: std::collections::BTreeMap<_, _> = url
                    .query_pairs()
                    .map(|(key, value)| (key.into_owned(), value.into_owned()))
                    .collect();
                assert_eq!(query["sid"], SID);
                let result = match query["id"].as_str() {
                    "1" => {
                        assert_eq!(payload, json!([{"a":"ug"}]));
                        json!({"u":"testuser"})
                    }
                    "2" => {
                        assert_eq!(payload, json!([{"a":"ug"}]));
                        if mode == "user-rejected" {
                            json!(-11)
                        } else {
                            json!({"u":"testuser","name":"Truthful Fixture"})
                        }
                    }
                    "3" => {
                        assert_ne!(mode, "user-rejected");
                        assert_eq!(payload, json!([{"a":"uq","strg":1,"xfer":1}]));
                        match mode {
                            "quota-rejected" | "quiet-default-quota-rejected" => json!(-11),
                            "session-expired" => json!(-15),
                            "invalid-quota" => json!({"mstrg":"invalid","cstrg":1024}),
                            _ => json!({"mstrg":8192,"cstrg":1024}),
                        }
                    }
                    _ => panic!(
                        "account info retried, logged in, logged out, or sent another request"
                    ),
                };
                // This helper advertises keep-alive and waits for client EOF/reset before returning.
                respond_and_observe_close(stream, 200, result);
                closed.try_send(()).unwrap();
            },
            |address| {
                let mut context = Context::test_peer(
                    scratch.path(),
                    Api::test_peer(address).unwrap(),
                    Output::with_writers(
                        false,
                        mode == "quiet-default-quota-rejected",
                        stdout.clone(),
                        stderr.clone(),
                    ),
                );
                let arguments = if mode == "quiet-default-quota-rejected" {
                    vec!["mb", "-q", "account", "info", "--vault-passphrase", PASS]
                } else {
                    vec!["mb", "account", "info", EMAIL, "--vault-passphrase", PASS]
                };
                let command = Cli::try_parse_from(arguments).unwrap().command.unwrap();
                let result = dispatch(&mut context, command);
                match mode {
                    "user-rejected" => {
                        assert!(matches!(result, Err(Error::Mega { code: -11, .. })))
                    }
                    "session-expired" => {
                        assert!(matches!(result, Err(Error::Mega { code: -15, .. })))
                    }
                    "invalid-quota" => assert!(matches!(result, Err(Error::Protocol(_)))),
                    _ => assert_eq!(result.unwrap(), 0),
                }
                let expected_requests = if mode == "user-rejected" { 2 } else { 3 };
                for _ in 0..expected_requests {
                    closure.recv_timeout(Duration::from_secs(2)).unwrap();
                }
                assert_eq!(closure.try_iter().count(), 0);
                // Observe release before the parent Context (and its fixture API template) drops.
                assert!(!context.control.is_canceled());
                assert_eq!(fs::read(paths.session(EMAIL)).unwrap(), before_session);
                if mode == "success" {
                    let account = context.accounts().find(Some(EMAIL)).unwrap();
                    assert_eq!(
                        (account.quota_total, account.quota_used),
                        (Some(8192), Some(1024))
                    );
                } else {
                    assert_eq!(fs::read(paths.accounts()).unwrap(), before_accounts);
                    let account = context.accounts().find(Some(EMAIL)).unwrap();
                    assert_eq!(
                        (account.quota_total, account.quota_used),
                        (Some(4096), Some(0))
                    );
                }
                assert!(!paths.logs.exists() && !paths.output.exists());
            },
        );
        assert_eq!(calls.len(), if mode == "user-rejected" { 2 } else { 3 });
        let info = String::from_utf8(stdout.0.lock().unwrap().clone()).unwrap();
        let diagnostic = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
        if mode == "success" {
            assert!(info.contains(&format!("Email | {EMAIL}\n")));
            assert!(info.contains("Name | Truthful Fixture\n"));
            assert!(info.contains("Total storage | 8.00 KB\n"));
            assert!(info.contains("Used storage | 1.00 KB\n"));
            assert!(diagnostic.is_empty());
        } else if matches!(mode, "quota-rejected" | "quiet-default-quota-rejected") {
            assert!(
                info.is_empty(),
                "failed quota produced a partial account table"
            );
            assert!(
                diagnostic
                    == "[ERROR] Could not fetch quota; saved account information was kept.\n"
            );
        } else {
            assert!(
                info.is_empty(),
                "authentication or malformed quota became successful info"
            );
            assert!(
                diagnostic.is_empty(),
                "fatal errors were handled as optional quota failures"
            );
        }
        for text in [&info, &diagnostic] {
            for secret in [SID, PASS, "synthetic password"] {
                assert!(!text.contains(secret));
            }
        }
    }
}
