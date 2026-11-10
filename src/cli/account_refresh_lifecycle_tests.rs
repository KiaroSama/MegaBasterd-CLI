//! Refresh every stored account without retaining any of its HTTP responses.
#![allow(clippy::unwrap_used)]

use clap::Parser;
use serde_json::{Value, json};
use std::{fs, path::Path, sync::mpsc, time::Duration};

use super::{
    args::Cli,
    auto_account_peer_tests::{Capture, seed_accounts},
    client_lifecycle_peer_tests::respond_and_observe_close,
    context::Context,
    dispatch,
};
use crate::{
    protocol::{api::Api, test_peer},
    terminal::output::Output,
};

#[test]
fn parsed_refresh_all_releases_each_account_response_before_context_drop() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/account-refresh-lifecycle");
    fs::create_dir_all(&base).unwrap();
    let scratch = crate::test_support::tempdir_in(base).unwrap();
    let choices = [
        ("a@example.invalid", "refresh-session-a", 4096),
        ("b@example.invalid", "refresh-session-b", 8192),
    ];
    seed_accounts(scratch.path(), &choices);
    let paths = Context::test_context(scratch.path()).paths;
    let accounts = crate::storage::accounts::Accounts::new(paths.accounts());
    let mut expected = serde_json::to_value(accounts.list().unwrap()).unwrap();
    let cached: Vec<_> = choices
        .iter()
        .map(|(email, _, _)| fs::read(paths.session(email)).unwrap())
        .collect();
    let stdout = Capture::default();
    let stderr = Capture::default();
    let (closed, closure) = mpsc::sync_channel(4);
    let mut index = 0;
    let ((), calls) = test_peer::with_raw_peer(
        |request, stream| {
            assert!(
                index < 4,
                "refresh opened an unexpected additional response"
            );
            let account = index / 2;
            let action = if index % 2 == 0 { "ug" } else { "uq" };
            assert_eq!(request.method, "POST");
            let url = url::Url::parse(&format!("https://testserver.com{}", request.path)).unwrap();
            let query: Vec<_> = url
                .query_pairs()
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect();
            assert_eq!(query.iter().filter(|(key, _)| key == "sid").count(), 1);
            assert!(
                query
                    .iter()
                    .any(|(key, value)| key == "sid" && value == choices[account].1)
            );
            assert_eq!(query.iter().filter(|(key, _)| key == "id").count(), 1);
            assert!(
                query
                    .iter()
                    .any(|(key, value)| key == "id" && value == &(index % 2 + 1).to_string())
            );
            assert_eq!(
                serde_json::from_slice::<Value>(&request.body).unwrap(),
                if action == "ug" {
                    json!([{"a":"ug"}])
                } else {
                    json!([{"a":"uq","strg":1,"xfer":1}])
                }
            );
            let result = if action == "ug" {
                json!({"u":"testuser"})
            } else {
                json!({"mstrg":16384u64 << account,"cstrg":1024u64 << account})
            };
            respond_and_observe_close(stream, 200, result);
            closed.try_send(index).unwrap();
            index += 1;
        },
        |address| {
            let mut context = Context::test_peer(
                scratch.path(),
                Api::test_peer(address).unwrap(),
                Output::with_writers(false, true, stdout.clone(), stderr.clone()),
            );
            let command = Cli::try_parse_from([
                "mb",
                "-q",
                "account",
                "refresh-all",
                "--vault-passphrase",
                "synthetic vault passphrase",
            ])
            .unwrap()
            .command
            .unwrap();
            assert_eq!(dispatch(&mut context, command).unwrap(), 0);
            for expected in 0..4 {
                assert_eq!(
                    closure.recv_timeout(Duration::from_secs(2)).unwrap(),
                    expected
                );
            }
            let updated = serde_json::to_value(accounts.list().unwrap()).unwrap();
            for (index, (email, _, _)) in choices.iter().enumerate() {
                let stamp = updated["accounts"][index]["last_used_iso"]
                    .as_str()
                    .unwrap();
                chrono::DateTime::parse_from_rfc3339(stamp).unwrap();
                expected["accounts"][index]["quota_total"] = json!(16384u64 << index);
                expected["accounts"][index]["quota_used"] = json!(1024u64 << index);
                expected["accounts"][index]["last_used_iso"] = json!(stamp);
                assert_eq!(fs::read(paths.session(email)).unwrap(), cached[index]);
            }
            assert_eq!(
                updated, expected,
                "refresh changed unrelated account fields"
            );
            assert!(stdout.0.lock().unwrap().is_empty());
            assert!(stderr.0.lock().unwrap().is_empty());
            assert!(!context.control.is_canceled());
            assert!(!paths.output.exists() && !paths.logs.exists());
            assert!(!paths.queue().exists() && !paths.config().exists());
        },
    );
    assert_eq!(calls.len(), 4);
    assert_eq!(index, 4);
}
