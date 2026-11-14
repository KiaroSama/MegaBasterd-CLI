//! Every parsed cloud command releases its responses without ending its cached session.
#![allow(clippy::unwrap_used)]

use std::{fs, path::Path, sync::mpsc, time::Duration};

use clap::Parser;
use serde_json::{Value, json};

use super::{
    args::Cli,
    auto_account_peer_tests::{Capture, seed_accounts},
    client_lifecycle_peer_tests::respond_and_observe_close,
    context::Context,
    dispatch,
};
use crate::{
    crypto::wire,
    protocol::{api::Api, test_peer},
    terminal::output::Output,
};

#[test]
fn parsed_share_import_accepts_empty_and_skips_only_unavailable_keys_before_mutating() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/import-listings");
    fs::create_dir_all(&base).unwrap();
    let scratch = crate::test_support::tempdir_in(base).unwrap();
    seed_accounts(scratch.path(), &[(EMAIL, SID, 1024)]);
    let paths = Context::test_context(scratch.path()).paths;
    let accounts = fs::read(paths.accounts()).unwrap();
    let session = fs::read(paths.session(EMAIL)).unwrap();
    let key = wire::b64_url_encode(&SHARE_KEY);
    for mode in ["empty", "skipped", "malformed", "missing-subpath"] {
        let imported = AtomicUsize::new(0);
        let stdout = Capture::default();
        let stderr = Capture::default();
        let (_, calls) = test_peer::with_peer(
            |request| {
                let commands: Value = serde_json::from_slice(&request.body).unwrap();
                let command = &commands[0];
                let result = match command["a"].as_str().unwrap() {
                    "ug" => json!({"u":"testuser"}),
                    "f" if command.get("r").is_some() => {
                        assert_eq!(commands, json!([{"a":"f","c":1,"r":1,"ca":1}]));
                        assert!(request.path.contains("n=ABCDEFGH"));
                        match mode {
                            "skipped" => {
                                let mut bad = folder("BAD00001", "SHARED01", "bad", &SHARE_KEY);
                                bad["k"] = json!("owner:!!!not-base64!!!");
                                let mut empty = folder("EMPTY001", "SHARED01", "empty", &SHARE_KEY);
                                empty["k"] = json!("");
                                json!({"f":[folder("SHARED01","outside","album",&SHARE_KEY),bad,empty,
                                    folder("GOOD0001","SHARED01","good",&SHARE_KEY)]})
                            }
                            "malformed" => json!({"f":[{"p":"outside","t":1}]}),
                            _ => json!({"f":[]}),
                        }
                    }
                    "f" => json!({"f":[{"h":"ROOT0001","t":2}]}),
                    "p" => {
                        assert_eq!(mode, "skipped", "empty or invalid share issued a mutation");
                        let index = imported.fetch_add(1, Ordering::Relaxed);
                        assert_eq!(command["sm"], 1);
                        assert_eq!(
                            command["n"][0]["h"],
                            if index == 0 { "SHARED01" } else { "GOOD0001" }
                        );
                        assert_eq!(
                            command["t"],
                            if index == 0 { "ROOT0001" } else { "NEWROOT1" }
                        );
                        json!({"f":[{"h":if index == 0 { "NEWROOT1" } else { "NEWGOOD1" }}]})
                    }
                    _ => panic!("unexpected import request"),
                };
                Some(test_peer::Response {
                    status: 200,
                    headers: vec![],
                    body: serde_json::to_vec(&json!([result])).unwrap(),
                })
            },
            |address| {
                let mut context = Context::test_peer(
                    scratch.path(),
                    Api::test_peer(address).unwrap(),
                    Output::with_writers(false, false, stdout.clone(), stderr.clone()),
                );
                let link = format!(
                    "https://mega.nz/folder/ABCDEFGH#{key}{}",
                    if mode == "missing-subpath" {
                        "/folder/ABSENT01"
                    } else {
                        ""
                    }
                );
                let command =
                    Cli::try_parse_from(["mb", "import", &link, "--vault-passphrase", PASS])
                        .unwrap()
                        .command
                        .unwrap();
                let result = dispatch(&mut context, command);
                if matches!(mode, "malformed" | "missing-subpath") {
                    let error = result.unwrap_err();
                    if mode == "missing-subpath" {
                        assert!(matches!(&error, crate::error::Error::Invalid(message)
                            if message == "Subfolder not found in the public share"));
                        assert_eq!(error.exit_code(), 2);
                    }
                    assert!(
                        !String::from_utf8(stderr.0.lock().unwrap().clone())
                            .unwrap()
                            .contains("Imported")
                    );
                } else {
                    assert_eq!(result.unwrap(), 0);
                    let diagnostic = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
                    assert!(diagnostic.contains(if mode == "empty" {
                        "Imported 0 node(s)."
                    } else {
                        "Imported 2 node(s)."
                    }));
                    if mode == "skipped" {
                        assert!(diagnostic.contains("BAD00001") && diagnostic.contains("EMPTY001"));
                        assert_eq!(diagnostic.matches("[WARNING]").count(), 2);
                    }
                    assert!(!diagnostic.contains(&key) && !diagnostic.contains(PASS));
                }
                assert!(stdout.0.lock().unwrap().is_empty());
                assert_eq!(fs::read(paths.accounts()).unwrap(), accounts);
                assert_eq!(fs::read(paths.session(EMAIL)).unwrap(), session);
            },
        );
        assert_eq!(
            imported.load(Ordering::Relaxed),
            if mode == "skipped" { 2 } else { 0 }
        );
        assert_eq!(calls.len(), if mode == "skipped" { 5 } else { 3 });
    }
}

const EMAIL: &str = "fixture@example.invalid";
const SID: &str = "synthetic-command-session";
const PASS: &str = "synthetic vault passphrase";
const MASTER: [u8; 16] = [9; 16];
const FOLDER_KEY: [u8; 16] = [7; 16];
const SHARE_KEY: [u8; 16] = [17; 16];

fn folder(handle: &str, parent: &str, name: &str, wrapping_key: &[u8]) -> Value {
    json!({"h":handle,"p":parent,"t":1,
        "k":wire::b64_url_encode(&wire::aes_key_wrap_encrypt(&FOLDER_KEY,wrapping_key).unwrap()),
        "a":wire::b64_url_encode(&wire::encrypt_attributes(&json!({"n":name}),&FOLDER_KEY).unwrap())})
}

#[test]
fn each_parsed_cloud_command_uses_shared_authentication_and_keeps_the_cached_session() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/cloud-lifecycle");
    fs::create_dir_all(&base).unwrap();
    let scratch = crate::test_support::tempdir_in(base).unwrap();
    seed_accounts(scratch.path(), &[(EMAIL, SID, 1024)]);
    let paths = Context::test_context(scratch.path()).paths;
    let before_accounts = fs::read(paths.accounts()).unwrap();
    let before_session = fs::read(paths.session(EMAIL)).unwrap();
    let listing = json!({"f":[
        {"h":"ROOT0001","t":2},
        folder("FOLDER01", "ROOT0001", "before", &MASTER),
        folder("DEST0001", "ROOT0001", "destination", &MASTER),
    ]});
    let share = json!({"f":[folder("SHARED01", "outside", "shared", &SHARE_KEY)]});
    let link = format!(
        "https://mega.nz/folder/ABCDEFGH#{}",
        wire::b64_url_encode(&SHARE_KEY)
    );

    for arguments in [
        vec!["mb", "ls"],
        vec!["mb", "mkdir", "new folder"],
        vec!["mb", "rm", "FOLDER01", "--yes"],
        vec!["mb", "mv", "FOLDER01", "DEST0001"],
        vec!["mb", "rename", "FOLDER01", "after"],
        vec!["mb", "search", "before"],
        vec!["mb", "import", link.as_str()],
    ] {
        let verb = arguments[1];
        let expected: &[&str] = match verb {
            "ls" | "search" => &["ug", "f"],
            "mkdir" => &["ug", "f", "p"],
            "rm" => &["ug", "f", "d"],
            "mv" => &["ug", "f", "m"],
            "rename" => &["ug", "f", "a"],
            "import" => &["ug", "f", "f", "p"],
            _ => unreachable!(),
        };
        let stdout = Capture::default();
        let stderr = Capture::default();
        let (closed, closure) = mpsc::sync_channel(expected.len());
        let mut actions = Vec::new();
        let ((), calls) = test_peer::with_raw_peer(
            |request, stream| {
                assert_eq!(request.method, "POST");
                let payload: Value = serde_json::from_slice(&request.body).unwrap();
                assert_eq!(payload.as_array().unwrap().len(), 1);
                let command = &payload[0];
                let action = command["a"].as_str().unwrap();
                actions.push(action.to_owned());
                assert_eq!(actions.last().unwrap(), expected[actions.len() - 1]);
                let url =
                    url::Url::parse(&format!("https://testserver.com{}", request.path)).unwrap();
                assert!(
                    url.query_pairs()
                        .any(|(key, value)| key == "sid" && value == SID)
                );
                assert_eq!(
                    url.query_pairs().find(|(key, _)| key == "id").unwrap().1,
                    actions.len().to_string()
                );
                let result = match action {
                    "ug" => {
                        assert_eq!(payload, json!([{"a":"ug"}]));
                        json!({"u":"testuser"})
                    }
                    "f" if command.get("r").is_some() => {
                        assert_eq!(verb, "import");
                        assert_eq!(payload, json!([{"a":"f","c":1,"r":1,"ca":1}]));
                        assert!(
                            url.query_pairs()
                                .any(|(key, value)| key == "n" && value == "ABCDEFGH")
                        );
                        share.clone()
                    }
                    "f" => {
                        assert_eq!(payload, json!([{"a":"f","c":1}]));
                        assert!(!url.query_pairs().any(|(key, _)| key == "n"));
                        listing.clone()
                    }
                    "p" => {
                        assert!(matches!(verb, "mkdir" | "import"));
                        assert_eq!(command["t"], "ROOT0001");
                        assert_eq!(command["n"].as_array().unwrap().len(), 1);
                        let node = &command["n"][0];
                        assert_eq!(node["t"], 1);
                        let key = wire::aes_key_wrap_decrypt(
                            &wire::b64_url_decode(node["k"].as_str().unwrap()).unwrap(),
                            &MASTER,
                        )
                        .unwrap();
                        assert_eq!(key.len(), 16);
                        let attrs = wire::decrypt_attributes(
                            &wire::b64_url_decode(node["a"].as_str().unwrap()).unwrap(),
                            &key,
                        )
                        .unwrap();
                        assert_eq!(
                            attrs,
                            json!({"n":if verb == "mkdir" {"new folder"} else {"shared"}})
                        );
                        if verb == "import" {
                            assert_eq!(node["h"], "SHARED01");
                            assert_eq!(command["sm"], 1);
                            assert_eq!(key, FOLDER_KEY);
                            assert!(
                                url.query_pairs()
                                    .any(|(key, value)| key == "n" && value == "ABCDEFGH")
                            );
                        } else {
                            assert_eq!(node["h"], "xxxxxxxx");
                            assert!(!url.query_pairs().any(|(key, _)| key == "n"));
                        }
                        json!({"f":[{"h":"NEW00001"}]})
                    }
                    "d" => {
                        assert_eq!(verb, "rm");
                        assert_eq!(payload, json!([{"a":"d","n":"FOLDER01"}]));
                        json!(0)
                    }
                    "m" => {
                        assert_eq!(verb, "mv");
                        assert_eq!(payload, json!([{"a":"m","n":"FOLDER01","t":"DEST0001"}]));
                        json!(0)
                    }
                    "a" => {
                        assert_eq!(verb, "rename");
                        assert_eq!(command["n"], "FOLDER01");
                        assert_eq!(
                            wire::aes_key_wrap_decrypt(
                                &wire::b64_url_decode(command["key"].as_str().unwrap()).unwrap(),
                                &MASTER
                            )
                            .unwrap(),
                            FOLDER_KEY
                        );
                        assert_eq!(
                            wire::decrypt_attributes(
                                &wire::b64_url_decode(command["attr"].as_str().unwrap()).unwrap(),
                                &FOLDER_KEY
                            )
                            .unwrap(),
                            json!({"n":"after"})
                        );
                        json!(0)
                    }
                    _ => {
                        panic!("cloud command bypassed cached authentication or ended its session")
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
                let mut arguments = arguments.clone();
                arguments.extend(["--vault-passphrase", PASS]);
                let command = Cli::try_parse_from(arguments).unwrap().command.unwrap();
                assert_eq!(dispatch(&mut context, command).unwrap(), 0);
                for _ in expected {
                    closure.recv_timeout(Duration::from_secs(2)).unwrap();
                }
                // These assertions run while the enclosing Context and its peer API remain alive.
                assert_eq!(fs::read(paths.accounts()).unwrap(), before_accounts);
                assert_eq!(fs::read(paths.session(EMAIL)).unwrap(), before_session);
                assert!(!paths.output.exists() && !paths.logs.exists());
                assert!(!paths.config().exists() && !paths.queue().exists());
                assert!(!context.control.is_canceled());
                let out = String::from_utf8(stdout.0.lock().unwrap().clone()).unwrap();
                let diagnostic = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
                match verb {
                    "ls" | "search" => assert!(out.contains("before")),
                    "import" => assert!(diagnostic.contains("Imported 1 node(s).")),
                    "mkdir" => assert!(diagnostic.contains("Folder created: NEW00001")),
                    "rm" => assert!(diagnostic.contains("Cloud node deleted.")),
                    "mv" => assert!(diagnostic.contains("Cloud node moved.")),
                    "rename" => assert!(diagnostic.contains("Cloud node renamed.")),
                    _ => unreachable!(),
                }
                for text in [&out, &diagnostic] {
                    for secret in [EMAIL, SID, PASS, "synthetic password"] {
                        assert!(!text.contains(secret));
                    }
                    assert!(!text.contains("logged out") && !text.contains("Login failed"));
                }
            },
        );
        assert_eq!(actions, expected);
        assert_eq!(calls.len(), expected.len());
    }
}
