//! Parsed public-share commands retain key skipping and subtree selection through the real CLI seam.
#![allow(clippy::unwrap_used)]

use std::{collections::BTreeSet, fs, path::Path};

use clap::Parser;
use serde_json::{Value, json};

use super::{
    args::Cli,
    auto_account_peer_tests::{Capture, seed_accounts},
    context::Context,
    dispatch,
};
use crate::{
    crypto::{keys, wire},
    error::Error,
    protocol::{
        api::Api,
        test_peer::{self, Response},
    },
    terminal::output::Output,
};

const EMAIL: &str = "fixture@example.invalid";
const SID: &str = "share-command-session";
const PASS: &str = "synthetic vault passphrase";
const MASTER: [u8; 16] = [9; 16];
const SHARE: [u8; 16] = [7; 16];

fn scratch() -> crate::test_support::TempDir {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/share-commands");
    fs::create_dir_all(&base).unwrap();
    crate::test_support::tempdir_in(base).unwrap()
}

fn node(handle: &str, parent: &str, kind: u8, name: &str) -> Value {
    let raw = vec![if kind == 0 { 3 } else { 5 }; if kind == 0 { 32 } else { 16 }];
    let attribute_key = if kind == 0 {
        keys::unpack_file_key(&wire::bytes_to_a32(&raw))
            .unwrap()
            .aes_key
            .to_vec()
    } else {
        raw.clone()
    };
    json!({"h":handle,"p":parent,"t":kind,"s":17,
        "k":wire::b64_url_encode(&wire::aes_key_wrap_encrypt(&raw,&SHARE).unwrap()),
        "a":wire::b64_url_encode(&wire::encrypt_attributes(&json!({"n":name}),&attribute_key).unwrap())})
}

#[test]
fn parsed_file_link_import_refuses_with_a_useful_folder_only_error_before_authentication_or_io() {
    let scratch = scratch();
    let stdout = Capture::default();
    let stderr = Capture::default();
    let (_, calls) = test_peer::with_peer(
        |_| panic!("file link import contacted the API"),
        |address| {
            let mut context = Context::test_peer(
                scratch.path(),
                Api::test_peer(address).unwrap(),
                Output::with_writers(false, false, stdout.clone(), stderr.clone()),
            );
            let link = format!("https://mega.nz/file/ABCDEFGH#{}", "A".repeat(43));
            let command = Cli::try_parse_from(["mb", "import", link.as_str()])
                .unwrap()
                .command
                .unwrap();
            let error = dispatch(&mut context, command).unwrap_err();
            assert!(
                matches!(&error, Error::Invalid(message) if message == "Only folder shares can be imported.")
            );
            assert_eq!(error.exit_code(), 2);
            context.report_error(&error);
            assert!(!context.paths.accounts().exists());
            assert!(!context.paths.session(EMAIL).exists());
        },
    );
    assert!(calls.is_empty());
    assert!(stdout.0.lock().unwrap().is_empty());
    let text = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
    assert!(text.contains("Only folder shares can be imported."));
    assert!(!text.contains("Imported") && !text.contains("Authentication failed"));
}

#[test]
fn parsed_subfolder_and_each_unavailable_key_case_import_only_the_exact_surviving_nodes() {
    for mode in ["subtree", "bad-key", "empty-key"] {
        let scratch = scratch();
        seed_accounts(scratch.path(), &[(EMAIL, SID, 1024)]);
        let paths = Context::test_context(scratch.path()).paths;
        let accounts = fs::read(paths.accounts()).unwrap();
        let session = fs::read(paths.session(EMAIL)).unwrap();
        let listing = match mode {
            "subtree" => json!({"f":[
                node("sroot0001","outside01",1,"album"), node("schild001","sroot0001",0,"one.jpg"),
                node("ssub00001","sroot0001",1,"raw"), node("sdeep0001","ssub00001",0,"two.cr2")]}),
            "bad-key" => {
                let mut bad = node("sbad00001", "sroot0001", 0, "bad.jpg");
                bad["k"] = json!("owner:!!!not-base64!!!");
                json!({"f":[node("sroot0001","outside01",1,"album"), bad,
                    node("sgood0001","sroot0001",0,"good.jpg")]})
            }
            "empty-key" => {
                let mut empty = node("sempty001", "sroot0001", 0, "nokey.jpg");
                empty["k"] = json!("");
                json!({"f":[node("sroot0001","outside01",1,"album"),empty]})
            }
            _ => unreachable!(),
        };
        let mut imported = Vec::new();
        let stdout = Capture::default();
        let stderr = Capture::default();
        let (code, calls) = test_peer::with_peer(
            |request| {
                assert_eq!(request.method, "POST");
                let commands: Value = serde_json::from_slice(&request.body).unwrap();
                assert_eq!(commands.as_array().unwrap().len(), 1);
                let command = &commands[0];
                let url =
                    url::Url::parse(&format!("https://testserver.com{}", request.path)).unwrap();
                assert!(
                    url.query_pairs()
                        .any(|(key, value)| key == "sid" && value == SID)
                );
                let result = match command["a"].as_str().unwrap() {
                    "ug" => json!({"u":"testuser"}),
                    "f" if command.get("r").is_some() => {
                        assert_eq!(command, &json!({"a":"f","c":1,"r":1,"ca":1}));
                        assert!(
                            url.query_pairs()
                                .any(|(key, value)| key == "n" && value == "SHARE00001")
                        );
                        listing.clone()
                    }
                    "f" => json!({"f":[{"h":"ROOT0001","t":2}]}),
                    "p" => {
                        assert_eq!(command["sm"], 1);
                        assert!(
                            url.query_pairs()
                                .any(|(key, value)| key == "n" && value == "SHARE00001")
                        );
                        let incoming = &command["n"][0];
                        let original = listing["f"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .find(|original| original["h"] == incoming["h"])
                            .unwrap();
                        assert_eq!(incoming["t"], original["t"]);
                        assert_eq!(incoming["a"], original["a"]);
                        let raw = wire::aes_key_wrap_decrypt(
                            &wire::b64_url_decode(incoming["k"].as_str().unwrap()).unwrap(),
                            &MASTER,
                        )
                        .unwrap();
                        let kind = incoming["t"].as_u64().unwrap();
                        assert_eq!(
                            raw,
                            vec![if kind == 0 { 3 } else { 5 }; if kind == 0 { 32 } else { 16 }]
                        );
                        imported.push((
                            incoming["h"].as_str().unwrap().to_owned(),
                            command["t"].as_str().unwrap().to_owned(),
                        ));
                        json!({"f":[{"h":format!("NEW{:05}",imported.len())}]})
                    }
                    _ => panic!("share command sent an unrelated API mutation"),
                };
                Some(Response {
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
                    "https://mega.nz/folder/SHARE00001#{}{}",
                    wire::b64_url_encode(&SHARE),
                    if mode == "subtree" {
                        "/folder/ssub00001"
                    } else {
                        ""
                    }
                );
                let command = Cli::try_parse_from([
                    "mb",
                    "import",
                    link.as_str(),
                    "--vault-passphrase",
                    PASS,
                ])
                .unwrap()
                .command
                .unwrap();
                let code = dispatch(&mut context, command).unwrap();
                assert_eq!(fs::read(paths.accounts()).unwrap(), accounts);
                assert_eq!(fs::read(paths.session(EMAIL)).unwrap(), session);
                code
            },
        );
        assert_eq!(code, 0);
        let expected = match mode {
            "subtree" => vec![
                ("ssub00001".to_owned(), "ROOT0001".to_owned()),
                ("sdeep0001".to_owned(), "NEW00001".to_owned()),
            ],
            "bad-key" => vec![
                ("sroot0001".to_owned(), "ROOT0001".to_owned()),
                ("sgood0001".to_owned(), "NEW00001".to_owned()),
            ],
            "empty-key" => vec![("sroot0001".to_owned(), "ROOT0001".to_owned())],
            _ => unreachable!(),
        };
        assert_eq!(imported, expected);
        assert_eq!(calls.len(), if mode == "empty-key" { 4 } else { 5 });
        assert!(stdout.0.lock().unwrap().is_empty());
        let diagnostic = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
        assert!(diagnostic.contains(if mode == "empty-key" {
            "Imported 1 node(s)."
        } else {
            "Imported 2 node(s)."
        }));
        let warnings = diagnostic
            .lines()
            .filter(|line| line.starts_with("[WARNING]"))
            .collect::<Vec<_>>();
        assert_eq!(warnings.len(), usize::from(mode != "subtree"));
        if let Some(warning) = warnings.first() {
            assert!(warning.contains(if mode == "bad-key" {
                "sbad00001"
            } else {
                "sempty001"
            }));
            assert!(warning.contains("decryption key is unavailable"));
        }
        assert!(!diagnostic.contains(SID) && !diagnostic.contains(PASS));
        let imported_handles: BTreeSet<_> =
            imported.iter().map(|(handle, _)| handle.as_str()).collect();
        assert!(!imported_handles.contains("schild001"));
        assert!(!imported_handles.contains("sbad00001") && !imported_handles.contains("sempty001"));
    }
}
