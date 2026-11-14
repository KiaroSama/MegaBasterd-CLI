//! Literal remote text through parsed cloud/account commands, not hand-built table rows.
#![allow(clippy::unwrap_used)]

use std::{fs, path::Path};

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
    protocol::{api::Api, test_peer},
    storage::vault::Vault,
    terminal::output::Output,
};

const EMAIL: &str = "fixture@example.invalid";
const SID: &str = "synthetic-render-session";
const PASS: &str = "synthetic vault passphrase";
const MASTER: [u8; 16] = [9; 16];
const NAMES: [&str; 5] = [
    "[bold red]x[/]",
    "weird[name.mp4",
    "holiday [/] clip.mp4",
    "normal.mp4",
    "[bold red]evil[/bold red]",
];
const FILES: [&str; 5] = ["AAAAAAAA", "BBBBBBBB", "CCCCCCCC", "DDDDDDDD", "abc[def"];
const TRASH_FILES: [&str; 5] = ["TRASH001", "TRASH002", "TRASH003", "TRASH004", "TRASH005"];
const HEADER: &str = "Type | Name | Size | Handle\n";

fn scratch() -> crate::test_support::TempDir {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/cloud-render");
    fs::create_dir_all(&base).unwrap();
    crate::test_support::tempdir_in(base).unwrap()
}

fn text(capture: &Capture) -> String {
    String::from_utf8(capture.0.lock().unwrap().clone()).unwrap()
}

fn remote_file(handle: &str, parent: &str, name: &str) -> Value {
    let key = [7; 32];
    let attributes = keys::unpack_file_key(&wire::bytes_to_a32(&key)).unwrap();
    json!({"h":handle,"p":parent,"u":"OOOOOOOO","t":0,"s":1234,"ts":0,
        "k":wire::b64_url_encode(&wire::aes_key_wrap_encrypt(&key,&MASTER).unwrap()),
        "a":wire::b64_url_encode(&wire::encrypt_attributes(&json!({"n":name}),
            attributes.aes_key.as_slice()).unwrap())})
}

fn remote_folder(handle: &str, parent: &str, name: &str) -> Value {
    let key = [7; 16];
    json!({"h":handle,"p":parent,"t":1,
        "k":wire::b64_url_encode(&wire::aes_key_wrap_encrypt(&key,&MASTER).unwrap()),
        "a":wire::b64_url_encode(&wire::encrypt_attributes(&json!({"n":name}),&key).unwrap())})
}

fn system_nodes() -> Vec<Value> {
    vec![
        json!({"h":"ROOT0001","t":2}),
        json!({"h":"INBOX001","t":3}),
        json!({"h":"BIN00001","t":4}),
    ]
}

fn populated_listing() -> Value {
    let mut nodes = system_nodes();
    nodes.push(remote_folder("PPPPPPPP", "ROOT0001", "album"));
    for (parent, handles) in [("PPPPPPPP", FILES), ("BIN00001", TRASH_FILES)] {
        for (handle, name) in handles.into_iter().zip(NAMES) {
            nodes.push(remote_file(handle, parent, name));
        }
    }
    json!({"f":nodes})
}

fn expected_rows(handles: &[&str]) -> String {
    handles
        .iter()
        .zip(NAMES)
        .map(|(handle, name)| format!("File | {name} | 1.21 KB | {handle}\n"))
        .collect()
}

fn assert_plain(stdout: &str, stderr: &str) {
    for output in [stdout, stderr] {
        for forbidden in [
            "\u{1b}",
            "[mb.dim]",
            "[mb.success]",
            "MarkupError",
            "Traceback",
            SID,
            PASS,
            "synthetic password",
        ] {
            assert!(
                !output.contains(forbidden),
                "unexpected output token: {forbidden}"
            );
        }
    }
}

fn run_cloud_cases(listing: Value, cases: Vec<(Vec<&str>, String, String)>) {
    let scratch = scratch();
    seed_accounts(scratch.path(), &[(EMAIL, SID, 1024)]);
    let paths = Context::test_context(scratch.path()).paths;
    let accounts = fs::read(paths.accounts()).unwrap();
    let session = fs::read(paths.session(EMAIL)).unwrap();
    let count = cases.len();
    let ((), calls) = test_peer::with_peer(
        |request| {
            assert_eq!(request.method, "POST");
            let url = url::Url::parse(&format!("https://testserver.com{}", request.path)).unwrap();
            assert!(
                url.query_pairs()
                    .any(|(key, value)| key == "sid" && value == SID)
            );
            assert!(!url.query_pairs().any(|(key, _)| key == "n"));
            let command: Value = serde_json::from_slice(&request.body).unwrap();
            let result = match command[0]["a"].as_str().unwrap() {
                "ug" => {
                    assert_eq!(command, json!([{"a":"ug"}]));
                    json!({"u":"testuser"})
                }
                "f" => {
                    assert_eq!(command, json!([{"a":"f","c":1}]));
                    listing.clone()
                }
                _ => panic!("read-only renderer issued a mutation, login or logout"),
            };
            Some(test_peer::Response {
                status: 200,
                headers: vec![],
                body: serde_json::to_vec(&json!([result])).unwrap(),
            })
        },
        |address| {
            for (arguments, expected_stdout, expected_stderr) in cases {
                let stdout = Capture::default();
                let stderr = Capture::default();
                let mut context = Context::test_peer(
                    scratch.path(),
                    Api::test_peer(address).unwrap(),
                    Output::with_writers(false, false, stdout.clone(), stderr.clone()),
                );
                let mut arguments = arguments;
                arguments.extend(["--vault-passphrase", PASS]);
                let command = Cli::try_parse_from(arguments).unwrap().command.unwrap();
                assert_eq!(dispatch(&mut context, command).unwrap(), 0);
                let output = text(&stdout);
                let diagnostic = text(&stderr);
                assert_eq!(output, expected_stdout);
                assert_eq!(diagnostic, expected_stderr);
                assert_plain(&output, &diagnostic);
                assert_eq!(fs::read(paths.accounts()).unwrap(), accounts);
                assert_eq!(fs::read(paths.session(EMAIL)).unwrap(), session);
                assert!(!paths.config().exists() && !paths.queue().exists());
                assert!(!paths.output.exists() && !paths.logs.exists());
                assert!(!context.control.is_canceled());
            }
        },
    );
    assert_eq!(calls.len(), count * 2);
    let actions = calls
        .iter()
        .map(|request| {
            let command: Value = serde_json::from_slice(&request.body).unwrap();
            command[0]["a"].as_str().unwrap().to_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(actions, ["ug", "f"].repeat(count));
}

#[test]
fn parsed_all_folder_search_and_trash_render_decrypted_hostile_names_and_handles_literally() {
    let folder = expected_rows(&FILES);
    let trash = expected_rows(&TRASH_FILES);
    let all = format!("{HEADER}Folder | album | 0 B | PPPPPPPP\n{folder}{trash}");
    run_cloud_cases(
        populated_listing(),
        vec![
            (vec!["mb", "ls", "--all"], all, String::new()),
            (
                vec!["mb", "ls", "PPPPPPPP"],
                format!("{HEADER}{folder}"),
                String::new(),
            ),
            (
                vec!["mb", "search", "red|mp4", "--regex"],
                format!("{HEADER}{folder}{trash}"),
                String::new(),
            ),
            (
                vec!["mb", "trash", "list"],
                format!("{HEADER}{trash}"),
                String::new(),
            ),
        ],
    );
}

#[test]
fn parsed_empty_and_system_only_listings_have_no_phantom_table_or_style_tags() {
    for listing in [json!({"f":[]}), json!({"f":system_nodes()})] {
        run_cloud_cases(
            listing,
            vec![
                (
                    vec!["mb", "ls", "--all"],
                    String::new(),
                    "[INFO] Your MEGA account is empty.\n".into(),
                ),
                (
                    vec!["mb", "search", "["],
                    String::new(),
                    "[INFO] Nothing matched '['.\n".into(),
                ),
            ],
        );
    }
    run_cloud_cases(
        json!({"f":system_nodes()}),
        vec![
            (
                vec!["mb", "ls"],
                String::new(),
                "[INFO] Your Cloud Drive is empty.\n".into(),
            ),
            (
                vec!["mb", "trash", "list"],
                String::new(),
                "[INFO] The trash is empty.\n".into(),
            ),
        ],
    );
}

#[test]
fn parsed_empty_folder_paths_and_nonempty_rows_keep_literal_context() {
    let paths = [
        "photos",
        "[bold red]owned[/bold red]",
        "unbalanced [tag",
        "[/close-only]",
    ];
    let mut nodes = system_nodes();
    let mut next = 0;
    for path in paths {
        let mut parent = "ROOT0001".to_owned();
        for name in path.split('/') {
            let handle = format!("EMPTY{next:03}");
            nodes.push(remote_folder(&handle, &parent, name));
            parent = handle;
            next += 1;
        }
    }
    run_cloud_cases(
        json!({"f":nodes}),
        paths
            .into_iter()
            .map(|path| {
                (
                    vec!["mb", "ls", path],
                    String::new(),
                    format!("[INFO] Folder '{path}' is empty.\n"),
                )
            })
            .collect(),
    );
    let mut nodes = system_nodes();
    nodes.push(remote_file("KEEP0001", "ROOT0001", "keep.bin"));
    run_cloud_cases(
        json!({"f":nodes}),
        vec![(
            vec!["mb", "ls", "--all"],
            format!("{HEADER}File | keep.bin | 1.21 KB | KEEP0001\n"),
            String::new(),
        )],
    );
}

#[test]
fn parsed_account_list_renders_the_real_stored_label_literally_without_mutating_the_vault() {
    let scratch = scratch();
    let seed = Context::test_context(scratch.path());
    assert!(
        seed.accounts()
            .add(
                "a@b.c",
                "synthetic password",
                Some("[bold red]label[/bold red]".into()),
                true,
                &Vault::new(PASS),
            )
            .unwrap()
    );
    let original = fs::read(seed.paths.accounts()).unwrap();
    let stdout = Capture::default();
    let stderr = Capture::default();
    let ((), calls) = test_peer::with_peer(
        |_| panic!("local account listing reached a remote service"),
        |address| {
            let mut context = Context::test_peer(
                scratch.path(),
                Api::test_peer(address).unwrap(),
                Output::with_writers(false, false, stdout.clone(), stderr.clone()),
            );
            let command = Cli::try_parse_from(["mb", "account", "list"])
                .unwrap()
                .command
                .unwrap();
            assert_eq!(dispatch(&mut context, command).unwrap(), 0);
            assert_eq!(
                text(&stdout),
                concat!(
                    "Default | Account | Label | Total | Used\n",
                    "Y | a@b.c | [bold red]label[/bold red] | Unknown | Unknown\n",
                )
            );
            assert!(text(&stderr).is_empty());
            assert_plain(&text(&stdout), &text(&stderr));
            assert_eq!(fs::read(context.paths.accounts()).unwrap(), original);
            assert!(!context.paths.session("a@b.c").exists());
            assert!(!context.paths.config().exists() && !context.paths.queue().exists());
            assert!(!context.paths.output.exists() && !context.paths.logs.exists());
        },
    );
    assert!(calls.is_empty());
}
