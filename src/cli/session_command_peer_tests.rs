//! Shared session restore and persistence across actual cloud, upload, queue and account commands.
#![allow(clippy::unwrap_used)]

use std::{fs, path::Path};

use clap::Parser;
use serde_json::{Value, json};

use super::{args::Cli, auto_account_peer_tests::Capture, context::Context, dispatch};
use crate::{
    crypto::{keys, wire},
    protocol::{
        api::Api,
        auth::Session,
        test_peer::{self, Response},
    },
    storage::{
        accounts::Accounts,
        queue::{JobStatus, JobType, Queue, QueuePayload},
        vault::Vault,
    },
    terminal::output::Output,
};

const EMAIL: &str = "fixture@example.invalid";
const PASS: &str = "synthetic command vault";
const USER: &str = "AQIDBAUGBwg";
const TOKEN: &str = "FCCyf3QV62uAsbARFKbVd8zWyqOQXPFgEL9i";

fn response(value: Value) -> Response {
    Response {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: serde_json::to_vec(&json!([value])).unwrap(),
    }
}

#[test]
fn fresh_upload_caches_its_login_for_later_upload_queue_info_and_refresh_commands() {
    let data: Value =
        serde_json::from_str(include_str!("../../tests/fixtures/crypto-vectors.json")).unwrap();
    let master = hex::decode(data["rsa"]["master_key"].as_str().unwrap()).unwrap();
    let derived = hex::decode(data["kdf_v2"][2]["derived"].as_str().unwrap()).unwrap();
    let sid = data["rsa"]["sid"].as_str().unwrap();
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/session-commands");
    fs::create_dir_all(&base).unwrap();
    let scratch = crate::test_support::tempdir_in(base).unwrap();
    let paths = Context::test_context(scratch.path()).paths;
    let vault = Vault::new(PASS);
    let accounts = Accounts::new(paths.accounts());
    accounts
        .add(EMAIL, "source-fixture", None, true, &vault)
        .unwrap();
    let original_accounts = fs::read(paths.accounts()).unwrap();
    assert!(!paths.session(EMAIL).exists());
    let mut cached = None;

    for mode in [
        "fresh-upload",
        "cached-upload",
        "queue-upload",
        "info",
        "refresh-all",
    ] {
        let source = scratch.path().join(format!("{mode}.bin"));
        let is_upload = mode.ends_with("upload");
        if is_upload {
            fs::write(&source, []).unwrap();
        }
        let queue = Queue::new(paths.queue());
        let queued_id = (mode == "queue-upload").then(|| {
            queue
                .add(
                    JobType::Upload,
                    &QueuePayload {
                        source: source.to_str().unwrap().into(),
                        destination: String::new(),
                        account: Some(EMAIL.into()),
                        password: None,
                        error: None,
                    },
                )
                .unwrap()
        });
        let stdout = Capture::default();
        let stderr = Capture::default();
        let mut actions = Vec::new();
        let ((), calls) = test_peer::with_peer(
            |request| {
                assert_eq!(request.method, "POST");
                if request.path.starts_with("/native-peer-upload/session/") {
                    assert!(is_upload);
                    assert_eq!(
                        request.path,
                        format!("/native-peer-upload/session/{mode}/0")
                    );
                    assert!(request.body.is_empty());
                    actions.push("body".to_owned());
                    return Some(Response {
                        status: 200,
                        headers: vec![],
                        body: TOKEN.as_bytes().to_vec(),
                    });
                }
                let payload: Value = serde_json::from_slice(&request.body).unwrap();
                assert_eq!(payload.as_array().unwrap().len(), 1);
                let command = &payload[0];
                let action = command["a"].as_str().unwrap();
                actions.push(action.to_owned());
                let url =
                    url::Url::parse(&format!("https://testserver.com{}", request.path)).unwrap();
                let sent_sid = url
                    .query_pairs()
                    .find(|(key, _)| key == "sid")
                    .map(|(_, value)| value.into_owned());
                if matches!(action, "us0" | "us") {
                    assert_eq!(mode, "fresh-upload", "cached command authenticated again");
                    assert!(sent_sid.is_none());
                } else {
                    assert_eq!(sent_sid.as_deref(), Some(sid));
                }
                Some(response(match action {
                    "us0" => {
                        assert_eq!(payload, json!([{"a":"us0","user":EMAIL}]));
                        json!({"v":2,"s":wire::b64_url_encode(&hex::decode(data["kdf_v2"][2]["salt"].as_str().unwrap()).unwrap())})
                    }
                    "us" => {
                        assert_eq!(
                            payload,
                            json!([{"a":"us","user":EMAIL,"uh":wire::b64_url_encode(&derived[16..])}])
                        );
                        json!({"u":USER,"k":wire::b64_url_encode(&wire::aes_key_wrap_encrypt(&master,&derived[..16]).unwrap()),
                            "privk":wire::b64_url_encode(&hex::decode(data["rsa"]["wrapped_private"].as_str().unwrap()).unwrap()),
                            "csid":wire::b64_url_encode(&hex::decode(data["rsa"]["csid"].as_str().unwrap()).unwrap())})
                    }
                    "ug" => {
                        assert_eq!(payload, json!([{"a":"ug"}]));
                        json!({"u":USER,"name":"Fixture"})
                    }
                    "uq" => {
                        assert!(!is_upload);
                        assert_eq!(payload, json!([{"a":"uq","strg":1,"xfer":1}]));
                        json!({"mstrg":8192,"cstrg":1024})
                    }
                    "f" => {
                        assert!(is_upload);
                        assert_eq!(payload, json!([{"a":"f","c":1}]));
                        json!({"f":[{"h":"ROOT0001","t":2}]})
                    }
                    "u" => {
                        assert!(is_upload);
                        assert_eq!(command["s"], 0);
                        json!({"p":format!("https://upload.mega.nz/native-peer-upload/session/{mode}")})
                    }
                    "p" => {
                        assert!(is_upload);
                        assert_eq!(command["t"], "ROOT0001");
                        assert_eq!(command["n"].as_array().unwrap().len(), 1);
                        let node = &command["n"][0];
                        assert_eq!(node["h"], TOKEN);
                        assert_eq!(node["t"], 0);
                        let raw = wire::aes_key_wrap_decrypt(
                            &wire::b64_url_decode(node["k"].as_str().unwrap()).unwrap(),
                            &master,
                        )
                        .unwrap();
                        assert_eq!(raw.len(), 32);
                        let key = keys::unpack_file_key(&wire::bytes_to_a32(&raw)).unwrap();
                        assert_eq!(key.mac, [0; 2]);
                        let attrs = wire::decrypt_attributes(
                            &wire::b64_url_decode(node["a"].as_str().unwrap()).unwrap(),
                            key.aes_key.as_slice(),
                        )
                        .unwrap();
                        assert_eq!(attrs["n"], format!("{mode}.bin"));
                        json!({"f":[{"h":"FILE0001"}]})
                    }
                    _ => panic!(
                        "session command reauthenticated, logged out, or sent an unrelated action"
                    ),
                }))
            },
            |address| {
                let mut context = Context::test_peer(
                    scratch.path(),
                    Api::test_peer(address).unwrap(),
                    Output::with_writers(is_upload, false, stdout.clone(), stderr.clone()),
                );
                context.config.upload_workers = 1;
                context.config.max_parallel_uploads = 1;
                let mut arguments: Vec<std::ffi::OsString> = match mode {
                    "fresh-upload" | "cached-upload" => vec![
                        "mb".into(),
                        "upload".into(),
                        source.clone().into_os_string(),
                        "--json".into(),
                    ],
                    "queue-upload" => vec!["mb".into(), "queue".into(), "run".into()],
                    _ => vec!["mb".into(), "account".into(), mode.into()],
                };
                arguments.extend(["--vault-passphrase".into(), PASS.into()]);
                let command = Cli::try_parse_from(arguments).unwrap().command.unwrap();
                assert_eq!(dispatch(&mut context, command).unwrap(), 0);
                let saved = fs::read(paths.session(EMAIL)).unwrap();
                if let Some(previous) = &cached {
                    assert_eq!(
                        &saved, previous,
                        "cached command replaced the proven session"
                    );
                } else {
                    assert_eq!(mode, "fresh-upload");
                    cached = Some(saved);
                }
                if is_upload {
                    assert_eq!(fs::read(paths.accounts()).unwrap(), original_accounts);
                    assert!(fs::read(&source).unwrap().is_empty());
                    let record: Value = serde_json::from_slice(&stdout.0.lock().unwrap()).unwrap();
                    assert_eq!(record["status"], "success");
                    assert_eq!(record["handle"], "FILE0001");
                    assert_eq!(record["size"], 0);
                    if let Some(id) = &queued_id {
                        let items = queue.list().unwrap();
                        assert_eq!(items.len(), 1);
                        assert_eq!(&items[0].id, id);
                        assert_eq!(items[0].status, JobStatus::Done);
                        assert!(items[0].run_id.is_none() && items[0].heartbeat_iso.is_none());
                        assert!(queue.payload(&items[0]).unwrap().error.is_none());
                    }
                } else {
                    let account = accounts.find(Some(EMAIL)).unwrap();
                    assert_eq!(
                        (account.quota_total, account.quota_used),
                        (Some(8192), Some(1024))
                    );
                }
                assert!(!context.control.is_canceled());
                assert!(!paths.logs.exists() && !paths.output.exists());
                for capture in [&stdout, &stderr] {
                    let text = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
                    for secret in [sid, PASS, "source-fixture"] {
                        assert!(!text.contains(secret));
                    }
                    assert!(!text.contains("could not be cached") && !text.contains("logged out"));
                }
            },
        );
        let expected: &[&str] = match mode {
            "fresh-upload" => &["us0", "us", "ug", "f", "u", "body", "p"],
            "cached-upload" | "queue-upload" => &["ug", "f", "u", "body", "p"],
            "info" => &["ug", "ug", "uq"],
            "refresh-all" => &["ug", "uq"],
            _ => unreachable!(),
        };
        assert_eq!(actions, expected);
        assert_eq!(calls.len(), expected.len());
    }
    let sealed: Value = serde_json::from_slice(&cached.unwrap()).unwrap();
    let plaintext = vault
        .open(
            sealed["data"]["encrypted"].as_str().unwrap(),
            b"session:fixture@example.invalid",
        )
        .unwrap();
    let session: Session = serde_json::from_slice(&plaintext).unwrap();
    assert_eq!(session.sid, sid);
    assert_eq!(session.master_key.as_slice(), master);
    assert_eq!(session.email, EMAIL);
    assert_eq!(session.user_handle, USER);
    let stored = accounts.find(Some(EMAIL)).unwrap();
    assert_eq!(
        &*Accounts::password(&stored, &vault).unwrap(),
        "source-fixture"
    );
    assert_eq!(
        accounts.list().unwrap().default_email.as_deref(),
        Some(EMAIL)
    );
}
