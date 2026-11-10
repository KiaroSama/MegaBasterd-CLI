//! Parsed folder downloads through encrypted listing, filtering and real verified CDN bytes.
#![allow(clippy::unwrap_used)]

use std::{
    io::{self, Write},
    path::Path,
    sync::{Arc, Mutex, OnceLock},
};

use clap::Parser;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{args::Cli, context::Context, dispatch};
use crate::{
    crypto::wire,
    platform::secure_files::{OutputDirectory, file_identity},
    protocol::{
        api::Api,
        test_peer::{self, Response},
    },
    storage::transfer_state::{States, TransferState},
    terminal::output::Output,
};

const SHARE: &str = "SHARE123";
const LINK: &str = "https://mega.nz/folder/SHARE123#AAECAwQFBgcICQoLDA0ODw";

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut output = self.0.lock().unwrap();
        if bytes.len() > (16 * 1024usize).saturating_sub(output.len()) {
            return Err(io::Error::other(
                "Folder command output fixture bound exceeded",
            ));
        }
        output.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Capture {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

fn listing(raw_file_key: &[u8]) -> Value {
    let wrapping_key: Vec<u8> = (0..16).collect();
    let attribute_key: Vec<u8> = (0..16).collect();
    let folder_key: Vec<u8> = (16..32).collect();
    let node = |handle: &str, parent: &str, name: &str, folder: bool| {
        let key = if folder {
            folder_key.as_slice()
        } else {
            raw_file_key
        };
        let attributes = if folder {
            folder_key.as_slice()
        } else {
            attribute_key.as_slice()
        };
        json!({"h":handle,"p":parent,"t":u8::from(folder),
            "s":if folder {0} else {17},
            "k":format!("own:{}",wire::b64_url_encode(&wire::aes_key_wrap_encrypt(key, &wrapping_key).unwrap())),
            "a":wire::b64_url_encode(&wire::encrypt_attributes(&json!({"n":name}),attributes).unwrap())})
    };
    let nodes = vec![
        node("rootAAAA", "outsideX", "Show", true),
        node("season01", "rootAAAA", "Season 1", true),
        node("FILE0001", "season01", "e1.mkv", false),
        node("FILE0002", "season01", "e2.mkv", false),
        node("FILE0003", "rootAAAA", "notes.txt", false),
    ];
    json!({"f":nodes})
}

#[test]
fn parsed_folder_filter_downloads_only_selected_file_with_exact_bytes_and_no_match_fails() {
    let vectors: Value =
        serde_json::from_str(include_str!("../../tests/fixtures/transfers/vectors.json")).unwrap();
    let vector = &vectors["vectors"][1];
    assert_eq!(vector["size"], 17);
    let raw_key = hex::decode(vector["raw_key"].as_str().unwrap()).unwrap();
    let listing = listing(&raw_key);
    let ciphertext = include_bytes!("../../tests/fixtures/transfers/ciphertext-17.bin");
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/folder-download-peers");
    std::fs::create_dir_all(&base).unwrap();
    let subfolder = format!("{LINK}/folder/season01");
    let file = format!("{LINK}/file/FILE0001");
    for (link, matched, listing_refused) in [
        (LINK, true, false),
        (LINK, false, false),
        (subfolder.as_str(), false, false),
        (file.as_str(), false, false),
        (LINK, false, true),
    ] {
        let scratch = crate::test_support::tempdir_in(&base).unwrap();
        let stdout = Capture::default();
        let stderr = Capture::default();
        let cdn = OnceLock::new();
        let (code, calls) = test_peer::with_peer(
            |request| {
                if request.path.starts_with("/cs?") {
                    assert_eq!(request.method, "POST");
                    let url = url::Url::parse(&format!("https://testserver.com{}", request.path))
                        .unwrap();
                    assert!(
                        url.query_pairs()
                            .any(|(key, value)| key == "n" && value == SHARE)
                    );
                    assert!(!url.query_pairs().any(|(key, _)| key == "sid"));
                    let body: Value = serde_json::from_slice(&request.body).unwrap();
                    assert_eq!(body.as_array().unwrap().len(), 1);
                    let response = match body[0]["a"].as_str().unwrap() {
                        "f" => {
                            assert_eq!(body, json!([{"a":"f","c":1,"r":1,"ca":1}]));
                            if listing_refused {
                                json!(-11)
                            } else {
                                listing.clone()
                            }
                        }
                        "g" => {
                            assert!(matched, "no-match must never request a CDN ticket");
                            assert_eq!(body, json!([{"a":"g","g":1,"ssl":2,"n":"FILE0001"}]));
                            json!({"s":17,"g":cdn.get().unwrap()})
                        }
                        _ => panic!("folder filter contacted an unexpected API action"),
                    };
                    Some(Response {
                        status: 200,
                        headers: vec![("Content-Type".into(), "application/json".into())],
                        body: serde_json::to_vec(&json!([response])).unwrap(),
                    })
                } else {
                    assert!(matched);
                    assert_eq!(request.method, "GET");
                    assert_eq!(request.path, "/cdn/FILE0001");
                    assert_eq!(request.headers["range"], "bytes=0-16");
                    Some(Response {
                        status: 206,
                        headers: vec![("Content-Range".into(), "bytes 0-16/17".into())],
                        body: ciphertext.to_vec(),
                    })
                }
            },
            |address| {
                cdn.set(format!(
                    "https://testserver.com:{}/cdn/FILE0001",
                    address.port()
                ))
                .unwrap();
                let mut context = Context::test_peer(
                    scratch.path(),
                    Api::test_peer(address).unwrap(),
                    Output::with_writers(true, true, stdout.clone(), stderr.clone()),
                );
                context.config.max_workers = 1;
                context.config.max_parallel_downloads = 1;
                let output = scratch.path().join("output with spaces");
                let mut arguments = vec![
                    "mb".into(),
                    "-q".into(),
                    "download".into(),
                    link.into(),
                    "--json".into(),
                    "-o".into(),
                    output.into_os_string(),
                    "--include".into(),
                    if matched {
                        "*.mkv".into()
                    } else {
                        "*.iso".into()
                    },
                ];
                if matched {
                    arguments.extend(["--exclude".into(), "*e2*".into()]);
                }
                let command = Cli::try_parse_from(arguments).unwrap().command.unwrap();
                dispatch(&mut context, command).unwrap()
            },
        );
        assert_eq!(code, i32::from(!matched));
        assert_eq!(calls.len(), if matched { 3 } else { 1 });
        let text = stdout.text();
        assert!(!text.contains("AAECAwQFBgcICQoLDA0ODw"));
        let records: Vec<Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let output = scratch.path().join("output with spaces");
        if matched {
            assert_eq!(records.len(), 2);
            assert_eq!(records[0]["event"], "result");
            assert_eq!(records[0]["status"], "success");
            assert_eq!(records[0]["name"], "e1.mkv");
            assert_eq!(records[0]["size"].as_u64(), Some(17));
            assert_eq!(records[0]["integrity_ok"], true);
            let path = output.join("Show/Season 1/e1.mkv");
            assert_eq!(records[0]["path"], serde_json::to_value(&path).unwrap());
            assert_eq!(
                hex::encode(Sha256::digest(std::fs::read(&path).unwrap())),
                vector["plaintext_sha256"]
            );
            assert!(!output.join("Show/Season 1/e2.mkv").exists());
            assert!(!output.join("Show/notes.txt").exists());
            assert_eq!(records[1]["event"], "summary");
            assert_eq!(records[1]["status"], "success");
            assert_eq!(records[1]["files"].as_u64(), Some(1));
            assert_eq!(records[1]["total_bytes"].as_u64(), Some(17));
            assert!(stderr.text().is_empty());
        } else {
            assert_eq!(records.len(), 1);
            assert_eq!(
                records[0]["event"],
                if link == file { "result" } else { "summary" }
            );
            assert_eq!(records[0]["type"], "download");
            assert_eq!(records[0]["status"], "failed");
            assert_eq!(
                records[0]["error_code"],
                if listing_refused {
                    "mega_error"
                } else {
                    "transfer_failed"
                }
            );
            assert!(
                records[0]["source"]
                    .as_str()
                    .unwrap()
                    .starts_with("https://mega.nz/folder/SHARE123#<key>")
            );
            assert!(records[0].get("files").is_none());
            if !listing_refused {
                assert!(
                    records[0]["error"]
                        .as_str()
                        .unwrap()
                        .contains("matched no files")
                );
                assert!(stderr.text().contains("matched no files"));
            } else {
                assert!(stderr.text().contains("Access denied"));
            }
            assert!(!output.exists());
        }
    }
}

#[test]
fn parsed_parallel_folder_workers_preserve_disabled_resume_and_custom_user_agent() {
    let vectors: Value =
        serde_json::from_str(include_str!("../../tests/fixtures/transfers/vectors.json")).unwrap();
    let vector = &vectors["vectors"][1];
    assert_eq!(vector["size"], 17);
    let raw_key = hex::decode(vector["raw_key"].as_str().unwrap()).unwrap();
    let mac: [u8; 16] = hex::decode(vector["chunks"][0]["mac"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let plaintext: Vec<u8> = (0..17).map(|index| (13 * index + 7) as u8).collect();
    assert_eq!(
        hex::encode(Sha256::digest(&plaintext)),
        vector["plaintext_sha256"]
    );
    let graph = listing(&raw_key);
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/folder-resume-options");
    std::fs::create_dir_all(&base).unwrap();
    let scratch = crate::test_support::tempdir_in(base).unwrap();
    let cdn = OnceLock::new();
    let (_, calls) = test_peer::with_parallel_peer(
        |request| {
            assert_eq!(request.method, "POST", "Completed resume contacted the CDN");
            assert!(request.path.starts_with("/cs?"));
            assert_eq!(
                request.headers["user-agent"],
                "MegaBasterd-CLI/custom-agent"
            );
            let url = url::Url::parse(&format!("https://testserver.com{}", request.path)).unwrap();
            assert!(
                url.query_pairs()
                    .any(|(key, value)| key == "n" && value == SHARE)
            );
            assert!(!url.query_pairs().any(|(key, _)| key == "sid"));
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            assert_eq!(body.as_array().unwrap().len(), 1);
            let response = match body[0]["a"].as_str().unwrap() {
                "f" => {
                    assert_eq!(body, json!([{"a":"f","c":1,"r":1,"ca":1}]));
                    graph.clone()
                }
                "g" => {
                    let handle = body[0]["n"].as_str().unwrap();
                    assert!(matches!(handle, "FILE0001" | "FILE0002"));
                    assert_eq!(body, json!([{"a":"g","g":1,"ssl":2,"n":handle}]));
                    json!({"s":17,"g":format!("{}/{handle}",cdn.get().unwrap())})
                }
                _ => panic!("Folder resume contacted an unexpected API action"),
            };
            Some(Response {
                status: 200,
                headers: vec![("Content-Type".into(), "application/json".into())],
                body: serde_json::to_vec(&json!([response])).unwrap(),
            })
        },
        |address| {
            cdn.set(format!("https://testserver.com:{}/cdn", address.port()))
                .unwrap();
            let mut api = Api::test_peer(address).unwrap();
            api.transport.user_agent = "MegaBasterd-CLI/custom-agent".into();
            let mut context = Context::test_peer(
                scratch.path(),
                api,
                Output::with_writers(true, true, Capture::default(), Capture::default()),
            );
            context.config.max_workers = 1;
            context.config.verify_integrity = true;
            context.config.user_agent = "MegaBasterd-CLI/custom-agent".into();
            let output = scratch.path().join("output with spaces");
            let directory = OutputDirectory::ensure(&output.join("Show/Season 1")).unwrap();
            let mut seeded = Vec::new();
            for (handle, name) in [("FILE0001", "e1.mkv"), ("FILE0002", "e2.mkv")] {
                let destination = output.join("Show/Season 1").join(name);
                let staging_name = format!(".mb-resume-{handle}.tmp");
                let mut staging = directory.open_file(staging_name.as_ref(), true).unwrap();
                staging.write_all(&plaintext).unwrap();
                staging.sync_all().unwrap();
                let identity = file_identity(&staging).unwrap();
                drop(staging);
                let source = serde_json::to_string(&("folder", SHARE, handle)).unwrap();
                let mut state =
                    TransferState::new("download", &source, &destination, 17, &raw_key).unwrap();
                state.staging_name = Some(staging_name.clone());
                state.staging_identity = Some(identity);
                state.completed.insert(0, mac);
                let state_path = context
                    .paths
                    .user
                    .join("Data/transfers/download")
                    .join(format!(
                        "{}.json",
                        hex::encode(Sha256::digest(destination.to_string_lossy().as_bytes())),
                    ));
                States::new(&state_path).save(&state).unwrap();
                let state_bytes = std::fs::read(&state_path).unwrap();
                seeded.push((
                    destination,
                    output.join("Show/Season 1").join(staging_name),
                    state_path,
                    state_bytes,
                ));
            }
            for resume in [false, true] {
                let stdout = Capture::default();
                let stderr = Capture::default();
                context.output = Output::with_writers(true, true, stdout.clone(), stderr.clone());
                context.config.auto_resume = resume;
                let arguments: Vec<std::ffi::OsString> = vec![
                    "mb".into(),
                    "-q".into(),
                    "download".into(),
                    LINK.into(),
                    "--json".into(),
                    "-o".into(),
                    output.clone().into_os_string(),
                    "--include".into(),
                    "*.mkv".into(),
                    "--parallel".into(),
                    "2".into(),
                ];
                let command = Cli::try_parse_from(arguments).unwrap().command.unwrap();
                assert_eq!(dispatch(&mut context, command).unwrap(), i32::from(!resume));
                let records: Vec<Value> = stdout
                    .text()
                    .lines()
                    .map(|line| serde_json::from_str(line).unwrap())
                    .collect();
                assert_eq!(records.len(), 3);
                for record in &records[..2] {
                    assert_eq!(record["event"], "result");
                    assert_eq!(record["status"], if resume { "success" } else { "failed" });
                    assert!(matches!(record["name"].as_str(), Some("e1.mkv" | "e2.mkv")));
                    if resume {
                        assert_eq!(record["size"], 17);
                        assert_eq!(record["integrity_ok"], true);
                    } else {
                        assert_eq!(record["error_code"], "storage_corrupt");
                        assert!(
                            record["error"]
                                .as_str()
                                .unwrap()
                                .contains("Interrupted state was preserved")
                        );
                    }
                }
                assert_ne!(records[0]["name"], records[1]["name"]);
                assert_eq!(records[2]["event"], "summary");
                assert_eq!(
                    records[2]["status"],
                    if resume { "success" } else { "failed" }
                );
                assert_eq!(records[2]["files"], if resume { 2 } else { 0 });
                assert_eq!(records[2]["total_bytes"], if resume { 34 } else { 0 });
                for (destination, staging, state_path, state_bytes) in &seeded {
                    if resume {
                        assert_eq!(
                            hex::encode(Sha256::digest(std::fs::read(destination).unwrap())),
                            vector["plaintext_sha256"]
                        );
                        assert!(!staging.exists() && !state_path.exists());
                        assert!(States::new(state_path).load().unwrap().is_none());
                    } else {
                        assert!(!destination.exists());
                        assert_eq!(std::fs::read(staging).unwrap(), plaintext);
                        assert_eq!(std::fs::read(state_path).unwrap(), *state_bytes);
                    }
                }
                assert!(!output.join("Show/notes.txt").exists());
                assert!(!context.control.is_canceled());
                assert!(!context.paths.logs.exists());
                if resume {
                    assert!(stderr.text().is_empty());
                } else {
                    assert!(stderr.text().contains("Interrupted state was preserved"));
                }
                for text in [stdout.text(), stderr.text()] {
                    assert!(!text.contains("AAECAwQFBgcICQoLDA0ODw"));
                    assert!(!text.contains("FILE0001") && !text.contains("FILE0002"));
                }
            }
        },
    );
    assert_eq!(calls.len(), 6);
    let mut actions = std::collections::BTreeMap::new();
    for request in calls {
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        let key = (
            body[0]["a"].as_str().unwrap().to_owned(),
            body[0]["n"].as_str().unwrap_or("").to_owned(),
        );
        *actions.entry(key).or_insert(0) += 1;
    }
    assert_eq!(
        actions,
        std::collections::BTreeMap::from([
            (("f".to_owned(), String::new()), 2),
            (("g".to_owned(), "FILE0001".to_owned()), 2),
            (("g".to_owned(), "FILE0002".to_owned()), 2),
        ])
    );
}

#[test]
fn parsed_cyclic_folder_graph_refuses_before_ticket_or_disk_output() {
    let vectors: Value =
        serde_json::from_str(include_str!("../../tests/fixtures/transfers/vectors.json")).unwrap();
    let raw_key = hex::decode(vectors["vectors"][1]["raw_key"].as_str().unwrap()).unwrap();
    let template = listing(&raw_key);
    let mut first = template["f"][1].clone();
    first["h"] = json!("A");
    first["p"] = json!("B");
    let mut second = first.clone();
    second["h"] = json!("B");
    second["p"] = json!("A");
    let mut victim = template["f"][2].clone();
    victim["p"] = json!("A");
    let graph = json!({"f":[template["f"][0],first,second,victim]});
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/folder-cycle");
    std::fs::create_dir_all(&base).unwrap();
    for link in [LINK.to_owned(), format!("{LINK}/file/FILE0001")] {
        let scratch = crate::test_support::tempdir_in(&base).unwrap();
        let stdout = Capture::default();
        let stderr = Capture::default();
        let output = scratch.path().join("no output");
        let (code, calls) = test_peer::with_peer(
            |request| {
                assert_eq!(request.method, "POST");
                assert_eq!(
                    serde_json::from_slice::<Value>(&request.body).unwrap(),
                    json!([{"a":"f","c":1,"r":1,"ca":1}]),
                    "cyclic folder reached a ticket or another API action"
                );
                let url =
                    url::Url::parse(&format!("https://testserver.com{}", request.path)).unwrap();
                assert!(
                    url.query_pairs()
                        .any(|(key, value)| key == "n" && value == SHARE)
                );
                assert!(!url.query_pairs().any(|(key, _)| key == "sid"));
                Some(Response {
                    status: 200,
                    headers: vec![("Content-Type".into(), "application/json".into())],
                    body: serde_json::to_vec(&json!([graph])).unwrap(),
                })
            },
            |address| {
                let mut context = Context::test_peer(
                    scratch.path(),
                    Api::test_peer(address).unwrap(),
                    Output::with_writers(true, true, stdout.clone(), stderr.clone()),
                );
                let arguments: Vec<std::ffi::OsString> = vec![
                    "mb".into(),
                    "-q".into(),
                    "download".into(),
                    link.clone().into(),
                    "--json".into(),
                    "-o".into(),
                    output.clone().into_os_string(),
                ];
                let command = Cli::try_parse_from(arguments).unwrap().command.unwrap();
                let code = dispatch(&mut context, command).unwrap();
                assert!(!context.control.is_canceled());
                assert!(!context.paths.user.exists() && !context.paths.logs.exists());
                code
            },
        );
        assert_eq!(code, 1);
        assert_eq!(calls.len(), 1);
        assert!(!output.exists());
        assert!(std::fs::read_dir(scratch.path()).unwrap().next().is_none());
        let record: Value = serde_json::from_str(&stdout.text()).unwrap();
        assert_eq!(
            record["event"],
            if link == LINK { "summary" } else { "result" }
        );
        assert_eq!(record["status"], "failed");
        assert_eq!(record["error_code"], "protocol_error");
        assert!(record["error"].as_str().unwrap().contains("parent cycle"));
        assert!(stderr.text().contains("parent cycle"));
        for text in [stdout.text(), stderr.text()] {
            assert!(!text.contains("AAECAwQFBgcICQoLDA0ODw"));
            assert!(!text.contains("FILE0001") && !text.contains("Loop"));
        }
    }
}
