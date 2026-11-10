//! Parsed transfer and queue commands invoke one bounded native batch callback with real outcomes.
#![allow(clippy::unwrap_used)]

use std::{collections::BTreeMap, ffi::OsString, io::Write, path::Path, sync::OnceLock};

use clap::Parser;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{
    args::Cli,
    auto_account_peer_tests::{Capture, seed_accounts},
    context::Context,
    dispatch,
};
use crate::{
    crypto::{keys, wire},
    protocol::{
        api::Api,
        test_peer::{self, Request, Response},
    },
    storage::queue::{JobStatus, JobType, Queue, QueuePayload},
    terminal::output::Output,
};

const CHILD: &str = "cli::batch_hook_peer_tests::batch_callback_child_writes_one_exact_outcome";
const FILE_CHILD: &str = "cli::batch_hook_peer_tests::file_callback_child_records_one_literal_path";
const TOKEN: &str = "FCCyf3QV62uAsbARFKbVd8zWyqOQXPFgEL9i";
const MASTER: [u8; 16] = [9; 16];
const EMAIL: &str = "fixture@example.invalid";
const RAW_KEY: &str = "0000000000000000896bfac36bc3028500010203040506078162f0c867ce0c8a";

fn scratch() -> crate::test_support::TempDir {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/batch-hook-peers");
    std::fs::create_dir_all(&root).unwrap();
    crate::test_support::tempdir_in(root).unwrap()
}

fn command(request: &Request) -> Value {
    assert_eq!(request.method, "POST");
    let value: Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(value.as_array().unwrap().len(), 1);
    value[0].clone()
}

fn response(value: Value) -> Response {
    Response {
        status: 200,
        headers: vec![],
        body: serde_json::to_vec(&json!([value])).unwrap(),
    }
}

fn child_command(test: &str) -> String {
    let cwd = std::env::current_dir().unwrap().canonicalize().unwrap();
    let executable = std::env::current_exe().unwrap().canonicalize().unwrap();
    let executable = executable.strip_prefix(&cwd).unwrap().to_str().unwrap();
    assert!(!executable.contains(char::is_whitespace));
    format!("{executable} --exact {test} --nocapture --test-threads=1")
}

fn callback(marker: &Path) -> String {
    let cwd = std::env::current_dir().unwrap().canonicalize().unwrap();
    let parent = marker.parent().unwrap().canonicalize().unwrap();
    let marker = parent.join(marker.file_name().unwrap());
    let marker = marker.strip_prefix(&cwd).unwrap().to_str().unwrap();
    assert!(!marker.contains(char::is_whitespace));
    format!("{} {marker}", child_command(CHILD))
}

#[test]
fn file_callback_child_records_one_literal_path() {
    let arguments: Vec<_> = std::env::args_os().collect();
    if !arguments
        .windows(2)
        .any(|pair| pair[0] == "--exact" && pair[1] == FILE_CHILD)
    {
        return;
    }
    assert_eq!(arguments.len(), 6);
    assert_eq!(arguments[3], "--nocapture");
    assert_eq!(arguments[4], "--test-threads=1");
    let path = std::path::PathBuf::from(&arguments[5]);
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/batch-hook-peers");
    assert!(
        path.canonicalize()
            .unwrap()
            .starts_with(root.canonicalize().unwrap())
    );
    assert!(matches!(std::fs::metadata(&path).unwrap().len(), 4 | 17));
    let mut output = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path.with_extension("file-hook.jsonl"))
        .unwrap();
    serde_json::to_writer(&mut output, &json!({"path":path})).unwrap();
    writeln!(output).unwrap();
    output.flush().unwrap();
    output.sync_all().unwrap();
}

fn file_callback(path: &Path) {
    let bytes = std::fs::read(path.with_extension("file-hook.jsonl")).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).unwrap(),
        json!({"path":path})
    );
}

#[test]
fn batch_callback_child_writes_one_exact_outcome() {
    let arguments: Vec<_> = std::env::args_os().collect();
    if !arguments
        .windows(2)
        .any(|pair| pair[0] == "--exact" && pair[1] == CHILD)
    {
        return;
    }
    assert_eq!(arguments.len(), 9);
    assert_eq!(arguments[3], "--nocapture");
    assert_eq!(arguments[4], "--test-threads=1");
    let marker = Path::new(&arguments[5]);
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/batch-hook-peers");
    assert!(
        marker
            .parent()
            .unwrap()
            .canonicalize()
            .unwrap()
            .starts_with(root.canonicalize().unwrap())
    );
    assert_eq!(marker.file_name().unwrap(), "batch.json");
    let kind = arguments[6].to_str().unwrap();
    assert!(matches!(kind, "download" | "upload" | "queue"));
    let succeeded: usize = arguments[7].to_str().unwrap().parse().unwrap();
    let failed: usize = arguments[8].to_str().unwrap().parse().unwrap();
    assert!((1..=3).contains(&(succeeded + failed)));
    let mut output = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(marker)
        .unwrap();
    serde_json::to_writer(
        &mut output,
        &json!({"kind":kind,"succeeded":succeeded,"failed":failed}),
    )
    .unwrap();
    writeln!(output).unwrap();
    output.flush().unwrap();
    output.sync_all().unwrap();
}

fn run(context: &mut Context, arguments: Vec<OsString>) -> i32 {
    let parsed = Cli::try_parse_from(arguments).unwrap();
    match dispatch(context, parsed.command.unwrap()) {
        Ok(code) => code,
        Err(error) => {
            context.report_error(&error);
            error.exit_code()
        }
    }
}

fn outcome(marker: &Path, kind: &str, succeeded: usize, failed: usize) -> Vec<u8> {
    let bytes = std::fs::read(marker).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).unwrap(),
        json!({"kind":kind,"succeeded":succeeded,"failed":failed})
    );
    bytes
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DownloadCase {
    Success,
    Mixed,
    Invalid,
    Empty,
    MissingCommand,
    QueueSuccess,
    QueueMixed,
    QueueEmpty,
}

#[test]
fn parsed_download_and_queue_batch_callbacks_use_actual_transfer_outcomes_and_never_repeat() {
    for mode in [
        DownloadCase::Success,
        DownloadCase::Mixed,
        DownloadCase::Invalid,
        DownloadCase::Empty,
        DownloadCase::MissingCommand,
        DownloadCase::QueueSuccess,
        DownloadCase::QueueMixed,
        DownloadCase::QueueEmpty,
    ] {
        let scratch = scratch();
        let output = scratch.path().join("output with spaces");
        let marker = scratch.path().join("batch.json");
        let queue_mode = matches!(
            mode,
            DownloadCase::QueueSuccess | DownloadCase::QueueMixed | DownloadCase::QueueEmpty
        );
        let empty = matches!(mode, DownloadCase::Empty | DownloadCase::QueueEmpty);
        let mixed = matches!(
            mode,
            DownloadCase::Mixed | DownloadCase::QueueMixed | DownloadCase::Invalid
        );
        let stdout = Capture::default();
        let stderr = Capture::default();
        let raw_key = hex::decode(RAW_KEY).unwrap();
        let links: Vec<_> = ["FILE0001", "FILE0002"]
            .iter()
            .map(|handle| {
                format!(
                    "https://mega.nz/file/{handle}#{}",
                    wire::b64_url_encode(&raw_key)
                )
            })
            .collect();
        let cdn = OnceLock::new();
        let ((), calls) = test_peer::with_peer(
            |request| {
                assert!(!empty, "empty batch contacted a peer");
                if request.path.starts_with("/cdn/") {
                    assert_eq!(request.method, "GET");
                    assert_eq!(request.headers["range"], "bytes=0-16");
                    let refused = mixed && request.path == "/cdn/FILE0001";
                    return Some(Response {
                        status: if refused { 400 } else { 206 },
                        headers: if refused {
                            vec![]
                        } else {
                            vec![("Content-Range".into(), "bytes 0-16/17".into())]
                        },
                        body: if refused {
                            vec![]
                        } else {
                            include_bytes!("../../tests/fixtures/transfers/ciphertext-17.bin")
                                .to_vec()
                        },
                    });
                }
                let value = command(request);
                assert_eq!(value["a"], "g");
                let handle = value["p"].as_str().unwrap();
                assert!(matches!(handle, "FILE0001" | "FILE0002"));
                let name = if handle == "FILE0001" {
                    "first.bin"
                } else {
                    "second.bin"
                };
                let attrs =
                    wire::encrypt_attributes(&json!({"n":name}), &(0u8..16).collect::<Vec<_>>())
                        .unwrap();
                Some(response(
                    json!({"s":17,"at":wire::b64_url_encode(&attrs),"g":format!("{}/cdn/{handle}",cdn.get().unwrap())}),
                ))
            },
            |address| {
                cdn.set(format!("https://testserver.com:{}", address.port()))
                    .unwrap();
                let mut context = Context::test_peer(
                    scratch.path(),
                    Api::test_peer(address).unwrap(),
                    Output::with_writers(!queue_mode, false, stdout.clone(), stderr.clone()),
                );
                context.config.max_workers = 1;
                context.config.max_parallel_downloads = 1;
                context.config.run_command = Some(child_command(FILE_CHILD));
                let configured = callback(&marker);
                context.config.all_finished_command =
                    Some(if mode == DownloadCase::MissingCommand {
                        let cwd = std::env::current_dir().unwrap().canonicalize().unwrap();
                        let absent = scratch
                            .path()
                            .canonicalize()
                            .unwrap()
                            .join("absent-batch-executable");
                        assert!(!absent.exists());
                        absent
                            .strip_prefix(cwd)
                            .unwrap()
                            .to_str()
                            .unwrap()
                            .to_owned()
                    } else {
                        configured
                    });
                let arguments = if queue_mode {
                    let queue = Queue::new(context.paths.queue());
                    if !empty {
                        for link in &links {
                            queue
                                .add(
                                    JobType::Download,
                                    &QueuePayload {
                                        source: link.clone(),
                                        destination: output.to_str().unwrap().into(),
                                        account: None,
                                        password: None,
                                        error: None,
                                    },
                                )
                                .unwrap();
                        }
                    }
                    vec!["mb".into(), "queue".into(), "run".into()]
                } else {
                    let mut arguments: Vec<OsString> = vec![
                        "mb".into(),
                        "download".into(),
                        "--json".into(),
                        "-w".into(),
                        "1".into(),
                        "-P".into(),
                        if mode == DownloadCase::Success {
                            "2".into()
                        } else {
                            "1".into()
                        },
                        "-o".into(),
                        output.clone().into_os_string(),
                    ];
                    if empty {
                        let list = scratch.path().join("empty-list.txt");
                        std::fs::write(&list, b"# comments only\n\n").unwrap();
                        arguments.extend(["-i".into(), list.into_os_string()]);
                    } else {
                        arguments.push(if mode == DownloadCase::Invalid {
                            "https://example.invalid/not-mega".into()
                        } else {
                            links[0].clone().into()
                        });
                        arguments.push(links[1].clone().into());
                    }
                    arguments
                };
                let code = run(&mut context, arguments);
                assert_eq!(
                    code,
                    if mode == DownloadCase::Empty {
                        2
                    } else {
                        i32::from(mixed)
                    }
                );
                if empty || mode == DownloadCase::MissingCommand {
                    assert!(!marker.exists());
                } else {
                    let saved = outcome(
                        &marker,
                        if queue_mode { "queue" } else { "download" },
                        if mixed { 1 } else { 2 },
                        usize::from(mixed),
                    );
                    if queue_mode {
                        let queue = Queue::new(context.paths.queue());
                        let items = queue.list().unwrap();
                        assert_eq!(
                            items
                                .iter()
                                .filter(|item| item.status == JobStatus::Done)
                                .count(),
                            if mixed { 1 } else { 2 }
                        );
                        assert_eq!(
                            items
                                .iter()
                                .filter(|item| item.status == JobStatus::Failed)
                                .count(),
                            usize::from(mixed)
                        );
                        assert_eq!(
                            run(
                                &mut context,
                                vec!["mb".into(), "queue".into(), "run".into()]
                            ),
                            0
                        );
                        assert_eq!(std::fs::read(&marker).unwrap(), saved);
                    }
                }
            },
        );
        assert_eq!(
            calls.len(),
            if empty {
                0
            } else if mode == DownloadCase::Invalid {
                2
            } else {
                4
            }
        );
        if empty {
            assert!(!output.exists());
        } else {
            for name in if mixed {
                vec!["second.bin"]
            } else {
                vec!["first.bin", "second.bin"]
            } {
                assert_eq!(
                    hex::encode(Sha256::digest(std::fs::read(output.join(name)).unwrap())),
                    "22f22bdc60fc16e495400f16088af4ed246cb07a15b5049865c4e9c231a21c59"
                );
                file_callback(&output.join(name));
            }
            if mixed {
                assert!(!output.join("first.bin").exists());
                assert!(!output.join("first.file-hook.jsonl").exists());
            }
        }
        if mode == DownloadCase::MissingCommand {
            assert!(
                String::from_utf8(stderr.0.lock().unwrap().clone())
                    .unwrap()
                    .contains("All-finished command failed:")
            );
        }
    }
}

#[test]
fn parsed_upload_batch_callback_counts_parallel_files_and_structured_partial_failure() {
    for (structured, fail) in [(false, false), (false, true), (true, true)] {
        let scratch = scratch();
        let source = scratch.path().join("tree");
        std::fs::create_dir(&source).unwrap();
        let count = if !structured && !fail { 3 } else { 2 };
        for index in 0..count {
            std::fs::write(source.join(format!("f{index}.bin")), [index as u8; 4]).unwrap();
        }
        seed_accounts(scratch.path(), &[(EMAIL, "synthetic-session", 128)]);
        let marker = scratch.path().join("batch.json");
        let stdout = Capture::default();
        let stderr = Capture::default();
        let mut bodies = BTreeMap::new();
        let mut slots = 0;
        let mut files = 0;
        let mut nodes = vec![json!({"h":"ROOT0001","t":2})];
        let ((), calls) = test_peer::with_peer(
            |request| {
                if let Some(rest) = request.path.strip_prefix("/native-peer-upload/batch/") {
                    let (id, offset) = rest.split_once('/').unwrap();
                    let id: usize = id.parse().unwrap();
                    assert_eq!(offset, "0");
                    assert_eq!(request.body.len(), 4);
                    assert!(bodies.insert(id, request.body.clone()).is_none());
                    return Some(Response {
                        status: if fail && id == 0 { 400 } else { 200 },
                        headers: vec![],
                        body: if fail && id == 0 {
                            vec![]
                        } else {
                            TOKEN.as_bytes().to_vec()
                        },
                    });
                }
                let value = command(request);
                Some(match value["a"].as_str().unwrap() {
                    "ug" => response(json!({"u":"testuser"})),
                    "f" => response(json!({"f":nodes})),
                    "u" => {
                        assert_eq!(value["s"], 4);
                        let id = slots;
                        slots += 1;
                        response(
                            json!({"p":format!("https://upload.mega.nz/native-peer-upload/batch/{id}")}),
                        )
                    }
                    "p" => {
                        let node = &value["n"][0];
                        if node["t"] == 1 {
                            assert!(structured);
                            assert_eq!(nodes.len(), 1);
                            let mut folder = node.clone();
                            folder["h"] = json!("FOLD0001");
                            folder["p"] = json!("ROOT0001");
                            nodes.push(folder);
                            response(json!({"f":[{"h":"FOLD0001"}]}))
                        } else {
                            files += 1;
                            assert_eq!(node["h"], TOKEN);
                            assert_eq!(
                                value["t"],
                                if structured { "FOLD0001" } else { "ROOT0001" }
                            );
                            let raw = wire::aes_key_wrap_decrypt(
                                &wire::b64_url_decode(node["k"].as_str().unwrap()).unwrap(),
                                &MASTER,
                            )
                            .unwrap();
                            let key = keys::unpack_file_key(&wire::bytes_to_a32(&raw)).unwrap();
                            let attrs = wire::decrypt_attributes(
                                &wire::b64_url_decode(node["a"].as_str().unwrap()).unwrap(),
                                key.aes_key.as_slice(),
                            )
                            .unwrap();
                            let name = attrs["n"].as_str().unwrap();
                            let index: usize = name
                                .strip_prefix('f')
                                .unwrap()
                                .strip_suffix(".bin")
                                .unwrap()
                                .parse()
                                .unwrap();
                            assert!(index < count);
                            assert!(bodies.iter().any(|(&id, bytes)| {
                                !(fail && id == 0)
                                    && wire::ctr_crypt_at_offset(
                                        key.aes_key.as_slice(),
                                        &key.nonce,
                                        0,
                                        bytes,
                                    )
                                    .unwrap()
                                        == [index as u8; 4]
                            }));
                            response(json!({"f":[{"h":format!("FILE{files:04}")}]}))
                        }
                    }
                    _ => panic!("unexpected batch upload action"),
                })
            },
            |address| {
                let mut context = Context::test_peer(
                    scratch.path(),
                    Api::test_peer(address).unwrap(),
                    Output::with_writers(true, false, stdout.clone(), stderr.clone()),
                );
                context.config.all_finished_command = Some(callback(&marker));
                context.config.run_command = Some(child_command(FILE_CHILD));
                let mut arguments: Vec<OsString> = vec!["mb".into(), "upload".into()];
                if structured {
                    arguments.push(source.clone().into_os_string());
                    arguments.extend(["--keep-structure".into(), "--keep-going".into()]);
                } else {
                    arguments.extend(
                        (0..count)
                            .map(|index| source.join(format!("f{index}.bin")).into_os_string()),
                    );
                }
                arguments.extend([
                    "--json".into(),
                    "-w".into(),
                    "1".into(),
                    "-P".into(),
                    "2".into(),
                    "--vault-passphrase".into(),
                    "synthetic vault passphrase".into(),
                ]);
                assert_eq!(run(&mut context, arguments), i32::from(fail));
                outcome(
                    &marker,
                    "upload",
                    if structured {
                        0
                    } else {
                        count - usize::from(fail)
                    },
                    usize::from(fail),
                );
            },
        );
        assert_eq!(slots, count);
        assert_eq!(files, count - usize::from(fail));
        assert_eq!(
            calls
                .iter()
                .filter(|request| request.path.starts_with("/native-peer-upload/"))
                .count(),
            count
        );
        let output = String::from_utf8(stdout.0.lock().unwrap().clone()).unwrap();
        let records: Vec<Value> = output
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(
            records
                .iter()
                .filter(|record| record["status"] == "success")
                .count(),
            count - usize::from(fail)
        );
        for record in records
            .iter()
            .filter(|record| record["status"] == "success")
        {
            file_callback(Path::new(record["path"].as_str().unwrap()));
        }
        for index in 0..count {
            let path = source.join(format!("f{index}.bin"));
            assert_eq!(std::fs::read(&path).unwrap(), [index as u8; 4]);
            if records.iter().any(|record| {
                record["status"] == "failed" && record["path"] == path.to_str().unwrap()
            }) {
                assert!(!path.with_extension("file-hook.jsonl").exists());
            }
        }
    }
}
