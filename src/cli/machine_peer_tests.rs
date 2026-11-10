//! Parsed commands and real TLS transfers observed through the production JSONL writer.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use clap::Parser;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{
    args::{Cli, VaultOptions},
    context::Context,
    dispatch, queue, queue_transfer,
};
use crate::{
    crypto::wire,
    protocol::{
        api::Api,
        auth::Session,
        test_peer::{self, Request, Response},
    },
    storage::{
        queue::{JobStatus, JobType, Queue, QueuePayload},
        sessions::Sessions,
        vault::Vault,
    },
    terminal::output::Output,
};

const NAME: &str = "OAD -  09v2.mkv";
const MASTER: [u8; 16] = [9; 16];
const TOKEN: &str = "FCCyf3QV62uAsbARFKbVd8zWyqOQXPFgEL9i";

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut output = self.0.lock().unwrap();
        if bytes.len() > (64 * 1024usize).saturating_sub(output.len()) {
            return Err(io::Error::other("Command output fixture bound exceeded"));
        }
        output.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Capture {
    fn records(&self) -> Vec<Value> {
        let output = self.0.lock().unwrap();
        let text = std::str::from_utf8(&output).unwrap();
        assert!(text.is_empty() || text.ends_with('\n'));
        assert!(!text.contains("synthetic-session") && !text.contains("synthetic password"));
        text.lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

fn scratch() -> tempfile::TempDir {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/machine-command-peers");
    std::fs::create_dir_all(&base).unwrap();
    tempfile::tempdir_in(base).unwrap()
}

fn request(request: &Request) -> Value {
    assert_eq!(request.method, "POST");
    let envelope: Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(envelope.as_array().unwrap().len(), 1);
    envelope[0].clone()
}

fn response(value: Value) -> Response {
    Response {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: serde_json::to_vec(&json!([value])).unwrap(),
    }
}

fn run(context: &mut Context, arguments: Vec<std::ffi::OsString>) -> i32 {
    let cli = Cli::try_parse_from(arguments).unwrap();
    match dispatch(context, cli.command.unwrap()) {
        Ok(code) => code,
        Err(error) => {
            context.report_error(&error);
            error.exit_code()
        }
    }
}

#[test]
fn parsed_download_emits_source_redacted_failure_or_verified_success_from_actual_cdn() {
    let vectors: Value =
        serde_json::from_str(include_str!("../../tests/fixtures/transfers/vectors.json")).unwrap();
    let vector = &vectors["vectors"][1];
    assert_eq!(vector["size"], 17);
    let key = hex::decode(vector["raw_key"].as_str().unwrap()).unwrap();
    let link = format!(
        "https://mega.nz/file/FILE0001#{}",
        wire::b64_url_encode(&key)
    );
    let attrs = wire::encrypt_attributes(
        &json!({"n":NAME}),
        &hex::decode(vector["aes_key"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    let ciphertext = include_bytes!("../../tests/fixtures/transfers/ciphertext-17.bin");
    for (success, json_mode) in [(false, true), (true, true), (true, false)] {
        let scratch = scratch();
        let capture = Capture::default();
        let diagnostics = Capture::default();
        let cdn = OnceLock::new();
        let (code, calls) = test_peer::with_peer(
            |call| {
                if call.path.starts_with("/cs?") {
                    assert_eq!(request(call)["a"], "g");
                    Some(response(json!({"s":17,"at":wire::b64_url_encode(&attrs),
                        "g":cdn.get().unwrap()})))
                } else {
                    assert_eq!(call.method, "GET");
                    assert_eq!(call.path, "/cdn");
                    assert_eq!(call.headers["range"], "bytes=0-16");
                    Some(Response {
                        status: if success { 206 } else { 400 },
                        headers: if success {
                            vec![("Content-Range".into(), "bytes 0-16/17".into())]
                        } else {
                            vec![]
                        },
                        body: if success { ciphertext.to_vec() } else { vec![] },
                    })
                }
            },
            |address| {
                cdn.set(format!("https://testserver.com:{}/cdn", address.port()))
                    .unwrap();
                let mut context = Context::test_peer(
                    scratch.path(),
                    Api::test_peer(address).unwrap(),
                    Output::with_writers(json_mode, false, capture.clone(), diagnostics.clone()),
                );
                let mut arguments = vec![
                    "mb".into(),
                    "download".into(),
                    "--workers".into(),
                    "1".into(),
                    "--parallel".into(),
                    "1".into(),
                    link.clone().into(),
                    "-o".into(),
                    context_output(scratch.path()).into_os_string(),
                ];
                if json_mode {
                    arguments.push("--json".into());
                }
                run(&mut context, arguments)
            },
        );
        assert_eq!(code, if success { 0 } else { 1 });
        assert_eq!(
            calls.len(),
            2,
            "metadata plus one CDN request, no deterministic retry"
        );
        let stderr = String::from_utf8(diagnostics.0.lock().unwrap().clone()).unwrap();
        assert!(stderr.contains(if success {
            "Downloaded"
        } else {
            "Transfer failed"
        }));
        assert!(!stderr.contains(&wire::b64_url_encode(&key)));
        let records = capture.records();
        if !json_mode {
            assert!(
                records.is_empty(),
                "human mode must not emit machine records"
            );
            let bytes = std::fs::read(context_output(scratch.path()).join(NAME)).unwrap();
            assert_eq!(
                hex::encode(Sha256::digest(bytes)),
                vector["plaintext_sha256"].as_str().unwrap()
            );
            continue;
        }
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record["event"], "result");
        assert_eq!(record["type"], "download");
        if success {
            assert_eq!(record["status"], "success");
            assert_eq!(record["name"], NAME);
            assert_eq!(record["size"], 17);
            assert_eq!(record["integrity_ok"], true);
            let bytes = std::fs::read(context_output(scratch.path()).join(NAME)).unwrap();
            assert_eq!(
                hex::encode(Sha256::digest(bytes)),
                vector["plaintext_sha256"].as_str().unwrap()
            );
        } else {
            assert_eq!(record["status"], "failed");
            assert_eq!(record["error_code"], "transfer_failed");
            assert_eq!(record["source"], "https://mega.nz/file/FILE0001#<key>");
            assert!(!context_output(scratch.path()).join(NAME).exists());
        }
        assert!(
            !String::from_utf8(capture.0.lock().unwrap().clone())
                .unwrap()
                .contains(&wire::b64_url_encode(&key))
        );
    }
}

#[test]
fn parsed_download_batch_continues_after_invalid_source_or_failed_body_and_exits_nonzero() {
    let vectors: Value =
        serde_json::from_str(include_str!("../../tests/fixtures/transfers/vectors.json")).unwrap();
    let vector = &vectors["vectors"][1];
    let key = hex::decode(vector["raw_key"].as_str().unwrap()).unwrap();
    let aes_key = hex::decode(vector["aes_key"].as_str().unwrap()).unwrap();
    let encoded_key = wire::b64_url_encode(&key);
    let ciphertext = include_bytes!("../../tests/fixtures/transfers/ciphertext-17.bin");
    for invalid_source in [false, true] {
        let scratch = scratch();
        let capture = Capture::default();
        let diagnostics = Capture::default();
        let cdn = OnceLock::new();
        let first = if invalid_source {
            "not-a-mega-link".to_owned()
        } else {
            format!("https://mega.nz/file/FILE0001#{encoded_key}")
        };
        let (code, calls) = test_peer::with_peer(
            |call| {
                if call.path.starts_with("/cs?") {
                    let command = request(call);
                    assert_eq!(command["a"], "g");
                    let handle = command["p"].as_str().unwrap();
                    assert!(matches!(handle, "FILE0001" | "FILE0002"));
                    assert!(!invalid_source || handle == "FILE0002");
                    let attrs = wire::encrypt_attributes(
                        &json!({"n":if handle == "FILE0001" {"rejected.bin"} else {NAME}}),
                        &aes_key,
                    )
                    .unwrap();
                    Some(response(json!({"s":17,"at":wire::b64_url_encode(&attrs),
                        "g":format!("{}/{handle}", cdn.get().unwrap())})))
                } else {
                    assert_eq!(call.method, "GET");
                    assert_eq!(call.headers["range"], "bytes=0-16");
                    assert!(matches!(
                        call.path.as_str(),
                        "/cdn/FILE0001" | "/cdn/FILE0002"
                    ));
                    let success = call.path == "/cdn/FILE0002";
                    Some(Response {
                        status: if success { 206 } else { 400 },
                        headers: if success {
                            vec![("Content-Range".into(), "bytes 0-16/17".into())]
                        } else {
                            vec![]
                        },
                        body: if success { ciphertext.to_vec() } else { vec![] },
                    })
                }
            },
            |address| {
                cdn.set(format!("https://testserver.com:{}/cdn", address.port()))
                    .unwrap();
                let mut context = Context::test_peer(
                    scratch.path(),
                    Api::test_peer(address).unwrap(),
                    Output::with_writers(true, true, capture.clone(), diagnostics.clone()),
                );
                run(
                    &mut context,
                    vec![
                        "mb".into(),
                        "-q".into(),
                        "download".into(),
                        "--json".into(),
                        "--workers".into(),
                        "1".into(),
                        "--parallel".into(),
                        "1".into(),
                        first.clone().into(),
                        format!("https://mega.nz/file/FILE0002#{encoded_key}").into(),
                        "-o".into(),
                        context_output(scratch.path()).into_os_string(),
                    ],
                )
            },
        );
        assert_eq!(code, 1, "one failed item must not become overall success");
        let order: Vec<String> = calls
            .iter()
            .map(|call| {
                if call.path.starts_with("/cs?") {
                    format!("g:{}", request(call)["p"].as_str().unwrap())
                } else {
                    call.path.clone()
                }
            })
            .collect();
        assert_eq!(
            order,
            if invalid_source {
                vec!["g:FILE0002", "/cdn/FILE0002"]
            } else {
                vec!["g:FILE0001", "g:FILE0002", "/cdn/FILE0001", "/cdn/FILE0002"]
            }
        );
        let records = capture.records();
        assert_eq!(records.len(), 2);
        assert!(
            records
                .iter()
                .all(|record| record["event"] == "result" && record["type"] == "download")
        );
        assert_eq!(records[0]["status"], "failed");
        assert_eq!(
            records[0]["error_code"],
            if invalid_source {
                "invalid_input"
            } else {
                "transfer_failed"
            }
        );
        assert_eq!(
            records[0]["source"],
            if invalid_source {
                first
            } else {
                "https://mega.nz/file/FILE0001#<key>".into()
            }
        );
        assert_eq!(records[1]["status"], "success");
        assert_eq!(records[1]["name"], NAME);
        assert_eq!(records[1]["size"], 17);
        assert_eq!(records[1]["integrity_ok"], true);
        assert!(!context_output(scratch.path()).join("rejected.bin").exists());
        let bytes = std::fs::read(context_output(scratch.path()).join(NAME)).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(bytes)),
            vector["plaintext_sha256"].as_str().unwrap()
        );
        for output in [&capture, &diagnostics] {
            assert!(
                !String::from_utf8(output.0.lock().unwrap().clone())
                    .unwrap()
                    .contains(&encoded_key)
            );
        }
    }
}

fn context_output(root: &Path) -> std::path::PathBuf {
    root.join("output with spaces")
}

#[test]
fn parsed_queue_run_exits_nonzero_retains_failed_status_and_requires_explicit_retry() {
    let scratch = scratch();
    let capture = Capture::default();
    let diagnostics = Capture::default();
    let (code, calls) = test_peer::with_peer(
        |call| {
            assert_eq!(request(call)["a"], "g");
            Some(response(json!(-11)))
        },
        |address| {
            let mut context = Context::test_peer(
                scratch.path(),
                Api::test_peer(address).unwrap(),
                Output::with_writers(false, true, capture.clone(), diagnostics.clone()),
            );
            context.config.max_workers = 1;
            context.config.max_parallel_downloads = 1;
            let queue = Queue::new(context.paths.queue());
            queue.add(JobType::Download, &QueuePayload {
                source: "https://mega.nz/file/FILE0001#AAAAAAAAAACJa_rDa8MChQABAgMEBQYHgWLwyGfODIo".into(),
                destination: context_output(scratch.path()).to_string_lossy().into_owned(),
                account: None, password: None, error: None,
            }).unwrap();
            let code = run(
                &mut context,
                vec!["mb".into(), "-q".into(), "queue".into(), "run".into()],
            );
            assert_eq!(code, 1);
            let items = queue.list().unwrap();
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].status, JobStatus::Failed);
            assert!(
                queue
                    .payload(&items[0])
                    .unwrap()
                    .error
                    .as_deref()
                    .unwrap()
                    .contains("Queued transfer failed")
            );
            assert!(
                queue
                    .claim_next("0123456789abcdef0123456789abcdef")
                    .unwrap()
                    .is_none()
            );
            assert!(!context_output(scratch.path()).join(NAME).exists());
            code
        },
    );
    assert_eq!(code, 1);
    assert_eq!(calls.len(), 1);
    assert!(
        capture.records().is_empty(),
        "queue has no JSON output flag"
    );
    let stderr = String::from_utf8(diagnostics.0.lock().unwrap().clone()).unwrap();
    assert!(stderr.contains("1 queue job(s) failed."));
    assert!(!stderr.contains("AAAAAAAAAACJa_rDa8MChQABAgMEBQYHgWLwyGfODIo"));
}

#[test]
fn parsed_upload_emits_successful_share_or_stable_transfer_failure_without_credentials() {
    for (success, queued) in [(false, false), (true, false), (false, true)] {
        let scratch = scratch();
        let source = scratch.path().join("up.bin");
        std::fs::write(&source, b"data").unwrap();
        let capture = Capture::default();
        let mut nodes = vec![json!({"h":"ROOT0001","t":2})];
        let (closed, closure) = std::sync::mpsc::sync_channel(8);
        let (code, calls) = test_peer::with_raw_peer(
            |call, stream| {
                let mut send = |response| {
                    test_peer::respond(stream, response, true);
                    super::client_lifecycle_peer_tests::observe_close(stream);
                    closed.try_send(()).unwrap();
                };
                if call.path.starts_with("/native-peer-upload/machine/") {
                    assert_eq!(call.method, "POST");
                    assert_eq!(call.body.len(), 4);
                    return send(Response {
                        status: if success { 200 } else { 400 },
                        headers: vec![],
                        body: if success {
                            TOKEN.as_bytes().to_vec()
                        } else {
                            vec![]
                        },
                    });
                }
                let command = request(call);
                send(match command["a"].as_str().unwrap() {
                    "ug" => response(json!({"u":"testuser"})),
                    "f" => response(json!({"f":nodes})),
                    "u" => {
                        response(json!({"p":"https://upload.mega.nz/native-peer-upload/machine"}))
                    }
                    "p" => {
                        assert!(success, "failed body must not register a node");
                        let mut node = command["n"][0].clone();
                        assert_eq!(node["h"], TOKEN);
                        node["h"] = json!("FILE0001");
                        node["p"] = json!("ROOT0001");
                        node["s"] = json!(4);
                        nodes.push(node);
                        response(json!({"f":[{"h":"FILE0001"}]}))
                    }
                    "l" => {
                        assert!(success);
                        response(json!("AQIDBAUG"))
                    }
                    _ => panic!("unexpected upload command"),
                })
            },
            |address| {
                let mut context = Context::test_peer(
                    scratch.path(),
                    Api::test_peer(address).unwrap(),
                    Output::with_writer(true, true, capture.clone()),
                );
                let vault = Vault::new("synthetic vault passphrase");
                context
                    .accounts()
                    .add(
                        "fixture@example.invalid",
                        "synthetic password",
                        None,
                        true,
                        &vault,
                    )
                    .unwrap();
                Sessions::new(context.paths.session("fixture@example.invalid"))
                    .remember(
                        &Session {
                            sid: "synthetic-session".into(),
                            master_key: MASTER,
                            rsa_private_key: None,
                            user_handle: "testuser".into(),
                            email: "fixture@example.invalid".into(),
                        },
                        &vault,
                    )
                    .unwrap();
                if queued {
                    context.config.upload_workers = 1;
                    context.config.max_parallel_uploads = 1;
                    let queue = Queue::new(context.paths.queue());
                    queue
                        .add(
                            JobType::Upload,
                            &QueuePayload {
                                source: source.to_string_lossy().into_owned(),
                                destination: String::new(),
                                account: None,
                                password: None,
                                error: None,
                            },
                        )
                        .unwrap();
                    let control = context.control.clone();
                    let summary = queue::run(
                        &queue,
                        &control,
                        queue::HeartbeatTiming::default(),
                        |item, payload| {
                            queue_transfer::execute(
                                &mut context,
                                item,
                                payload,
                                &VaultOptions {
                                    vault_passphrase: Some("synthetic vault passphrase".into()),
                                    mfa_code: None,
                                },
                            )
                        },
                    )
                    .unwrap();
                    assert_eq!(summary.failed, 1);
                    assert_eq!(summary.succeeded, 0);
                    let items = queue.list().unwrap();
                    assert_eq!(items[0].status, JobStatus::Failed);
                    assert!(
                        queue
                            .claim_next("0123456789abcdef0123456789abcdef")
                            .unwrap()
                            .is_none()
                    );
                    for _ in 0..4 {
                        closure
                            .recv_timeout(std::time::Duration::from_secs(2))
                            .unwrap();
                    }
                    assert!(closure.try_recv().is_err());
                    return 1;
                }
                let code = run(
                    &mut context,
                    vec![
                        "mb".into(),
                        "upload".into(),
                        "--json".into(),
                        "--share".into(),
                        "--workers".into(),
                        "1".into(),
                        "--parallel".into(),
                        "1".into(),
                        "--vault-passphrase".into(),
                        "synthetic vault passphrase".into(),
                        source.clone().into_os_string(),
                    ],
                );
                for _ in 0..if success { 7 } else { 4 } {
                    closure
                        .recv_timeout(std::time::Duration::from_secs(2))
                        .unwrap();
                }
                assert!(closure.try_recv().is_err());
                code
            },
        );
        assert_eq!(code, if success { 0 } else { 1 });
        let records = capture.records();
        assert_eq!(
            records.len(),
            1,
            "one upload item must produce one result record"
        );
        assert!(
            records
                .iter()
                .all(|record| record["status"] == if success { "success" } else { "failed" })
        );
        assert!(
            !String::from_utf8(capture.0.lock().unwrap().clone())
                .unwrap()
                .contains("synthetic vault passphrase")
        );
        let upload = records
            .iter()
            .find(|record| record["type"] == "upload")
            .unwrap();
        if success {
            assert_eq!(records.len(), 1);
            assert_eq!(upload["handle"], "FILE0001");
            assert_eq!(upload["account"], "fixture@example.invalid");
            assert_eq!(upload["name"], "up.bin");
            assert_eq!(upload["size"], 4);
            let registration = calls
                .iter()
                .filter(|call| call.path.starts_with("/cs?"))
                .map(request)
                .find(|command| command["a"] == "p")
                .unwrap();
            let raw_key = wire::aes_key_wrap_decrypt(
                &wire::b64_url_decode(registration["n"][0]["k"].as_str().unwrap()).unwrap(),
                &MASTER,
            )
            .unwrap();
            assert_eq!(raw_key.len(), 32);
            assert_eq!(
                upload["share_link"],
                format!(
                    "https://mega.nz/file/AQIDBAUG#{}",
                    wire::b64_url_encode(&raw_key)
                )
            );
            assert!(upload.get("vault_passphrase").is_none());
            assert_eq!(upload["thumbnail"]["status"], "not_applicable");
        } else {
            assert_eq!(upload["error_code"], "transfer_failed");
            assert!(
                records
                    .iter()
                    .all(|record| record["error_code"] == "transfer_failed")
            );
            assert!(
                calls
                    .iter()
                    .filter(|call| call.path.starts_with("/cs?"))
                    .all(|call| request(call)["a"] != "p" && request(call)["a"] != "l")
            );
        }
        assert_eq!(std::fs::read(source).unwrap(), b"data");
        assert_eq!(
            calls
                .iter()
                .filter(|call| call.path.starts_with("/native-peer-upload/"))
                .count(),
            1
        );
    }
}
