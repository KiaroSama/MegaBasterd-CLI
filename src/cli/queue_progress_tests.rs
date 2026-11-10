// SPDX-License-Identifier: GPL-3.0-or-later
//! Queue rows reflect committed jobs, including failures before a transfer can create a file row.
#![allow(clippy::unwrap_used)]

use std::{fs, path::Path, sync::OnceLock};

use clap::Parser;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::*;
use crate::{
    cli::{
        args::{Cli, Command},
        auto_account_peer_tests::Capture,
        queue_transfer,
    },
    crypto::wire,
    protocol::{
        api::Api,
        test_peer::{self, Response},
    },
    storage::files::Store,
    terminal::{
        output::Output,
        progress::{Progress, Status},
    },
};

fn fixture() -> crate::test_support::TempDir {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/queue-progress");
    fs::create_dir_all(&base).unwrap();
    crate::test_support::tempdir_in(base).unwrap()
}

fn run_command(
    context: &mut Context,
    queue: &Queue,
    progress: &mut Progress,
    execute: impl FnMut(&mut Context, &QueueItem, &QueuePayload, &args::VaultOptions) -> Result<()>,
) -> Result<()> {
    let command = Cli::try_parse_from(["mb", "-q", "queue", "run"])
        .unwrap()
        .command
        .unwrap();
    let Command::Queue(args::Queue::Run { auth }) = command else {
        panic!("not queue run")
    };
    run_command_with(
        context,
        queue,
        HeartbeatTiming::default(),
        &auth,
        progress,
        execute,
    )
}

#[test]
fn mixed_queue_rows_keep_each_job_direction_through_final_reporting() {
    let scratch = fixture();
    let mut context = Context::test_context(scratch.path());
    let stdout = Capture::default();
    let stderr = Capture::default();
    context.output = Output::with_writers(false, false, stdout.clone(), stderr.clone());
    let queue = Queue::new(context.paths.queue());
    let mut labels = Vec::new();
    for (kind, direction) in [
        (JobType::Upload, "↑ Upload"),
        (JobType::Download, "↓ Download"),
    ] {
        let id = queue
            .add(
                kind,
                &QueuePayload {
                    source: "synthetic-private-source".into(),
                    destination: String::new(),
                    account: None,
                    password: Some("synthetic-private-password".into()),
                    error: None,
                },
            )
            .unwrap();
        labels.push(format!("Job {id} {direction}"));
    }
    let mut progress = Progress::new(false);
    let mut executed = 0;
    run_command(
        &mut context,
        &queue,
        &mut progress,
        |_, item, payload, _| {
            let direction = match item.kind {
                JobType::Upload => "↑ Upload",
                JobType::Download => "↓ Download",
            };
            assert_eq!(labels[executed], format!("Job {} {direction}", item.id));
            assert_eq!(payload.source, "synthetic-private-source");
            executed += 1;
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(executed, 2);
    let rows = progress.frame().unwrap().0;
    assert_eq!(rows.len(), 2);
    let saved = queue.list().unwrap();
    assert_eq!(saved.len(), 2);
    let diagnostic = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
    for (index, label) in labels.iter().enumerate() {
        assert!(rows[index].starts_with(&format!("{label} ")));
        assert!(rows[index].contains("Done") && !rows[index].contains("ETA"));
        assert_eq!(progress.snapshot(index).unwrap().status, Status::Complete);
        assert_eq!(saved[index].status, JobStatus::Done);
        assert!(saved[index].run_id.is_none() && saved[index].heartbeat_iso.is_none());
        assert!(diagnostic.contains(&format!("[INFO] {label} ")));
    }
    assert_eq!(diagnostic.matches("[INFO] Job ").count(), 2);
    assert!(!diagnostic.contains("synthetic-private-source"));
    assert!(!diagnostic.contains("synthetic-private-password"));
    assert!(stdout.0.lock().unwrap().is_empty());
}

#[test]
fn actual_queue_transfers_keep_failed_and_complete_rows_and_no_active_residue() {
    let vectors: Value =
        serde_json::from_str(include_str!("../../tests/fixtures/transfers/vectors.json")).unwrap();
    let vector = &vectors["vectors"][1];
    let raw_key = hex::decode(vector["raw_key"].as_str().unwrap()).unwrap();
    let aes_key = hex::decode(vector["aes_key"].as_str().unwrap()).unwrap();
    let encoded = wire::b64_url_encode(&raw_key);
    let ciphertext = include_bytes!("../../tests/fixtures/transfers/ciphertext-17.bin");
    for mixed in [false, true] {
        let scratch = fixture();
        let stdout = Capture::default();
        let stderr = Capture::default();
        let cdn = OnceLock::new();
        let (_, calls) = test_peer::with_peer(
            |call| {
                if call.path.starts_with("/cs?") {
                    let commands: Value = serde_json::from_slice(&call.body).unwrap();
                    assert_eq!(commands.as_array().unwrap().len(), 1);
                    assert_eq!(commands[0]["a"], "g");
                    let id = commands[0]["p"].as_str().unwrap();
                    let name = if id == "FILE0001" {
                        "failed.bin"
                    } else {
                        "complete.bin"
                    };
                    let attributes =
                        wire::encrypt_attributes(&json!({"n":name}), &aes_key).unwrap();
                    Some(Response { status: 200, headers: vec![], body: serde_json::to_vec(&json!([{
                    "s":17,"at":wire::b64_url_encode(&attributes),"g":format!("{}/{id}",cdn.get().unwrap())
                }])).unwrap() })
                } else {
                    assert_eq!(call.headers["range"], "bytes=0-16");
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
                    Output::with_writers(false, false, stdout.clone(), stderr.clone()),
                );
                context.config.max_workers = 1;
                context.config.max_parallel_downloads = 1;
                let queue = Queue::new(context.paths.queue());
                for id in if mixed {
                    vec!["FILE0001", "FILE0002"]
                } else {
                    vec!["FILE0001"]
                } {
                    queue
                        .add(
                            JobType::Download,
                            &QueuePayload {
                                source: format!("https://mega.nz/file/{id}#{encoded}"),
                                destination: scratch
                                    .path()
                                    .join("output")
                                    .to_string_lossy()
                                    .into_owned(),
                                account: None,
                                password: None,
                                error: None,
                            },
                        )
                        .unwrap();
                }
                let mut progress = Progress::new(false);
                let error =
                    run_command(&mut context, &queue, &mut progress, queue_transfer::execute)
                        .unwrap_err();
                assert_eq!(error.exit_code(), 1);
                assert_eq!(progress.snapshot(0).unwrap().status, Status::Failed);
                assert_eq!(progress.totals().unwrap().items, if mixed { 2 } else { 1 });
                if mixed {
                    assert_eq!(progress.snapshot(1).unwrap().status, Status::Complete);
                }
                assert_eq!(progress.totals().unwrap().status, Status::Failed);
                let saved = queue.list().unwrap();
                assert_eq!(
                    saved.iter().map(|item| item.status).collect::<Vec<_>>(),
                    if mixed {
                        vec![JobStatus::Failed, JobStatus::Done]
                    } else {
                        vec![JobStatus::Failed]
                    }
                );
                assert!(
                    saved
                        .iter()
                        .all(|item| item.run_id.is_none() && item.heartbeat_iso.is_none())
                );
                assert!(!scratch.path().join("output/failed.bin").exists());
                if mixed {
                    let actual = fs::read(scratch.path().join("output/complete.bin")).unwrap();
                    assert_eq!(
                        hex::encode(Sha256::digest(actual)),
                        vector["plaintext_sha256"].as_str().unwrap()
                    );
                } else {
                    assert!(!scratch.path().join("output/complete.bin").exists());
                }
            },
        );
        assert_eq!(calls.len(), if mixed { 4 } else { 2 });
        assert!(stdout.0.lock().unwrap().is_empty());
        let diagnostic = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
        assert_eq!(
            diagnostic.matches("[INFO] Job ").count(),
            if mixed { 2 } else { 1 }
        );
        assert!(
            diagnostic
                .lines()
                .any(|line| line.starts_with("[INFO] Job ") && line.contains("Failed"))
        );
        assert_eq!(
            diagnostic
                .lines()
                .any(|line| line.starts_with("[INFO] Job ") && line.contains("Done")),
            mixed
        );
        assert!(!diagnostic.contains(&encoded));
    }
}

#[test]
fn missing_upload_source_has_a_failed_queue_row_before_account_or_network_work() {
    let scratch = fixture();
    let mut context = Context::test_context(scratch.path());
    let diagnostic = Capture::default();
    context.output = Output::with_writers(false, false, Vec::new(), diagnostic.clone());
    let queue = Queue::new(context.paths.queue());
    let source = scratch.path().join("gone.bin");
    fs::write(&source, b"x").unwrap();
    queue
        .add(
            JobType::Upload,
            &QueuePayload {
                source: source.to_string_lossy().into_owned(),
                destination: String::new(),
                account: Some("fixture@example.invalid".into()),
                password: None,
                error: None,
            },
        )
        .unwrap();
    fs::remove_file(&source).unwrap();
    let mut progress = Progress::new(false);
    let error =
        run_command(&mut context, &queue, &mut progress, queue_transfer::execute).unwrap_err();
    assert_eq!(error.exit_code(), 1);
    assert_eq!(progress.snapshot(0).unwrap().status, Status::Failed);
    let saved = queue.list().unwrap();
    assert_eq!(saved[0].status, JobStatus::Failed);
    assert!(
        queue
            .payload(&saved[0])
            .unwrap()
            .error
            .as_deref()
            .unwrap()
            .contains("missing")
    );
    assert!(!context.paths.accounts().exists());
    assert!(!context.paths.output.exists());
    let diagnostic = String::from_utf8(diagnostic.0.lock().unwrap().clone()).unwrap();
    assert!(
        diagnostic
            .lines()
            .any(|line| line.starts_with("[INFO] Job ") && line.contains("Failed"))
    );
}

#[test]
fn canceled_executor_marks_the_row_canceled_and_releases_the_owned_lease() {
    let scratch = fixture();
    let mut context = Context::test_context(scratch.path());
    context.output = Output::with_writers(false, true, Vec::new(), Vec::new());
    let queue = Queue::new(context.paths.queue());
    queue
        .add(
            JobType::Download,
            &QueuePayload {
                source: "https://mega.nz/file/abc123#xyz".into(),
                destination: String::new(),
                account: None,
                password: None,
                error: None,
            },
        )
        .unwrap();
    let mut progress = Progress::new(false);
    let error = run_command(&mut context, &queue, &mut progress, |context, _, _, _| {
        context.control.cancel();
        Err(Error::Canceled)
    })
    .unwrap_err();
    assert_eq!(error.exit_code(), 130);
    assert_eq!(progress.snapshot(0).unwrap().status, Status::Canceled);
    let saved = queue.list().unwrap();
    assert_eq!(saved[0].status, JobStatus::Interrupted);
    assert!(saved[0].run_id.is_none() && saved[0].heartbeat_iso.is_none());
    assert!(queue.claim_next("after-cancel").unwrap().is_some());
}

#[test]
fn canceled_success_commits_done_but_a_lost_commit_never_displays_done() {
    for lost_commit in [false, true] {
        let scratch = fixture();
        let mut context = Context::test_context(scratch.path());
        context.output = Output::with_writers(false, true, Vec::new(), Vec::new());
        let queue = Queue::new(context.paths.queue());
        queue
            .add(
                JobType::Download,
                &QueuePayload {
                    source: "https://mega.nz/file/abc123#xyz".into(),
                    destination: String::new(),
                    account: None,
                    password: None,
                    error: None,
                },
            )
            .unwrap();
        let mut progress = Progress::new(false);
        let error = run_command(&mut context, &queue, &mut progress, |context, _, _, _| {
            if lost_commit {
                let locked = Store::new(queue.path()).lock()?;
                let mut data: Value = locked.load()?.unwrap();
                data["items"][0]["lease_epoch"] = 2.into();
                locked.save(&data)?;
            } else {
                context.control.cancel();
            }
            Ok(())
        })
        .unwrap_err();
        let saved = queue.list().unwrap();
        if lost_commit {
            assert!(matches!(error, Error::Busy(_)));
            // Heartbeat may detect the changed generation before the final commit does.
            assert_eq!(
                progress.snapshot(0).unwrap().status,
                if context.control.is_canceled() {
                    Status::Canceled
                } else {
                    Status::Failed
                }
            );
            assert_eq!(saved[0].status, JobStatus::Active);
            assert_eq!(saved[0].lease_epoch, 2);
        } else {
            assert!(matches!(error, Error::Canceled));
            assert_eq!(progress.snapshot(0).unwrap().status, Status::Complete);
            assert_eq!(saved[0].status, JobStatus::Done);
            assert!(queue.claim_next("must-not-replay").unwrap().is_none());
        }
    }
}

#[test]
fn broken_final_diagnostics_preserve_cancellation_and_ambiguous_mutation_errors() {
    struct Broken;
    impl std::io::Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "controlled output failure",
            ))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    for canceled in [false, true] {
        let scratch = fixture();
        let mut context = Context::test_context(scratch.path());
        context.output = Output::with_writers(false, false, Vec::new(), Broken);
        let queue = Queue::new(context.paths.queue());
        queue
            .add(
                JobType::Download,
                &QueuePayload {
                    source: "https://mega.nz/file/abc123#xyz".into(),
                    destination: String::new(),
                    account: None,
                    password: None,
                    error: None,
                },
            )
            .unwrap();
        let mut progress = Progress::new(false);
        let error = run_command(&mut context, &queue, &mut progress, |context, _, _, _| {
            if canceled {
                context.control.cancel();
                Err(Error::Canceled)
            } else {
                Err(Error::AmbiguousMutation("upload"))
            }
        })
        .unwrap_err();
        if canceled {
            assert!(matches!(error, Error::Canceled));
            assert_eq!(error.exit_code(), 130);
            assert_eq!(queue.list().unwrap()[0].status, JobStatus::Interrupted);
        } else {
            assert!(matches!(error, Error::AmbiguousMutation("upload")));
            assert_eq!(queue.list().unwrap()[0].status, JobStatus::Active);
        }
        assert_eq!(
            progress.snapshot(0).unwrap().status,
            if canceled {
                Status::Canceled
            } else {
                Status::Failed
            }
        );
    }
}

#[test]
fn unknown_saved_job_kind_refuses_before_any_progress_row_and_preserves_the_document() {
    let scratch = fixture();
    let mut context = Context::test_context(scratch.path());
    context.output = Output::with_writers(false, true, Vec::new(), Vec::new());
    let queue = Queue::new(context.paths.queue());
    queue
        .add(
            JobType::Download,
            &QueuePayload {
                source: "https://mega.nz/file/abc123#xyz".into(),
                destination: String::new(),
                account: None,
                password: None,
                error: None,
            },
        )
        .unwrap();
    let locked = Store::new(queue.path()).lock().unwrap();
    let mut data: Value = locked.load().unwrap().unwrap();
    data["items"][0]["kind"] = "teleport".into();
    locked.save(&data).unwrap();
    drop(locked);
    let before = fs::read(queue.path()).unwrap();
    let mut progress = Progress::new(false);
    let error = run_command(&mut context, &queue, &mut progress, |_, _, _, _| {
        panic!("corrupt job executed")
    })
    .unwrap_err();
    assert!(matches!(error, Error::Corrupt(_)));
    assert_eq!(error.exit_code(), 1);
    assert_eq!(progress.totals().unwrap().items, 0);
    assert_eq!(fs::read(queue.path()).unwrap(), before);
    let copies: Vec<_> = fs::read_dir(queue.path().parent().unwrap())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("queue.json.corrupt-")
        })
        .collect();
    assert_eq!(copies.len(), 1);
    assert_eq!(fs::read(&copies[0]).unwrap(), before);
}
