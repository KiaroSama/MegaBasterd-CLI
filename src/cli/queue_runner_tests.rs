// SPDX-License-Identifier: GPL-3.0-or-later
//! Parsed queue commands exercise actual locks and heartbeat cancellation at the executor seam.
#![allow(clippy::unwrap_used)]

use std::{
    fs,
    io::{self, Write},
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use clap::Parser;

use super::*;
use crate::{
    cli::args::{Cli, Command},
    storage::files::Store,
    terminal::output::Output,
};

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);
impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut output = self.0.lock().unwrap();
        if bytes.len() > (16 * 1024usize).saturating_sub(output.len()) {
            return Err(io::Error::other("Queue fixture output limit exceeded"));
        }
        output.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn fixture() -> (
    crate::test_support::TempDir,
    Context,
    Queue,
    Capture,
    Capture,
) {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/queue-runner");
    fs::create_dir_all(&base).unwrap();
    let scratch = crate::test_support::tempdir_in(base).unwrap();
    let mut context = Context::test_context(scratch.path());
    let stdout = Capture::default();
    let stderr = Capture::default();
    context.output = Output::with_writers(false, true, stdout.clone(), stderr.clone());
    let queue = Queue::new(context.paths.queue());
    (scratch, context, queue, stdout, stderr)
}

fn add(queue: &Queue) -> String {
    queue
        .add(
            JobType::Download,
            &QueuePayload {
                source: "https://mega.nz/file/abc123#xyz".into(),
                destination: String::new(),
                account: None,
                password: Some("synthetic-queue-password".into()),
                error: None,
            },
        )
        .unwrap()
}

fn command() -> args::Queue {
    let cli = Cli::try_parse_from(["mb", "-q", "queue", "run"]).unwrap();
    let Some(Command::Queue(command)) = cli.command else {
        panic!("queue run did not parse");
    };
    command
}

fn timing() -> HeartbeatTiming {
    HeartbeatTiming {
        interval: Duration::from_millis(20),
        grace: Duration::from_secs(1),
    }
}

fn assert_busy(
    context: &Context,
    result: Result<()>,
    stdout: &Capture,
    stderr: &Capture,
    word: &str,
) {
    let error = result.unwrap_err();
    assert!(matches!(&error, Error::Busy(_)));
    assert_eq!(error.code(), "resource_busy");
    assert_eq!(error.exit_code(), 1);
    context.report_error(&error);
    assert!(stdout.0.lock().unwrap().is_empty());
    let diagnostic = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
    assert!(diagnostic.contains(word));
    for forbidden in [
        "synthetic-queue-password",
        "panicked at",
        "Traceback",
        "completed.",
    ] {
        assert!(!diagnostic.contains(forbidden));
    }
}

#[test]
fn held_queue_lock_refuses_claim_and_parsed_run_then_succeeds_after_release() {
    let (_scratch, mut context, queue, stdout, stderr) = fixture();
    let id = add(&queue);
    let queue = queue.with_lock_timeout(Duration::ZERO);
    let owner = Store::new(queue.path()).lock().unwrap();
    let before = fs::read(queue.path()).unwrap();
    let error = queue.claim_next("run-1").err().unwrap();
    assert!(matches!(error, Error::Busy(_)));
    assert!(
        error
            .to_string()
            .contains("retry when the other operation finishes")
    );
    let mut called = 0;
    let result = handle_with(&mut context, command(), &queue, timing(), |_, _, _, _| {
        called += 1;
        Ok(())
    });
    assert_busy(&context, result, &stdout, &stderr, "Saved-data lock");
    assert_eq!(called, 0);
    assert_eq!(fs::read(queue.path()).unwrap(), before);
    drop(owner);
    let claim = queue.claim_next("after-release").unwrap().unwrap();
    assert_eq!(claim.item.id, id);
    queue
        .finish(&claim.item, JobStatus::Interrupted, None)
        .unwrap();
    drop(claim);
    let queue = Queue::new(queue.path());
    handle_with(
        &mut context,
        command(),
        &queue,
        timing(),
        |_, item, _, _| {
            assert_eq!(item.id, id);
            called += 1;
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(called, 1);
    assert_eq!(queue.list().unwrap()[0].status, JobStatus::Done);
    assert!(!context.paths.logs.exists() && !context.paths.output.exists());
}

#[test]
fn sustained_lock_contention_stops_the_inflight_executor_within_heartbeat_grace() {
    let (_scratch, mut context, queue, stdout, stderr) = fixture();
    let first = add(&queue);
    let later = add(&queue);
    let mut called = 0;
    let mut held_bytes = Vec::new();
    let started = Instant::now();
    let result = handle_with(
        &mut context,
        command(),
        &queue,
        timing(),
        |context, item, _, _| {
            assert_eq!(item.id, first);
            called += 1;
            let owner = Store::new(queue.path())
                .with_timeout(Duration::from_secs(1))
                .lock()?;
            held_bytes = fs::read(queue.path())?;
            // The four-second ceiling is a failure bound, not a settle sleep.
            let result = context.control.wait(Duration::from_secs(4));
            assert!(matches!(&result, Err(Error::Canceled)));
            drop(owner);
            result
        },
    );
    assert_busy(&context, result, &stdout, &stderr, "heartbeat");
    assert!(started.elapsed() < Duration::from_millis(1500));
    assert_eq!(called, 1);
    assert!(context.control.is_canceled());
    assert_eq!(fs::read(queue.path()).unwrap(), held_bytes);
    let items = queue.list().unwrap();
    assert_eq!(items[0].id, first);
    assert_eq!(items[0].status, JobStatus::Active);
    assert_eq!(items[1].id, later);
    assert_eq!(items[1].status, JobStatus::Pending);
    let execution = queue
        .path()
        .with_file_name(format!("queue.json.job-{first}"));
    drop(
        Store::new(execution)
            .with_timeout(Duration::ZERO)
            .lock()
            .unwrap(),
    );
}

#[test]
fn changed_generation_cancels_the_running_executor_and_never_claims_the_following_job() {
    let (_scratch, mut context, queue, stdout, stderr) = fixture();
    let first = add(&queue);
    let later = add(&queue);
    let mut called = 0;
    let result = handle_with(
        &mut context,
        command(),
        &queue,
        timing(),
        |context, item, _, _| {
            assert_eq!(item.id, first);
            called += 1;
            let owner = Store::new(queue.path())
                .with_timeout(Duration::from_secs(1))
                .lock()?;
            let mut data: serde_json::Value = owner.load()?.unwrap();
            data["items"][0]["lease_epoch"] = 2.into();
            owner.save(&data)?;
            drop(owner);
            let result = context.control.wait(Duration::from_secs(2));
            assert!(matches!(&result, Err(Error::Canceled)));
            result
        },
    );
    assert_busy(&context, result, &stdout, &stderr, "lease");
    assert_eq!(called, 1);
    assert!(context.control.is_canceled());
    let items = queue.list().unwrap();
    assert_eq!(items[0].status, JobStatus::Active);
    assert_eq!(items[0].lease_epoch, 2);
    assert_eq!(items[1].id, later);
    assert_eq!(items[1].status, JobStatus::Pending);
}

#[test]
fn healthy_parsed_run_renews_its_lease_and_completes_the_one_byte_output() {
    let (scratch, mut context, queue, stdout, stderr) = fixture();
    let id = add(&queue);
    let output = scratch.path().join("output.bin");
    let mut called = 0;
    handle_with(
        &mut context,
        command(),
        &queue,
        timing(),
        |context, item, _, _| {
            assert_eq!(item.id, id);
            called += 1;
            let first = queue.list()?.remove(0).heartbeat_iso;
            let deadline = Instant::now() + Duration::from_secs(1);
            while queue.list()?[0].heartbeat_iso == first {
                if Instant::now() >= deadline {
                    return Err(Error::Timeout);
                }
                context.control.wait(Duration::from_millis(5))?;
            }
            fs::write(&output, b"x")?;
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(called, 1);
    assert_eq!(fs::read(output).unwrap(), b"x");
    assert_eq!(queue.list().unwrap()[0].status, JobStatus::Done);
    assert!(!context.control.is_canceled());
    assert!(stdout.0.lock().unwrap().is_empty());
    assert!(stderr.0.lock().unwrap().is_empty());
}
