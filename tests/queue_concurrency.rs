// SPDX-License-Identifier: GPL-3.0-or-later
//! Public queue transactions fence concurrent heartbeats, saves and reclaimed owners.
#![allow(clippy::unwrap_used)]

use std::{fs, path::PathBuf, sync::mpsc, thread, time::Duration};

use megabasterd_cli::{
    error::Error,
    storage::{
        files::Store,
        queue::{JobStatus, JobType, Queue, QueuePayload},
    },
};

const SIGNAL_TIMEOUT: Duration = Duration::from_secs(3);

fn fixture() -> (private_tempfile::TempDir, Queue) {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".ci-work/queue-concurrency");
    fs::create_dir_all(&base).unwrap();
    let scratch = private_tempfile::tempdir_in(base).unwrap();
    let queue = Queue::new(scratch.path().join("private space/queue.json"));
    (scratch, queue)
}

fn payload() -> QueuePayload {
    QueuePayload {
        source: "https://mega.nz/file/example#synthetic-file-key".into(),
        destination: "output with  two spaces".into(),
        account: None,
        password: Some("synthetic-link-password".into()),
        error: None,
    }
}

fn race<A: Send, B: Send>(
    left: impl FnOnce() -> A + Send,
    right: impl FnOnce() -> B + Send,
) -> (A, B) {
    thread::scope(|scope| {
        let (ready, waiting) = mpsc::sync_channel(2);
        let (go_left, start_left) = mpsc::sync_channel(1);
        let (go_right, start_right) = mpsc::sync_channel(1);
        let left_ready = ready.clone();
        let left = scope.spawn(move || {
            left_ready.try_send(()).unwrap();
            start_left.recv_timeout(SIGNAL_TIMEOUT).unwrap();
            left()
        });
        let right = scope.spawn(move || {
            ready.try_send(()).unwrap();
            start_right.recv_timeout(SIGNAL_TIMEOUT).unwrap();
            right()
        });
        for _ in 0..2 {
            waiting.recv_timeout(SIGNAL_TIMEOUT).unwrap();
        }
        go_left.try_send(()).unwrap();
        go_right.try_send(()).unwrap();
        (left.join().unwrap(), right.join().unwrap())
    })
}

#[test]
fn racing_heartbeats_and_completion_leave_parseable_done_state_without_a_lease() {
    let (_scratch, queue) = fixture();
    let id = queue.add(JobType::Download, &payload()).unwrap();
    let claim = queue.claim_next("run-1").unwrap().unwrap();
    assert!(queue.touch(&claim.item).unwrap());
    let (done, completed) = mpsc::sync_channel(1);
    let heartbeat_queue = &queue;
    let lease = &claim.item;
    race(
        move || {
            for _ in 0..4 {
                heartbeat_queue.touch(lease).unwrap();
                let raw = fs::read(heartbeat_queue.path()).unwrap();
                serde_json::from_slice::<serde_json::Value>(&raw).unwrap();
            }
            completed.recv_timeout(SIGNAL_TIMEOUT).unwrap();
            assert!(!heartbeat_queue.touch(lease).unwrap());
        },
        || {
            Queue::new(queue.path())
                .finish(&claim.item, JobStatus::Done, None)
                .unwrap();
            done.try_send(()).unwrap();
        },
    );
    let saved = Queue::new(queue.path()).list().unwrap().remove(0);
    assert_eq!(saved.id, id);
    assert_eq!(saved.status, JobStatus::Done);
    assert_eq!(saved.lease_epoch, 1);
    assert!(saved.run_id.is_none() && saved.heartbeat_iso.is_none());
    assert!(saved.finished_iso.is_some());
    assert_eq!(queue.payload(&saved).unwrap().source, payload().source);
}

#[test]
fn concurrent_private_saves_keep_all_four_jobs_and_consume_staging_files() {
    let (_scratch, queue) = fixture();
    let ids: Vec<_> = (0..4)
        .map(|_| queue.add(JobType::Download, &payload()).unwrap())
        .collect();
    let claims: Vec<_> = (0..4)
        .map(|_| queue.claim_next("run-1").unwrap().unwrap())
        .collect();
    let mutate = |claims: &[megabasterd_cli::storage::queue::Claim]| {
        let manager = Queue::new(queue.path());
        for claim in claims {
            assert!(manager.touch(&claim.item).unwrap());
            manager
                .finish(&claim.item, JobStatus::Failed, Some("controlled failure"))
                .unwrap();
            assert!(manager.retry(&claim.item.id).unwrap());
            assert!(!manager.touch(&claim.item).unwrap());
        }
    };
    race(|| mutate(&claims[..2]), || mutate(&claims[2..]));
    let saved = Queue::new(queue.path()).list().unwrap();
    assert_eq!(saved.len(), 4);
    assert_eq!(
        saved.iter().map(|item| &item.id).collect::<Vec<_>>(),
        ids.iter().collect::<Vec<_>>()
    );
    for item in saved {
        assert_eq!(item.status, JobStatus::Pending);
        assert_eq!(item.lease_epoch, 1);
        assert!(item.run_id.is_none() && item.heartbeat_iso.is_none());
        let decoded = queue.payload(&item).unwrap();
        assert_eq!(decoded.password.as_deref(), Some("synthetic-link-password"));
        assert!(decoded.error.is_none());
    }
    assert!(
        fs::read_dir(queue.path().parent().unwrap())
            .unwrap()
            .all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp"))
    );
}

#[test]
fn reclaimed_generation_finishes_before_the_parked_stale_writer_is_refused() {
    let (_scratch, queue) = fixture();
    let id = queue.add(JobType::Download, &payload()).unwrap();
    let claim = queue.claim_next("run-A").unwrap().unwrap();
    let stale = claim.item.clone();
    let locked = Store::new(queue.path()).lock().unwrap();
    let mut data: serde_json::Value = locked.load().unwrap().unwrap();
    data["items"][0]["heartbeat_iso"] = "2000-01-01T00:00:00Z".into();
    locked.save(&data).unwrap();
    drop(locked);
    // Native execution ownership is released only after the old executor has stopped.
    drop(claim);
    let (done, completed) = mpsc::sync_channel(1);
    let late_queue = &queue;
    race(
        || {
            let manager = Queue::new(queue.path());
            let current = manager.claim_next("run-B").unwrap().unwrap();
            assert_eq!(current.item.id, id);
            assert_eq!(current.item.lease_epoch, 2);
            manager
                .finish(&current.item, JobStatus::Done, None)
                .unwrap();
            done.try_send(()).unwrap();
        },
        move || {
            completed.recv_timeout(SIGNAL_TIMEOUT).unwrap();
            let before = fs::read(late_queue.path()).unwrap();
            assert!(matches!(
                late_queue.finish(&stale, JobStatus::Failed, Some("late failure")),
                Err(Error::Busy(_))
            ));
            assert!(!late_queue.touch(&stale).unwrap());
            assert_eq!(fs::read(late_queue.path()).unwrap(), before);
        },
    );
    let saved = Queue::new(queue.path()).list().unwrap().remove(0);
    assert_eq!(saved.id, id);
    assert_eq!(saved.status, JobStatus::Done);
    assert_eq!(saved.lease_epoch, 2);
    assert!(saved.run_id.is_none() && saved.heartbeat_iso.is_none());
}

#[path = "common/private_tempfile.rs"]
mod private_tempfile;
