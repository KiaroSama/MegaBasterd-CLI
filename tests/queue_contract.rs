// SPDX-License-Identifier: GPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
use std::{fs, path::PathBuf, time::Duration};

use megabasterd_cli::{
    storage::{
        files::Store,
        queue::{JobStatus, JobType, Queue, QueuePayload},
    },
    transfers::control::Control,
};

fn fixture() -> (tempfile::TempDir, Queue) {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".ci-work/queue-tests");
    fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::Builder::new()
        .prefix("queue-")
        .tempdir_in(base)
        .unwrap();
    let queue = Queue::new(scratch.path().join("private space/queue.json"));
    (scratch, queue)
}

fn download() -> QueuePayload {
    QueuePayload {
        source: "https://mega.nz/file/example#synthetic-file-key".into(),
        destination: "output with  two spaces".into(),
        account: None,
        password: Some("synthetic-link-password".into()),
        error: None,
    }
}

#[test]
fn lifecycle_reloads_and_seals_every_private_payload_field() {
    let (_scratch, queue) = fixture();
    let id = queue.add(JobType::Download, &download()).unwrap();
    let other = Queue::new(queue.path());
    let item = other.list().unwrap().remove(0);
    assert_eq!(item.id, id);
    assert_eq!(item.status, JobStatus::Pending);
    let payload = other.payload(&item).unwrap();
    assert_eq!(payload.source, download().source);
    assert_eq!(payload.destination, "output with  two spaces");
    assert_eq!(payload.password.as_deref(), Some("synthetic-link-password"));
    let raw = fs::read_to_string(queue.path()).unwrap();
    for secret in [
        "synthetic-file-key",
        "synthetic-link-password",
        "output with  two spaces",
    ] {
        assert!(!raw.contains(secret));
    }
    let claimed = queue.claim_next("run-a").unwrap().unwrap();
    assert_eq!(claimed.item.lease_epoch, 1);
    assert!(other.claim_next("run-b").unwrap().is_none());
    assert!(other.touch(&claimed.item).unwrap());
    queue
        .finish(
            &claimed.item,
            JobStatus::Failed,
            Some("password=synthetic-link-password"),
        )
        .unwrap();
    assert!(!other.touch(&claimed.item).unwrap());
    assert!(other.retry(&id).unwrap());
    assert_eq!(
        other.payload(&other.list().unwrap()[0]).unwrap().error,
        None
    );
    drop(claimed);
    let next = other.claim_next("run-b").unwrap().unwrap();
    assert_eq!(next.item.lease_epoch, 2);
    other.finish(&next.item, JobStatus::Done, None).unwrap();
    assert!(!queue.retry(&id).unwrap());
    drop(next);
    assert_eq!(queue.clear_done().unwrap(), 1);
    assert!(queue.list().unwrap().is_empty());
    assert!(!queue.remove(&id).unwrap());
    assert!(queue.path().with_file_name("queue.json.lock").exists());
}

#[test]
fn runner_records_failures_continues_and_interrupts_cancel_without_claiming_more() {
    use megabasterd_cli::cli::queue::{HeartbeatTiming, run};
    let (_scratch, queue) = fixture();
    let first = queue.add(JobType::Download, &download()).unwrap();
    let mut upload = download();
    upload.account = Some("synthetic-account".into());
    let second = queue.add(JobType::Upload, &upload).unwrap();
    let mut order = Vec::new();
    let summary = run(
        &queue,
        &Control::new(),
        HeartbeatTiming::default(),
        |item, payload| {
            order.push(item.id.clone());
            if item.id == first {
                Err(megabasterd_cli::error::Error::invalid(
                    "controlled transfer failure",
                ))
            } else {
                assert_eq!(payload.account.as_deref(), Some("synthetic-account"));
                Ok(())
            }
        },
    )
    .unwrap();
    assert_eq!(order, [first.clone(), second]);
    assert_eq!((summary.succeeded, summary.failed), (1, 1));
    assert_eq!(queue.list().unwrap()[0].status, JobStatus::Failed);
    assert!(queue.retry(&first).unwrap());
    let later = queue.add(JobType::Download, &download()).unwrap();
    let control = Control::new();
    let mut called = 0;
    let error = run(&queue, &control, HeartbeatTiming::default(), |_, _| {
        called += 1;
        control.cancel();
        Err(megabasterd_cli::error::Error::Canceled)
    })
    .unwrap_err();
    assert_eq!(error.code(), "cancelled");
    assert_eq!(called, 1);
    let items = queue.list().unwrap();
    assert_eq!(items[0].status, JobStatus::Interrupted);
    assert_eq!(
        items.iter().find(|v| v.id == later).unwrap().status,
        JobStatus::Pending
    );
}

fn expire(queue: &Queue) {
    let locked = Store::new(queue.path()).lock().unwrap();
    let mut data: serde_json::Value = locked.load().unwrap().unwrap();
    data["items"][0]["heartbeat_iso"] = "2000-01-01T00:00:00Z".into();
    locked.save(&data).unwrap();
}

#[test]
fn successful_callback_is_not_requeued_when_cancel_races_with_its_return() {
    use megabasterd_cli::cli::queue::{HeartbeatTiming, run};
    let (_scratch, queue) = fixture();
    queue.add(JobType::Download, &download()).unwrap();
    let control = Control::new();
    let result = run(&queue, &control, HeartbeatTiming::default(), |_, _| {
        control.cancel();
        Ok(())
    });
    assert!(result.is_err());
    assert_eq!(queue.list().unwrap()[0].status, JobStatus::Done);
    assert!(queue.claim_next("later-run").unwrap().is_none());
}

#[test]
fn native_execution_lock_blocks_recovery_and_expired_generation_cannot_write() {
    for next_run in ["same-run", "other-run"] {
        let (_scratch, queue) = fixture();
        let id = queue.add(JobType::Download, &download()).unwrap();
        assert_eq!(queue.list().unwrap()[0].lease_epoch, 0);
        let claim = queue.claim_next("same-run").unwrap().unwrap();
        let stale = claim.item.clone();
        assert_eq!(stale.lease_epoch, 1);
        let other = Queue::new(queue.path());
        let before = fs::read(queue.path()).unwrap();
        assert!(other.recover_interrupted().unwrap().is_empty());
        assert!(other.claim_next("competitor").unwrap().is_none());
        assert_eq!(fs::read(queue.path()).unwrap(), before);
        let live = other.list().unwrap().remove(0);
        assert_eq!(live.id, id);
        assert_eq!(live.status, JobStatus::Active);
        assert_eq!(live.run_id.as_deref(), Some("same-run"));
        assert_eq!(live.lease_epoch, 1);
        assert_eq!(live.heartbeat_iso, stale.heartbeat_iso);
        let mut wrong_owner = stale.clone();
        wrong_owner.run_id = Some("not-the-owner".into());
        assert!(!other.touch(&wrong_owner).unwrap());
        assert_eq!(fs::read(queue.path()).unwrap(), before);
        assert!(other.touch(&stale).unwrap());
        let current = other.list().unwrap().remove(0);
        assert!(current.heartbeat_iso >= stale.heartbeat_iso);
        assert_eq!(current.status, JobStatus::Active);
        expire(&queue);
        let expired = fs::read(queue.path()).unwrap();
        assert!(other.recover_interrupted().unwrap().is_empty());
        assert!(other.claim_next("other-run").unwrap().is_none());
        assert_eq!(fs::read(queue.path()).unwrap(), expired);
        assert!(matches!(
            queue.finish(&stale, JobStatus::Done, None),
            Err(megabasterd_cli::error::Error::Busy(_))
        ));
        assert!(!queue.touch(&stale).unwrap());
        assert!(queue.remove(&id).is_err());
        assert!(queue.reset().is_err());
        drop(claim);
        assert_eq!(other.recover_interrupted().unwrap(), [id.clone()]);
        let recovered = other.list().unwrap().remove(0);
        assert_eq!(recovered.status, JobStatus::Interrupted);
        assert!(recovered.run_id.is_none() && recovered.heartbeat_iso.is_none());
        assert!(recovered.finished_iso.is_none());
        let new = other.claim_next(next_run).unwrap().unwrap();
        assert_eq!(new.item.id, id);
        assert_eq!(new.item.lease_epoch, 2);
        assert_eq!(new.item.run_id.as_deref(), Some(next_run));
        let before = fs::read(queue.path()).unwrap();
        for status in [JobStatus::Done, JobStatus::Failed, JobStatus::Interrupted] {
            assert!(matches!(
                queue.finish(&stale, status, Some("late")),
                Err(megabasterd_cli::error::Error::Busy(_))
            ));
            assert_eq!(fs::read(queue.path()).unwrap(), before);
        }
        assert!(!queue.touch(&stale).unwrap());
        assert_eq!(fs::read(queue.path()).unwrap(), before);
        other.finish(&new.item, JobStatus::Done, None).unwrap();
        let completed = fs::read(queue.path()).unwrap();
        assert!(matches!(
            queue.finish(&stale, JobStatus::Failed, Some("late")),
            Err(megabasterd_cli::error::Error::Busy(_))
        ));
        assert!(!queue.touch(&stale).unwrap());
        assert_eq!(fs::read(queue.path()).unwrap(), completed);
        assert_eq!(queue.list().unwrap()[0].status, JobStatus::Done);
    }
}

#[test]
fn current_owner_can_finish_each_supported_status_and_terminal_jobs_ignore_late_heartbeats() {
    for status in [
        JobStatus::Done,
        JobStatus::Failed,
        JobStatus::Interrupted,
        JobStatus::Canceled,
    ] {
        let (_scratch, queue) = fixture();
        let id = queue.add(JobType::Download, &download()).unwrap();
        let claim = queue.claim_next("run-A").unwrap().unwrap();
        let other = Queue::new(queue.path());
        other
            .finish(&claim.item, status, Some("controlled outcome"))
            .unwrap();
        let saved = queue.list().unwrap().remove(0);
        assert_eq!(saved.id, id);
        assert_eq!(saved.status, status);
        assert!(saved.run_id.is_none() && saved.heartbeat_iso.is_none());
        assert_eq!(
            saved.finished_iso.is_some(),
            status != JobStatus::Interrupted
        );
        assert_eq!(saved.lease_epoch, 1);
        let before = fs::read(queue.path()).unwrap();
        assert!(!queue.touch(&claim.item).unwrap());
        assert_eq!(fs::read(queue.path()).unwrap(), before);
        assert_eq!(
            queue.payload(&saved).unwrap().password.as_deref(),
            Some("synthetic-link-password")
        );
    }
}

#[test]
fn independent_managers_keep_distinct_jobs_and_do_not_resurrect_a_finished_sibling() {
    let (_scratch, queue) = fixture();
    let first = queue.add(JobType::Download, &download()).unwrap();
    let second = queue.add(JobType::Download, &download()).unwrap();
    let other = Queue::new(queue.path());
    let first_claim = queue.claim_next("run-A").unwrap().unwrap();
    let second_claim = other.claim_next("run-B").unwrap().unwrap();
    assert_eq!(first_claim.item.id, first);
    assert_eq!(second_claim.item.id, second);
    assert!(queue.claim_next("run-C").unwrap().is_none());
    other
        .finish(&second_claim.item, JobStatus::Done, None)
        .unwrap();
    queue
        .finish(&first_claim.item, JobStatus::Failed, Some("boom"))
        .unwrap();
    let items = Queue::new(queue.path()).list().unwrap();
    assert_eq!(items[0].status, JobStatus::Failed);
    assert_eq!(items[1].status, JobStatus::Done);
    assert_eq!(
        queue.payload(&items[0]).unwrap().error.as_deref(),
        Some("boom")
    );
}

#[test]
fn expired_crashed_job_is_runnable_again_but_a_failed_sibling_requires_explicit_retry() {
    let (_scratch, queue) = fixture();
    let first = queue.add(JobType::Download, &download()).unwrap();
    let second = queue.add(JobType::Download, &download()).unwrap();
    let failed = queue.claim_next("failed-run").unwrap().unwrap();
    queue
        .finish(&failed.item, JobStatus::Failed, Some("boom"))
        .unwrap();
    drop(failed);
    let crashed = queue.claim_next("dead-run").unwrap().unwrap();
    assert_eq!(crashed.item.id, second);
    drop(crashed);
    let locked = Store::new(queue.path()).lock().unwrap();
    let mut data: serde_json::Value = locked.load().unwrap().unwrap();
    data["items"][1]["heartbeat_iso"] = "2000-01-01T00:00:00Z".into();
    locked.save(&data).unwrap();
    drop(locked);
    let fresh = Queue::new(queue.path());
    assert_eq!(fresh.recover_interrupted().unwrap(), [second.clone()]);
    let items = fresh.list().unwrap();
    assert_eq!(items[0].id, first);
    assert_eq!(items[0].status, JobStatus::Failed);
    assert_eq!(items[1].status, JobStatus::Interrupted);
    let recovered = fresh.claim_next("recovery-run").unwrap().unwrap();
    assert_eq!(recovered.item.id, second);
    assert_eq!(recovered.item.lease_epoch, 2);
    assert!(fresh.claim_next("competitor").unwrap().is_none());
    assert_eq!(fresh.list().unwrap()[0].status, JobStatus::Failed);
}

#[test]
fn corruption_unknown_schema_and_future_version_preserve_original_and_backup() {
    let (_scratch, queue) = fixture();
    queue.add(JobType::Download, &download()).unwrap();
    let valid = fs::read(queue.path()).unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&valid).unwrap();
    let mut duplicate = parsed.clone();
    duplicate["data"]["items"]
        .as_array_mut()
        .unwrap()
        .push(parsed["data"]["items"][0].clone());
    let mut wrong_state = parsed.clone();
    wrong_state["data"]["items"][0]["size"] = true.into();
    let mut unknown = parsed.clone();
    unknown["data"]["items"][0]["password"] = "plaintext is not accepted".into();
    for bad in [
        b"{broken".to_vec(),
        serde_json::to_vec(&duplicate).unwrap(),
        serde_json::to_vec(&wrong_state).unwrap(),
        serde_json::to_vec(&unknown).unwrap(),
    ] {
        fs::write(queue.path(), &bad).unwrap();
        assert!(queue.list().is_err());
        assert!(queue.list().is_err());
        assert!(queue.add(JobType::Download, &download()).is_err());
        assert_eq!(fs::read(queue.path()).unwrap(), bad);
        let backup = queue.reset().unwrap().unwrap();
        assert_eq!(fs::read(queue.path().with_file_name(backup)).unwrap(), bad);
        assert!(queue.list().unwrap().is_empty());
    }
    let mut future = parsed;
    future["version"] = 999.into();
    let future = serde_json::to_vec(&future).unwrap();
    fs::write(queue.path(), &future).unwrap();
    assert!(queue.list().is_err());
    assert!(queue.reset().is_err());
    assert_eq!(fs::read(queue.path()).unwrap(), future);
}

#[test]
fn ciphertext_cannot_move_between_jobs() {
    let (_scratch, queue) = fixture();
    queue.add(JobType::Download, &download()).unwrap();
    queue.add(JobType::Upload, &download()).unwrap();
    let original = fs::read(queue.path()).unwrap();
    let locked = Store::new(queue.path()).lock().unwrap();
    let mut data: serde_json::Value = locked.load().unwrap().unwrap();
    let first = data["items"][0]["enc_payload"].clone();
    data["items"][0]["enc_payload"] = data["items"][1]["enc_payload"].clone();
    data["items"][1]["enc_payload"] = first;
    locked.save(&data).unwrap();
    drop(locked);
    assert!(matches!(
        queue.list(),
        Err(megabasterd_cli::error::Error::Corrupt(_))
    ));
    assert_eq!(
        Store::new(queue.path())
            .lock()
            .unwrap()
            .load::<serde_json::Value>()
            .unwrap()
            .unwrap(),
        data
    );
    fs::write(queue.path(), original).unwrap();
    let restored = queue.list().unwrap();
    assert_eq!(restored.len(), 2);
    for item in restored {
        assert_eq!(
            queue.payload(&item).unwrap().password.as_deref(),
            Some("synthetic-link-password")
        );
    }
}

#[test]
fn paused_executor_keeps_heartbeat_alive_and_reaps_it_after_resume() {
    use megabasterd_cli::cli::queue::{HeartbeatTiming, run};
    use std::sync::mpsc;
    let (_scratch, queue) = fixture();
    queue.add(JobType::Download, &download()).unwrap();
    let control = Control::new();
    let paused = control.clone();
    let (started, ready) = mpsc::sync_channel(1);
    let (done, finished) = mpsc::sync_channel(1);
    let path = queue.path().to_owned();
    let worker = std::thread::spawn(move || {
        let result = run(
            &Queue::new(path),
            &paused,
            HeartbeatTiming {
                interval: Duration::from_millis(10),
                grace: Duration::from_secs(1),
            },
            |_, _| {
                paused.toggle_pause()?;
                let _ = started.try_send(());
                paused.checkpoint()
            },
        );
        let _ = done.try_send(result);
    });
    let ready = ready.recv_timeout(Duration::from_secs(3));
    if ready.is_err() {
        control.cancel();
        worker.join().unwrap();
        panic!("executor never reached pause");
    }
    let result = (|| {
        let first = queue.list()?.remove(0);
        if queue.claim_next("competitor")?.is_some() {
            return Err(megabasterd_cli::error::Error::protocol(
                "paused lease was stolen",
            ));
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        loop {
            if queue.list()?[0].heartbeat_iso != first.heartbeat_iso {
                break;
            }
            if std::time::Instant::now() >= deadline {
                return Err(megabasterd_cli::error::Error::Timeout);
            }
            // Bounded polling observes persisted heartbeat; no blind settle sleep.
            control.wait(Duration::from_millis(5))?;
        }
        control.toggle_pause()?;
        finished
            .recv_timeout(Duration::from_secs(3))
            .map_err(|_| megabasterd_cli::error::Error::Timeout)?
    })();
    if result.is_err() {
        control.cancel();
    }
    worker.join().unwrap();
    assert_eq!(result.unwrap().succeeded, 1);
    assert_eq!(queue.list().unwrap()[0].status, JobStatus::Done);
}

#[test]
fn lost_heartbeat_cancels_inflight_executor_and_refuses_following_job() {
    use megabasterd_cli::cli::queue::{HeartbeatTiming, run};
    use std::sync::mpsc;
    let (_scratch, queue) = fixture();
    queue.add(JobType::Download, &download()).unwrap();
    let later = queue.add(JobType::Download, &download()).unwrap();
    let control = Control::new();
    let worker_control = control.clone();
    let (started, ready) = mpsc::sync_channel(1);
    let (done, finished) = mpsc::sync_channel(1);
    let path = queue.path().to_owned();
    let worker = std::thread::spawn(move || {
        let result = run(
            &Queue::new(path),
            &worker_control,
            HeartbeatTiming {
                interval: Duration::from_millis(10),
                grace: Duration::from_secs(1),
            },
            |_, _| {
                let _ = started.try_send(());
                worker_control.wait(Duration::from_secs(3))
            },
        );
        let _ = done.try_send(result);
    });
    if ready.recv_timeout(Duration::from_secs(3)).is_err() {
        control.cancel();
        worker.join().unwrap();
        panic!("executor did not start");
    }
    let injection = (|| -> megabasterd_cli::error::Result<()> {
        let locked = Store::new(queue.path())
            .with_timeout(Duration::from_secs(1))
            .lock()?;
        let mut data: serde_json::Value = locked.load()?.unwrap();
        data["items"][0]["lease_epoch"] = 2.into();
        locked.save(&data)
    })();
    if injection.is_err() {
        control.cancel();
        worker.join().unwrap();
        panic!("could not inject changed lease");
    }
    let result = finished.recv_timeout(Duration::from_secs(3));
    if result.is_err() {
        control.cancel();
    }
    worker.join().unwrap();
    assert!(result.unwrap().is_err());
    assert!(control.is_canceled());
    let items = queue.list().unwrap();
    assert_eq!(items[0].status, JobStatus::Active);
    assert_eq!(
        items.iter().find(|v| v.id == later).unwrap().status,
        JobStatus::Pending
    );
}
