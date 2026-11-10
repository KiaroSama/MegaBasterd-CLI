//! Real queue claims and upload wire receipts across a local post-transfer failure.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use serde_json::{Value, json};

use super::{
    control::{Control, RateLimiter},
    upload,
};
use crate::{
    cli::queue::{HeartbeatTiming, run},
    error::Error,
    protocol::{
        api::Api,
        auth::Session,
        cloud::Cloud,
        test_peer::{self, Response},
    },
    storage::{
        queue::{JobStatus, JobType, Queue, QueuePayload},
        vault::Vault,
    },
    terminal::progress::Progress,
};

#[test]
fn queue_retry_recovers_registered_upload_before_committing_done_without_another_mutation() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/queued-upload-peers");
    std::fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    let source = scratch.path().join("source with  spaces.bin");
    std::fs::write(&source, b"source bytes").unwrap();
    let queue = Queue::new(scratch.path().join("private queue/queue.json"));
    let payload = QueuePayload {
        source: source.to_str().unwrap().into(),
        destination: String::new(),
        account: Some("fixture@example.invalid".into()),
        password: None,
        error: None,
    };
    let job_id = queue.add(JobType::Upload, &payload).unwrap();
    let states = scratch.path().join("private upload states");
    let vault = Vault::new("synthetic queued upload passphrase");
    let mut registrations = 0usize;
    let mut slots = 0usize;
    let (_, requests) = test_peer::with_peer(
        |request| {
            assert_eq!(request.method, "POST");
            if request.path.starts_with("/native-peer-upload/") {
                assert_eq!(request.body.len(), 12);
                return Some(Response {
                    status: 200,
                    headers: vec![],
                    body: b"FCCyf3QV62uAsbARFKbVd8zWyqOQXPFgEL9i".to_vec(),
                });
            }
            let commands: Value = serde_json::from_slice(&request.body).unwrap();
            assert_eq!(commands.as_array().unwrap().len(), 1);
            let result = match commands[0]["a"].as_str().unwrap() {
                "u" => {
                    slots += 1;
                    json!({"p":"https://upload.mega.nz/native-peer-upload/queued"})
                }
                "p" => {
                    registrations += 1;
                    assert_eq!(commands[0]["t"], "ROOT0001");
                    assert_eq!(
                        commands[0]["n"][0]["h"],
                        "FCCyf3QV62uAsbARFKbVd8zWyqOQXPFgEL9i"
                    );
                    json!({"f":[{"h":"FILE0001"}]})
                }
                _ => panic!("unexpected queue upload action"),
            };
            Some(Response {
                status: 200,
                headers: vec![("Content-Type".into(), "application/json".into())],
                body: serde_json::to_vec(&json!([result])).unwrap(),
            })
        },
        |address| {
            let mut cloud = Cloud::new(
                Api::test_peer(address).unwrap(),
                Session {
                    sid: "synthetic-session".into(),
                    master_key: [9; 16],
                    rsa_private_key: None,
                    user_handle: "testuser".into(),
                    email: "fixture@example.invalid".into(),
                },
            );
            let mut epochs = Vec::new();
            let mut finalizations = 0usize;
            for fail_local_reporting in [true, false] {
                let summary = run(
                    &queue,
                    &Control::new(),
                    HeartbeatTiming::default(),
                    |item, decoded| {
                        assert_eq!(item.id, job_id);
                        assert_eq!(decoded.source, payload.source);
                        assert_eq!(decoded.account, payload.account);
                        epochs.push(item.lease_epoch);
                        let progress = Progress::new(false);
                        let row = progress.add("source", 12)?;
                        let uploaded = upload::upload(
                            &mut cloud,
                            &source,
                            "ROOT0001",
                            None,
                            1,
                            &states,
                            &vault,
                            true,
                            Some(&item.id),
                            &RateLimiter::new(0.0)?,
                            &progress,
                            row,
                            &Control::new(),
                        )?;
                        assert_eq!(uploaded.handle, "FILE0001");
                        uploaded.finalize(|| {
                            finalizations += 1;
                            Ok(())
                        })?;
                        if fail_local_reporting {
                            Err(Error::Io(std::io::Error::other(
                                "controlled local reporting failure",
                            )))
                        } else {
                            // The queue, not an early receipt acknowledgement, commits terminal state.
                            Ok(())
                        }
                    },
                )
                .unwrap();
                let saved = queue.list().unwrap().remove(0);
                if fail_local_reporting {
                    assert_eq!((summary.succeeded, summary.failed), (0, 1));
                    assert_eq!(saved.status, JobStatus::Failed);
                    assert!(queue.payload(&saved).unwrap().error.is_some());
                    assert!(queue.retry(&job_id).unwrap());
                } else {
                    assert_eq!((summary.succeeded, summary.failed), (1, 0));
                    assert_eq!(saved.status, JobStatus::Done);
                    assert!(queue.payload(&saved).unwrap().error.is_none());
                    assert!(!queue.retry(&job_id).unwrap());
                    assert!(queue.claim_next("later-run").unwrap().is_none());
                }
            }
            assert_eq!(epochs, [1, 2]);
            assert_eq!(
                finalizations, 1,
                "a completed callback must not repeat on the retained queue receipt"
            );
        },
    );
    assert_eq!(slots, 1);
    assert_eq!(registrations, 1);
    assert_eq!(
        requests.len(),
        3,
        "retry must recover locally without another slot, body or registration"
    );
    assert_eq!(std::fs::read(&source).unwrap(), b"source bytes");
}
