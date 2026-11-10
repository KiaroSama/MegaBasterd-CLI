#![allow(clippy::unwrap_used)]

use megabasterd_cli::{
    cli::queue::{HeartbeatTiming, run},
    error::Error,
    storage::queue::{JobStatus, JobType, Queue, QueuePayload},
    transfers::control::Control,
};

#[test]
fn ambiguous_remote_outcome_aborts_queue_before_a_second_job() {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/queue-outcome");
    std::fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    let queue = Queue::new(scratch.path().join("private/queue.json"));
    let payload = QueuePayload {
        source: "synthetic.bin".into(),
        destination: String::new(),
        account: None,
        password: None,
        error: None,
    };
    queue.add(JobType::Upload, &payload).unwrap();
    queue.add(JobType::Upload, &payload).unwrap();
    let mut calls = 0;
    let result = run(
        &queue,
        &Control::new(),
        HeartbeatTiming::default(),
        |_, _| {
            calls += 1;
            Err(Error::AmbiguousMutation("p"))
        },
    );
    assert!(matches!(result, Err(Error::AmbiguousMutation("p"))));
    assert_eq!(calls, 1);
    let jobs = queue.list().unwrap();
    assert_eq!(jobs[0].status, JobStatus::Active);
    assert_eq!(jobs[1].status, JobStatus::Pending);
}
