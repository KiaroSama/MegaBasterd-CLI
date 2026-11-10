// SPDX-License-Identifier: GPL-3.0-or-later
//! Independent native processes share claims and exact corruption copies, not memory.
#![allow(clippy::unwrap_used)]

use std::{
    fs,
    path::PathBuf,
    time::{Duration, Instant},
};

use megabasterd_cli::{
    error::Error,
    storage::{
        files::Store,
        queue::{JobStatus, JobType, Queue, QueuePayload},
    },
    transfers::control::Control,
};

const CLAIM_CASE: &str = "independent_process_claims_once_recovers_crash_and_refuses_old_writer";
const CORRUPT_CASE: &str =
    "independent_processes_preserve_one_exact_corruption_copy_without_creating_a_key";
const CORRUPT: &[u8] = b"still not json";

fn fixture() -> (private_tempfile::TempDir, Queue) {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".ci-work/queue-processes");
    fs::create_dir_all(&base).unwrap();
    let scratch = private_tempfile::tempdir_in(base).unwrap();
    let queue = Queue::new(scratch.path().join("private space/queue.json"));
    (scratch, queue)
}

struct OwnedChild(std::process::Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn child(queue: &Queue, mode: &str, index: usize, test: &str) -> OwnedChild {
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    let directory = queue.path().parent().unwrap();
    let temporary = directory.join(format!("child-{mode}-{index}"));
    fs::create_dir_all(&temporary).unwrap();
    command.current_dir(directory).env_clear();
    for key in [
        "PATH",
        "SystemRoot",
        "WINDIR",
        "PATHEXT",
        "LD_LIBRARY_PATH",
        "DYLD_LIBRARY_PATH",
    ] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    for key in [
        "HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "TMP",
        "TEMP",
        "TMPDIR",
    ] {
        command.env(key, &temporary);
    }
    command
        .args(["--exact", test, "--test-threads=1"])
        .env("HOOKMAKER_MAX_TEST_WORKERS", "1")
        .env("MB_QUEUE_TEST_PATH", queue.path())
        .env("MB_QUEUE_TEST_MODE", mode)
        .env("MB_QUEUE_TEST_INDEX", index.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    OwnedChild(command.spawn().unwrap())
}

fn wait(child: &mut OwnedChild) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success(), "queue fixture subprocess failed");
            return;
        }
        assert!(
            Instant::now() < deadline,
            "queue fixture subprocess timed out"
        );
        Control::new().wait(Duration::from_millis(5)).unwrap();
    }
}

fn release_ready_children(queue: &Queue) {
    let directory = queue.path().parent().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !(directory.join("ready-0").exists() && directory.join("ready-1").exists()) {
        assert!(
            Instant::now() < deadline,
            "queue processes never became ready"
        );
        Control::new().wait(Duration::from_millis(5)).unwrap();
    }
    fs::write(directory.join("start"), b"start").unwrap();
}

fn queue_process_child(path: std::ffi::OsString) {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".ci-work/queue-processes");
    let path = PathBuf::from(path).canonicalize().unwrap();
    assert!(path.starts_with(base.canonicalize().unwrap()));
    let queue = Queue::new(path);
    let mode = std::env::var("MB_QUEUE_TEST_MODE").unwrap();
    let index = std::env::var("MB_QUEUE_TEST_INDEX").unwrap();
    let directory = queue.path().parent().unwrap();
    if mode != "stale" {
        fs::write(directory.join(format!("ready-{index}")), b"ready").unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !directory.join("start").exists() {
            assert!(Instant::now() < deadline);
            Control::new().wait(Duration::from_millis(5)).unwrap();
        }
    }
    match mode.as_str() {
        "claim" => {
            let claim = queue.claim_next(&format!("process-{index}")).unwrap();
            let output = claim
                .as_ref()
                .map_or("NONE", |value| value.item.id.as_str());
            fs::write(directory.join(format!("winner-{index}")), output).unwrap();
        }
        "stale" => {
            let stale: megabasterd_cli::storage::queue::QueueItem =
                Store::new(directory.join("stale.json"))
                    .lock()
                    .unwrap()
                    .load()
                    .unwrap()
                    .unwrap();
            assert!(!queue.touch(&stale).unwrap());
            assert!(matches!(
                queue.finish(&stale, JobStatus::Failed, Some("late process")),
                Err(Error::Busy(_))
            ));
            fs::write(directory.join("stale-refused"), b"refused").unwrap();
        }
        "corrupt" => {
            assert!(matches!(queue.list(), Err(Error::Corrupt(_))));
            assert_eq!(fs::read(queue.path()).unwrap(), CORRUPT);
            assert!(!queue.path().with_file_name("queue.json.key").exists());
            fs::write(directory.join(format!("result-{index}")), b"corrupt").unwrap();
        }
        _ => panic!("unknown queue fixture mode"),
    }
}

#[test]
fn independent_process_claims_once_recovers_crash_and_refuses_old_writer() {
    if let Some(path) = std::env::var_os("MB_QUEUE_TEST_PATH") {
        queue_process_child(path);
        return;
    }
    let (_scratch, queue) = fixture();
    let id = queue
        .add(
            JobType::Download,
            &QueuePayload {
                source: "https://mega.nz/file/example#synthetic-file-key".into(),
                destination: "output with  two spaces".into(),
                account: None,
                password: Some("synthetic-link-password".into()),
                error: None,
            },
        )
        .unwrap();
    let mut children = [
        child(&queue, "claim", 0, CLAIM_CASE),
        child(&queue, "claim", 1, CLAIM_CASE),
    ];
    release_ready_children(&queue);
    for process in &mut children {
        wait(process);
    }
    let directory = queue.path().parent().unwrap();
    let winners = [
        fs::read_to_string(directory.join("winner-0")).unwrap(),
        fs::read_to_string(directory.join("winner-1")).unwrap(),
    ];
    assert_eq!(
        winners.iter().filter(|value| value.as_str() == id).count(),
        1
    );
    assert_eq!(
        winners
            .iter()
            .filter(|value| value.as_str() == "NONE")
            .count(),
        1
    );
    let old = queue.list().unwrap().remove(0);
    assert_eq!(old.lease_epoch, 1);
    Store::new(directory.join("stale.json"))
        .lock()
        .unwrap()
        .save(&old)
        .unwrap();
    let locked = Store::new(queue.path()).lock().unwrap();
    let mut data: serde_json::Value = locked.load().unwrap().unwrap();
    data["items"][0]["heartbeat_iso"] = "2000-01-01T00:00:00Z".into();
    locked.save(&data).unwrap();
    drop(locked);
    let current = queue.claim_next("new-process").unwrap().unwrap();
    assert_eq!(current.item.lease_epoch, 2);
    queue.finish(&current.item, JobStatus::Done, None).unwrap();
    let before = fs::read(queue.path()).unwrap();
    let mut stale = child(&queue, "stale", 2, CLAIM_CASE);
    wait(&mut stale);
    assert_eq!(
        fs::read(directory.join("stale-refused")).unwrap(),
        b"refused"
    );
    assert_eq!(fs::read(queue.path()).unwrap(), before);
    assert_eq!(queue.list().unwrap()[0].status, JobStatus::Done);
}

#[test]
fn independent_processes_preserve_one_exact_corruption_copy_without_creating_a_key() {
    if let Some(path) = std::env::var_os("MB_QUEUE_TEST_PATH") {
        queue_process_child(path);
        return;
    }
    let (_scratch, queue) = fixture();
    Store::new(queue.path())
        .lock()
        .unwrap()
        .write_bytes(CORRUPT)
        .unwrap();
    let mut children = [
        child(&queue, "corrupt", 0, CORRUPT_CASE),
        child(&queue, "corrupt", 1, CORRUPT_CASE),
    ];
    release_ready_children(&queue);
    for process in &mut children {
        wait(process);
    }
    let directory = queue.path().parent().unwrap();
    for index in 0..2 {
        assert_eq!(
            fs::read(directory.join(format!("result-{index}"))).unwrap(),
            b"corrupt"
        );
    }
    let copies: Vec<_> = fs::read_dir(directory)
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
    assert_eq!(fs::read(&copies[0]).unwrap(), CORRUPT);
    assert_eq!(fs::read(queue.path()).unwrap(), CORRUPT);
    assert!(!queue.path().with_file_name("queue.json.key").exists());
    assert!(fs::read_dir(directory).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")
    }));
}

#[path = "common/private_tempfile.rs"]
mod private_tempfile;
