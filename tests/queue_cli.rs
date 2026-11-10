// SPDX-License-Identifier: GPL-3.0-or-later
//! Real headless commands refuse corrupt queue storage without exposing encrypted job secrets.
#![allow(clippy::unwrap_used)]

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use megabasterd_cli::{
    platform::process,
    storage::{
        files::Store,
        paths::Paths,
        queue::{JobType, Queue, QueuePayload},
    },
    transfers::control::Control,
};

struct Fixture {
    _scratch: tempfile::TempDir,
    paths: Paths,
    temporary: PathBuf,
    cwd: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/queue-cli");
        fs::create_dir_all(&base).unwrap();
        let scratch = tempfile::tempdir_in(base).unwrap();
        let root = scratch.path().join("runtime with spaces");
        let paths = Paths {
            user: root.join("User/native-v2"),
            logs: root.join("private logs"),
            output: root.join("Output"),
            root,
        };
        let temporary = scratch.path().join("private temporary");
        let cwd = scratch.path().join("unrelated cwd");
        fs::create_dir(&temporary).unwrap();
        fs::create_dir(&cwd).unwrap();
        Self {
            _scratch: scratch,
            paths,
            temporary,
            cwd,
        }
    }

    fn run(&self, arguments: &[&str]) {
        let mut command = Command::new(env!("CARGO_BIN_EXE_mb"));
        command.current_dir(&self.cwd).env_clear();
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
            command.env(key, &self.temporary);
        }
        command
            .env("MEGABASTERD_PROJECT_ROOT", &self.paths.root)
            .env("MEGABASTERD_USER_DIR", self.paths.user.parent().unwrap())
            .env("MEGABASTERD_LOG_DIR", &self.paths.logs)
            .env("HOOKMAKER_MAX_TEST_WORKERS", "1")
            .args(["-vv", "--log-file", "queue"])
            .args(arguments);
        let output = process::run_command(
            command,
            Duration::from_secs(5),
            16 * 1024,
            16 * 1024,
            &Control::new(),
            None,
        )
        .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        let stderr = std::str::from_utf8(&output.stderr).unwrap();
        assert!(stderr.contains("Queue"));
        self.safe_text(stderr);
        assert!(!self.paths.output.exists());
        assert_eq!(fs::read_dir(&self.cwd).unwrap().count(), 0);
    }

    fn safe_text(&self, text: &str) {
        for forbidden in [
            "topsecretpw",
            "fixture-account@example.invalid",
            "synthetic-queue-key-fragment",
            "panicked at",
            "Traceback",
            "\u{1b}[",
        ] {
            assert!(!text.contains(forbidden), "Unsafe queue diagnostic");
        }
    }

    fn logs(&self, expected: usize) {
        let logs: Vec<_> = fs::read_dir(&self.paths.logs)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(logs.len(), expected);
        for path in logs {
            assert!(
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("mb_")
            );
            let text = fs::read_to_string(path).unwrap();
            self.safe_text(&text);
            assert!(text.contains("Started") && text.contains("Finished"));
            assert!(text.contains("\"exit_code\":1"));
        }
    }

    fn backup(&self, expected: &[u8]) {
        let copies: Vec<_> = fs::read_dir(self.paths.queue().parent().unwrap())
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
        assert_eq!(fs::read(&copies[0]).unwrap(), expected);
        assert_eq!(fs::read(self.paths.queue()).unwrap(), expected);
    }
}

#[test]
fn actual_corrupt_queue_run_and_add_refuse_with_exit_one_and_preserve_original_bytes() {
    let fixture = Fixture::new();
    let raw = b"not json at all";
    Store::new(fixture.paths.queue())
        .lock()
        .unwrap()
        .write_bytes(raw)
        .unwrap();
    for arguments in [
        vec!["run"],
        vec!["add-download", "https://mega.nz/file/a#b"],
    ] {
        fixture.run(&arguments);
        fixture.backup(raw);
        assert!(
            !fixture
                .paths
                .queue()
                .with_file_name("queue.json.key")
                .exists()
        );
    }
    fixture.logs(2);
}

#[test]
fn actual_missing_key_recovery_keeps_ciphertext_and_secrets_out_of_debug_logs() {
    let fixture = Fixture::new();
    let queue = Queue::new(fixture.paths.queue());
    queue
        .add(
            JobType::Download,
            &QueuePayload {
                source: "https://mega.nz/file/ID#synthetic-queue-key-fragment".into(),
                destination: "output with  two spaces".into(),
                account: Some("fixture-account@example.invalid".into()),
                password: Some("topsecretpw".into()),
                error: None,
            },
        )
        .unwrap();
    let raw = fs::read(queue.path()).unwrap();
    let key_path = queue.path().with_file_name("queue.json.key");
    let key = fs::read(&key_path).unwrap();
    fs::remove_file(&key_path).unwrap();
    for arguments in [
        vec!["list"],
        vec!["run"],
        vec!["add-download", "https://mega.nz/file/a#b"],
    ] {
        fixture.run(&arguments);
        fixture.backup(&raw);
        assert!(!key_path.exists());
    }
    fixture.logs(3);
    use std::io::Write;
    let directory = megabasterd_cli::platform::secure_files::PrivateDirectory::open(
        queue.path().parent().unwrap(),
    )
    .unwrap();
    directory
        .open_private(std::ffi::OsStr::new("queue.json.key"), true)
        .unwrap()
        .write_all(&key)
        .unwrap();
    assert_eq!(
        queue
            .payload(&queue.list().unwrap()[0])
            .unwrap()
            .password
            .as_deref(),
        Some("topsecretpw")
    );
    assert_eq!(fs::read(queue.path()).unwrap(), raw);
}
