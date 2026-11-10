//! Real configuration commands preserve private values and current native documents.
#![allow(clippy::unwrap_used)]

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use megabasterd_cli::{
    platform::process::{self, ProcessOutput},
    storage::{
        config_store::ConfigStore,
        files::{STORE_VERSION, Store},
        paths::Paths,
    },
    transfers::control::Control,
};
use serde_json::{Value, json};

struct Fixture {
    _scratch: tempfile::TempDir,
    paths: Paths,
    cwd: PathBuf,
    temporary: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/config-cli");
        fs::create_dir_all(&base).unwrap();
        let scratch = tempfile::tempdir_in(base).unwrap();
        let root = scratch.path().join("runtime with spaces");
        let paths = Paths {
            user: root.join("User/native-v2"),
            logs: root.join("private logs"),
            output: root.join("Output"),
            root,
        };
        let cwd = scratch.path().join("unrelated working directory");
        let temporary = scratch.path().join("private temporary");
        fs::create_dir(&cwd).unwrap();
        fs::create_dir(&temporary).unwrap();
        Self {
            _scratch: scratch,
            paths,
            cwd,
            temporary,
        }
    }

    fn run(&self, words: &[&str], expected_exit: i32) -> ProcessOutput {
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
            .args(["--no-log-file", "config"])
            .args(words);
        let output = process::run_command(
            command,
            Duration::from_secs(5),
            32 * 1024,
            16 * 1024,
            &Control::new(),
            None,
        )
        .unwrap();
        assert_eq!(
            output.status.code(),
            Some(expected_exit),
            "{words:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        for surface in [&output.stdout, &output.stderr] {
            let text = std::str::from_utf8(surface).unwrap();
            for forbidden in [
                "hunter2",
                "APIKEY123",
                "s3cr3t",
                "panicked at",
                "Traceback",
                "\u{1b}[",
            ] {
                assert!(!text.contains(forbidden), "Unsafe config command output");
            }
        }
        output
    }

    fn data(&self) -> Value {
        let document: Value =
            serde_json::from_slice(&fs::read(self.paths.config()).unwrap()).unwrap();
        assert_eq!(document["version"], STORE_VERSION);
        assert!(document["data"].is_object());
        document["data"].clone()
    }

    fn only_config_files(&self) {
        self.config_files(None);
    }

    fn config_files(&self, backup: Option<&[u8]>) {
        let directory = self.paths.config().parent().unwrap().to_owned();
        let mut names: Vec<_> = fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        let mut expected = vec![
            std::ffi::OsString::from("config.json"),
            std::ffi::OsString::from("config.json.lock"),
        ];
        if let Some(bytes) = backup {
            use sha2::{Digest, Sha256};
            let name = format!("config.json.corrupt-{}", hex::encode(Sha256::digest(bytes)));
            assert_eq!(fs::read(directory.join(&name)).unwrap(), bytes);
            expected.push(name.into());
        }
        names.sort();
        expected.sort();
        assert_eq!(names, expected);
        for path in [
            self.paths.output.clone(),
            self.paths.logs.clone(),
            self.paths.user.join("Data"),
        ] {
            assert!(
                !path.exists(),
                "Configuration command created unrelated data"
            );
        }
    }
}

#[test]
fn actual_config_commands_redact_nested_secrets_and_refuse_invalid_mutations_without_rewriting() {
    let fixture = Fixture::new();
    assert!(
        fixture
            .run(&["set", "connect_proxy_password", "hunter2"], 0)
            .stdout
            .is_empty()
    );
    assert!(
        fixture
            .run(
                &[
                    "set",
                    "elc_accounts",
                    r#"{"host.example":{"user":"u","api_key":"APIKEY123"}}"#
                ],
                0
            )
            .stdout
            .is_empty()
    );
    assert!(
        fixture
            .run(&["set", "max_workers", "10"], 0)
            .stdout
            .is_empty()
    );
    assert_eq!(fixture.data()["connect_proxy_password"], "hunter2");
    assert_eq!(
        fixture.data()["elc_accounts"]["host.example"]["api_key"],
        "APIKEY123"
    );
    let original = fs::read(fixture.paths.config()).unwrap();
    let shown = fixture.run(&["show"], 0);
    assert!(shown.stderr.is_empty());
    let rows = std::str::from_utf8(&shown.stdout).unwrap();
    assert!(rows.contains("<redacted>"));
    let row = rows
        .lines()
        .find(|row| row.starts_with("elc_accounts | "))
        .unwrap();
    let nested: Value = serde_json::from_str(row.split_once(" | ").unwrap().1).unwrap();
    assert_eq!(
        nested,
        json!({"host.example":{"user":"u","api_key":"<redacted>"}})
    );
    let password = fixture.run(&["get", "connect_proxy_password"], 0);
    assert_eq!(
        std::str::from_utf8(&password.stdout).unwrap().trim(),
        "<redacted>"
    );
    let nested = fixture.run(&["get", "elc_accounts"], 0);
    let nested: Value = serde_json::from_slice(&nested.stdout).unwrap();
    assert_eq!(
        nested,
        json!({"host.example":{"user":"u","api_key":"<redacted>"}})
    );
    let workers = fixture.run(&["get", "max_workers"], 0);
    assert_eq!(std::str::from_utf8(&workers.stdout).unwrap().trim(), "10");
    for arguments in [
        vec!["get", "no_such_key"],
        vec!["set", "no_such_key", "1"],
        vec!["set", "streaming_port", "70000"],
        vec!["set", "chunk_size_kb", "1024"],
        vec!["unset", "max_workers"],
    ] {
        let output = fixture.run(&arguments, 2);
        assert!(output.stdout.is_empty());
        assert!(
            std::str::from_utf8(&output.stderr)
                .unwrap()
                .contains("[ERROR]")
        );
        assert_eq!(fs::read(fixture.paths.config()).unwrap(), original);
    }
    let migrated = fixture.run(&["migrate"], 0);
    assert!(migrated.stdout.is_empty());
    assert!(
        std::str::from_utf8(&migrated.stderr)
            .unwrap()
            .contains("removed 0")
    );
    assert_eq!(fs::read(fixture.paths.config()).unwrap(), original);
    fixture.only_config_files();
}

#[test]
fn independent_config_commands_preserve_both_updates_to_the_same_store() {
    let fixture = Fixture::new();
    fixture.run(&["set", "max_workers", "4"], 0);
    std::thread::scope(|scope| {
        let first = scope.spawn(|| fixture.run(&["set", "max_workers", "16"], 0));
        let second = scope.spawn(|| fixture.run(&["set", "timeout_seconds", "50"], 0));
        for output in [first.join().unwrap(), second.join().unwrap()] {
            assert!(output.stdout.is_empty());
            assert!(
                std::str::from_utf8(&output.stderr)
                    .unwrap()
                    .contains("Configuration setting saved.")
            );
        }
    });
    let data = fixture.data();
    assert_eq!(data["max_workers"], 16);
    assert_eq!(data["timeout_seconds"], 50);
    let (settings, warnings) = ConfigStore::new(fixture.paths.config()).load().unwrap();
    assert_eq!(settings.max_workers, 16);
    assert_eq!(settings.timeout_seconds, 50);
    assert!(warnings.is_empty());
    fixture.only_config_files();
}

#[test]
fn actual_corrupt_config_commands_refuse_mutation_but_preserve_safe_inspection() {
    let fixture = Fixture::new();
    fixture.run(&["set", "max_workers", "7"], 0);
    let malformed = b"{\"connect_proxy_password\": \"s3cr3t-not-a-real-password\", oops}";
    Store::new(fixture.paths.config())
        .lock()
        .unwrap()
        .write_bytes(malformed)
        .unwrap();
    for words in [
        vec!["set", "max_workers", "4"],
        vec!["unset", "default_account"],
        vec!["migrate"],
        vec!["reset"],
        vec!["recover"],
    ] {
        let output = fixture.run(&words, 1);
        assert!(output.stdout.is_empty());
        let error = std::str::from_utf8(&output.stderr).unwrap();
        assert!(error.contains("[ERROR]"));
        if words == ["migrate"] {
            assert!(error.contains("Saved file is not valid UTF-8 JSON"));
        } else {
            assert!(error.to_lowercase().contains("config"));
        }
        assert!(
            !error.contains("Configuration setting saved.") && !error.contains("reset to defaults")
        );
        assert_eq!(fs::read(fixture.paths.config()).unwrap(), malformed);
        fixture.config_files(Some(malformed));
    }
    for words in [vec!["show"], vec!["get", "max_workers"], vec!["path"]] {
        let output = fixture.run(&words, 0);
        let shown = std::str::from_utf8(&output.stdout).unwrap();
        if words == ["get", "max_workers"] {
            assert_eq!(shown.trim(), "8");
        } else if words == ["path"] {
            assert_eq!(shown.trim(), fixture.paths.config().to_str().unwrap());
        } else {
            assert!(shown.starts_with("Key | Value"));
        }
        assert_eq!(fs::read(fixture.paths.config()).unwrap(), malformed);
        fixture.config_files(Some(malformed));
    }
}

#[test]
fn actual_config_null_and_unset_persist_json_null_and_reload_without_staging_residue() {
    let fixture = Fixture::new();
    for clear in ["null", "unset"] {
        fixture.run(&["set", "smart_proxy_url", "http://p:8080"], 0);
        assert_eq!(fixture.data()["smart_proxy_url"], "http://p:8080");
        if clear == "unset" {
            fixture.run(&["unset", "smart_proxy_url"], 0);
        } else {
            fixture.run(&["set", "smart_proxy_url", clear], 0);
        }
        let data = fixture.data();
        assert!(data.as_object().unwrap().contains_key("smart_proxy_url"));
        assert!(data["smart_proxy_url"].is_null());
        let (settings, warnings) = ConfigStore::new(fixture.paths.config()).load().unwrap();
        assert!(settings.smart_proxy_url.is_none() && warnings.is_empty());
        let output = fixture.run(&["get", "smart_proxy_url"], 0);
        assert_eq!(std::str::from_utf8(&output.stdout).unwrap().trim(), "None");
        assert!(output.stderr.is_empty());
        fixture.only_config_files();
    }
    fixture.run(&["set", "connect_proxy_password", "hunter2"], 0);
    fixture.run(&["unset", "connect_proxy_password"], 0);
    assert!(fixture.data()["connect_proxy_password"].is_null());
    let output = fixture.run(&["get", "connect_proxy_password"], 0);
    assert_eq!(std::str::from_utf8(&output.stdout).unwrap().trim(), "None");
    assert!(output.stderr.is_empty());
    for workers in 1..=5 {
        fixture.run(&["set", "max_workers", &workers.to_string()], 0);
        assert_eq!(fixture.data()["max_workers"], workers);
        fixture.only_config_files();
    }
}
