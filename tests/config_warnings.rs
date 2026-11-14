//! Command contexts share ignored-setting warning history, without leaking unknown keys.
#![allow(clippy::unwrap_used)]

use std::{fs, path::Path, process::Command, time::Duration};

use megabasterd_cli::{
    cli::context::Context,
    error::Error,
    platform::process,
    storage::{config_store::ConfigStore, files::Store, paths::Paths},
    transfers::control::Control,
};
use serde_json::{Value, json};

const CHILD: &str = "MB_CONFIG_WARNING_CHILD";
const RETIRED: &str = "Config setting chunk_size_kb is retired; it was ignored";
const UNKNOWN: &str = "Config contains an unknown setting; it was ignored";
const INVALID: &str = "Config setting max_workers is invalid; using its default";

#[test]
fn repeated_command_contexts_warn_once_per_ignored_key_but_repeat_invalid_value_diagnostics() {
    if std::env::var_os(CHILD).as_deref() == Some(std::ffi::OsStr::new("1")) {
        let paths = Paths::discover().unwrap();
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/config-warnings");
        assert!(
            paths
                .root
                .canonicalize()
                .unwrap()
                .starts_with(base.canonicalize().unwrap())
        );
        let mut supplied = json!({"chunk_size_kb":1024,"unknown-private-key": "unknown-private-value","max_workers":4});
        for iteration in 0..6 {
            if iteration == 3 {
                supplied["second-private-key"] = json!("second-private-value");
            }
            if iteration == 4 {
                supplied["max_workers"] = json!(0);
            }
            Store::new(paths.config())
                .lock()
                .unwrap()
                .save(&supplied)
                .unwrap();
            let original = fs::read(paths.config()).unwrap();
            let context = Context::start(false, false, Some(true)).unwrap();
            context.require_config().unwrap();
            assert_eq!(
                context.config.max_workers,
                if iteration < 4 { 4 } else { 8 }
            );
            context.finish(0);
            drop(context);
            assert_eq!(fs::read(paths.config()).unwrap(), original);
        }
        // Pure validation must remain deterministic, independent of command warning history.
        for _ in 0..2 {
            let (_, warnings) = ConfigStore::new(paths.config()).load().unwrap();
            assert_eq!(warnings.len(), 4);
        }
        let logs: Vec<_> = fs::read_dir(&paths.logs)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(logs.len(), 6);
        let mut warnings_per_run = Vec::new();
        let mut combined = String::new();
        for log in logs {
            let text = fs::read_to_string(log).unwrap();
            assert!(text.contains(" UTC] [INFO] [RUNTIME] run=") && text.contains(" Started "));
            assert!(text.contains(" UTC] [INFO] [RUNTIME] run=") && text.contains(" Finished "));
            warnings_per_run.push(text.matches("[WARNING]").count());
            combined.push_str(&text);
        }
        warnings_per_run.sort_unstable();
        assert_eq!(warnings_per_run, [0, 0, 1, 1, 1, 2]);
        assert_eq!(combined.matches(RETIRED).count(), 1);
        assert_eq!(combined.matches(UNKNOWN).count(), 2);
        assert_eq!(combined.matches(INVALID).count(), 2);
        for secret in [
            "unknown-private-key",
            "unknown-private-value",
            "second-private-key",
            "second-private-value",
        ] {
            assert!(!combined.contains(secret));
        }
        let overflow: serde_json::Map<String, Value> = (0..4097)
            .map(|index| (format!("unrecognized-{index}"), json!(true)))
            .collect();
        Store::new(paths.config())
            .lock()
            .unwrap()
            .save(&overflow)
            .unwrap();
        let original = fs::read(paths.config()).unwrap();
        let context = Context::start(false, false, Some(false)).unwrap();
        assert!(
            matches!(context.require_config(), Err(Error::Corrupt(message)) if message.contains("warning limit") && message.contains("restart"))
        );
        drop(context);
        assert_eq!(fs::read(paths.config()).unwrap(), original);
        assert_eq!(fs::read_dir(&paths.logs).unwrap().count(), 6);
        return;
    }

    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/config-warnings");
    fs::create_dir_all(&base).unwrap();
    let scratch = private_tempfile::tempdir_in(base).unwrap();
    let root = scratch.path().join("runtime with spaces");
    let temporary = scratch.path().join("private temporary");
    let cwd = scratch.path().join("unrelated working directory");
    fs::create_dir(&root).unwrap();
    fs::create_dir(&temporary).unwrap();
    fs::create_dir(&cwd).unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.current_dir(&cwd).env_clear();
    for key in [
        "LLVM_PROFILE_FILE",
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
    command.env(CHILD, "1")
        .env("MEGABASTERD_PROJECT_ROOT", &root)
        .env("MEGABASTERD_USER_DIR", root.join("private user"))
        .env("MEGABASTERD_LOG_DIR", root.join("private logs"))
        .env("HOOKMAKER_MAX_TEST_WORKERS", "1")
        .args(["--exact", "repeated_command_contexts_warn_once_per_ignored_key_but_repeat_invalid_value_diagnostics", "--test-threads=1"]);
    let result = process::run_command(
        command,
        Duration::from_secs(10),
        16 * 1024,
        16 * 1024,
        &Control::new(),
        None,
    )
    .unwrap();
    assert_eq!(
        result.status.code(),
        Some(0),
        "{} {}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    let stdout = String::from_utf8(result.stdout).unwrap();
    assert!(
        stdout.contains("1 passed") && stdout.contains("0 failed") && stdout.contains("0 ignored")
    );
    let stderr = String::from_utf8(result.stderr).unwrap();
    assert_eq!(stderr.matches(RETIRED).count(), 1);
    assert_eq!(stderr.matches(UNKNOWN).count(), 2);
    assert_eq!(stderr.matches(INVALID).count(), 2);
    for secret in [
        "unknown-private-key",
        "unknown-private-value",
        "second-private-key",
        "second-private-value",
    ] {
        assert!(!stdout.contains(secret) && !stderr.contains(secret));
    }
}

#[path = "common/private_tempfile.rs"]
mod private_tempfile;
