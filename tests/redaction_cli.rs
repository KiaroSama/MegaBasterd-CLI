//! Native error output never exposes a rejected link's supplied decryption key.
#![allow(clippy::unwrap_used)]

use std::{fs, path::Path, process::Command, time::Duration};

use megabasterd_cli::{platform::process, transfers::control::Control};

#[test]
fn actual_binary_sanitizes_invalid_link_errors_on_human_and_machine_surfaces() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/redaction-cli");
    fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    let temporary = scratch.path().join("private temporary");
    let cwd = scratch.path().join("unrelated working directory");
    fs::create_dir(&temporary).unwrap();
    fs::create_dir(&cwd).unwrap();
    for json_mode in [false, true] {
        let root = scratch.path().join(if json_mode {
            "machine runtime"
        } else {
            "human runtime"
        });
        fs::create_dir(&root).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_mb"));
        command.current_dir(&cwd).env_clear();
        for name in [
            "PATH",
            "SystemRoot",
            "WINDIR",
            "PATHEXT",
            "LD_LIBRARY_PATH",
            "DYLD_LIBRARY_PATH",
        ] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        for name in [
            "HOME",
            "USERPROFILE",
            "APPDATA",
            "LOCALAPPDATA",
            "TMP",
            "TEMP",
            "TMPDIR",
        ] {
            command.env(name, &temporary);
        }
        command
            .env("MEGABASTERD_PROJECT_ROOT", &root)
            .env("MEGABASTERD_USER_DIR", root.join("private user"))
            .env("MEGABASTERD_LOG_DIR", root.join("private logs"))
            .env("HOOKMAKER_MAX_TEST_WORKERS", "1")
            .args([
                "--no-log-file",
                "download",
                "https://mega.nz/file/ABCD1234#SUPERSECRETKEYVALUE",
                "-w",
                "1",
                "-P",
                "1",
            ]);
        if json_mode {
            command.arg("--json");
        }
        let result = process::run_command(
            command,
            Duration::from_secs(5),
            16 * 1024,
            16 * 1024,
            &Control::new(),
            None,
        )
        .unwrap();
        assert_eq!(result.status.code(), Some(1));
        let stdout = String::from_utf8(result.stdout).unwrap();
        let stderr = String::from_utf8(result.stderr).unwrap();
        assert!(!stdout.contains("SUPERSECRETKEYVALUE") && !stderr.contains("SUPERSECRETKEYVALUE"));
        assert!(!stderr.contains("panicked") && !stderr.contains("Traceback"));
        assert!(!root.join("Output").exists());
        assert!(!root.join("private logs").exists());
        if json_mode {
            assert_eq!(stdout.lines().count(), 1);
            let record: serde_json::Value = serde_json::from_str(&stdout).unwrap();
            assert_eq!(record["status"], "failed");
            assert_eq!(record["error_code"], "invalid_input");
            assert_eq!(record["source"], "https://mega.nz/file/ABCD1234#<key>");
        } else {
            assert!(stdout.is_empty());
        }
    }
}
