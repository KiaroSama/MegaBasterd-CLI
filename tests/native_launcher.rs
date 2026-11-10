#![cfg(windows)]
#![allow(clippy::unwrap_used)]
use std::{fs, process::Command};
#[test]
fn candidate_launcher_forwards_arguments_from_an_unrelated_cwd_and_preserves_native_exit_codes() {
    let scratch = private_tempfile::tempdir().unwrap();
    let binary = scratch.path().join("mb with spaces.exe");
    fs::copy(env!("CARGO_BIN_EXE_mb"), &binary).unwrap();
    for (arguments, expected) in [
        (vec!["--version"], 0),
        (vec!["--no-log-file", "config", "get", "max_workers"], 0),
        (vec!["--no-log-file", "config", "get", "not-a-setting"], 2),
        (vec!["--not-an-option"], 2),
    ] {
        let result = Command::new(&binary)
            .current_dir(scratch.path())
            .env("MEGABASTERD_USER_DIR", scratch.path().join("User"))
            .args(arguments)
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(expected));
        assert!(!result.stdout.is_empty() || !result.stderr.is_empty());
    }
    assert!(!scratch.path().join("Run.ps1").exists());
}

#[path = "common/private_tempfile.rs"]
mod private_tempfile;
