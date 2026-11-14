//! Independent upload processes contend on the actual whole-transfer lease and recover after exit.
#![allow(clippy::unwrap_used)]

use super::{super::*, unqueued};
use crate::platform::{
    process,
    secure_files::{PrivateDirectory, file_identity},
};
use std::{io::Write, process::Command, time::Duration};

const CHILD: &str = "MB_UPLOAD_LEASE_CHILD";
const TEST: &str = "transfers::upload_peer_tests::lease_tests::process_tests::actual_upload_lease_excludes_another_process_and_recovers_after_abrupt_owner_exit";

fn child(root: &Path, source: &Path, states: &Path, address: std::net::SocketAddr, mode: &str) {
    let temporary = root.join("child temporary");
    std::fs::create_dir_all(&temporary).unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.current_dir(root).env_clear();
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
    command
        .env(CHILD, mode)
        .env("MB_UPLOAD_LEASE_SOURCE", source)
        .env("MB_UPLOAD_LEASE_STATES", states)
        .env("MB_UPLOAD_LEASE_PEER", address.to_string())
        .env("HOOKMAKER_MAX_TEST_WORKERS", "1")
        .args(["--exact", TEST, "--test-threads=1"]);
    let result = process::run_command(
        command,
        Duration::from_secs(10),
        16 * 1024,
        16 * 1024,
        &Control::new(),
        None,
    )
    .unwrap();
    let stdout = String::from_utf8(result.stdout).unwrap();
    let stderr = String::from_utf8(result.stderr).unwrap();
    assert!(
        !stderr.contains("panicked"),
        "upload lease child panicked: {stderr}"
    );
    assert_eq!(
        result.status.code(),
        Some(if mode == "exit" { 1 } else { 0 }),
        "{stderr}"
    );
    if mode == "exit" {
        assert!(stdout.contains("UPLOAD_RECEIPT_HELD_BEFORE_EXIT"));
    } else {
        assert!(
            stdout.contains("1 passed")
                && stdout.contains("0 failed")
                && stdout.contains("0 ignored")
        );
    }
}

#[test]
fn actual_upload_lease_excludes_another_process_and_recovers_after_abrupt_owner_exit() {
    if let Some(mode) = std::env::var_os(CHILD) {
        let source = PathBuf::from(std::env::var_os("MB_UPLOAD_LEASE_SOURCE").unwrap());
        let states = PathBuf::from(std::env::var_os("MB_UPLOAD_LEASE_STATES").unwrap());
        let base = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(".ci-work/upload-peers")
            .canonicalize()
            .unwrap();
        assert!(source.is_absolute() && states.is_absolute());
        assert!(source.canonicalize().unwrap().starts_with(&base));
        assert!(states.canonicalize().unwrap().starts_with(base));
        let address: std::net::SocketAddr = std::env::var("MB_UPLOAD_LEASE_PEER")
            .unwrap()
            .parse()
            .unwrap();
        assert!(address.ip().is_loopback() && address.port() != 0);
        let vault = Vault::new("synthetic upload passphrase");
        let result = unqueued(&mut cloud(address), &source, &states, &vault);
        match mode.to_str().unwrap() {
            "held" => assert!(matches!(result, Err(Error::Busy(_)))),
            "released" => {
                let uploaded = result.unwrap();
                assert_eq!(uploaded.handle, "AQIDBAUG");
                assert_eq!(uploaded.size, 17);
                drop(uploaded);
            }
            "exit" => {
                let uploaded = result.unwrap();
                assert_eq!(uploaded.handle, "AQIDBAUG");
                assert_eq!(uploaded.size, 17);
                // Direct stdout bypasses libtest capture; a panic's exit1 is not ownership proof.
                std::io::stdout()
                    .write_all(b"UPLOAD_RECEIPT_HELD_BEFORE_EXIT\n")
                    .unwrap();
                std::io::stdout().flush().unwrap();
                std::process::exit(1);
            }
            _ => panic!("unknown upload lease child mode"),
        }
        return;
    }
    let scratch = scratch();
    let source = source(scratch.path(), 17);
    let original = std::fs::read(&source).unwrap();
    let states = scratch.path().join("private state");
    let vault = Vault::new("synthetic upload passphrase");
    let ((mut cloud, address, uploaded), calls) = test_peer::with_peer(
        |request| {
            if request.path.starts_with("/native-peer-upload/") {
                return Some(Response {
                    status: 200,
                    headers: vec![],
                    body: TOKEN.as_bytes().to_vec(),
                });
            }
            Some(match command(request)["a"].as_str().unwrap() {
                "u" => api(json!({"p":SLOT})),
                "p" => api(json!({"f":[{"h":"AQIDBAUG"}]})),
                _ => panic!("upload lease child contacted an unexpected action"),
            })
        },
        |address| {
            let mut cloud = cloud(address);
            let uploaded = unqueued(&mut cloud, &source, &states, &vault).unwrap();
            (cloud, address, uploaded)
        },
    );
    assert_eq!(calls.len(), 3);
    // Receipt recovery is offline: child startup/KDF must not consume the TLS peer's budget.
    let paths = super::data_paths(&states);
    assert_eq!(paths.len(), 1);
    let saved = std::fs::read(&paths[0]).unwrap();
    let lease_path = super::lease(&states, &paths[0]);
    let directory = PrivateDirectory::open(&states).unwrap();
    let sidecar_name = format!("{}.lock", lease_path.file_name().unwrap().to_str().unwrap());
    let original_sidecar = directory
        .open_private(std::ffi::OsStr::new(&sidecar_name), false)
        .unwrap();
    let identity = file_identity(&original_sidecar).unwrap();
    child(scratch.path(), &source, &states, address, "held");
    assert_eq!(std::fs::read(&paths[0]).unwrap(), saved);
    drop(uploaded);
    child(scratch.path(), &source, &states, address, "released");
    assert_eq!(std::fs::read(&paths[0]).unwrap(), saved);
    child(scratch.path(), &source, &states, address, "exit");
    assert_eq!(std::fs::read(&paths[0]).unwrap(), saved);
    let recovered = unqueued(&mut cloud, &source, &states, &vault).unwrap();
    assert_eq!(recovered.handle, "AQIDBAUG");
    let current_sidecar = directory
        .open_private(std::ffi::OsStr::new(&sidecar_name), false)
        .unwrap();
    assert_eq!(file_identity(&current_sidecar).unwrap(), identity);
    recovered.acknowledge().unwrap();
    drop(recovered);
    assert!(super::data_paths(&states).is_empty());
    assert!(
        crate::storage::files::Store::new(lease_path)
            .with_timeout(Duration::ZERO)
            .lock()
            .is_ok()
    );
    assert_eq!(std::fs::read(&source).unwrap(), original);
}
