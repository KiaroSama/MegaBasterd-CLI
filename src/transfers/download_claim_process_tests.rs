//! Independent downloads bind saved state to the destination actually claimed, not the requested name.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::{
    platform::{process, secure_files::file_identity},
    storage::transfer_state::TransferState,
    transfers::claims::Claim,
};
use std::process::Command;

const CHILD: &str = "MB_DOWNLOAD_CLAIM_CHILD";
const TEST: &str = "transfers::download_peer_tests::claim_process_tests::independent_download_processes_persist_distinct_destination_bound_states";

fn failed_download(address: std::net::SocketAddr, destination: &Path, states: &Path) {
    let fixture = Fixture::new(17);
    let mut progress = Progress::new(false);
    let item = progress.add("movie.mkv", fixture.size).unwrap();
    let mut options = options(false);
    options.resume = false;
    let error = download(
        Api::test_peer(address).unwrap(),
        fixture.info(address),
        destination,
        states,
        &options,
        &RateLimiter::new(0.0).unwrap(),
        &progress,
        item,
        &Control::new(),
    )
    .unwrap_err();
    assert!(matches!(error, Error::Protocol(message)
        if message == "CDN did not honor the exact requested Range"));
    assert!(!progress.close(false).unwrap());
}

fn saved_states(directory: &Path) -> Vec<(PathBuf, Vec<u8>, TransferState)> {
    let mut paths: Vec<_> = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect();
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let bytes = std::fs::read(&path).unwrap();
            let state = States::new(&path).load().unwrap().unwrap();
            (path, bytes, state)
        })
        .collect()
}

fn assert_staging(root: &Path, state: &TransferState, destination: &Path) -> PathBuf {
    assert_eq!(state.kind, "download");
    assert_eq!(state.destination, destination.to_string_lossy());
    assert_eq!(state.size, 17);
    assert!(state.completed.is_empty());
    assert!(!destination.exists());
    let staging = root.join(state.staging_name.as_ref().unwrap());
    let file = std::fs::File::open(&staging).unwrap();
    assert_eq!(file.metadata().unwrap().len(), 17);
    assert_eq!(
        state.staging_identity.as_ref().unwrap(),
        &file_identity(&file).unwrap()
    );
    assert_eq!(std::fs::read(&staging).unwrap(), [0; 17]);
    staging
}

fn child(root: &Path, address: std::net::SocketAddr) {
    let temporary = root.join("child temporary");
    std::fs::create_dir(&temporary).unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.current_dir(root).env_clear();
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
        .env(CHILD, root)
        .env("MB_DOWNLOAD_CLAIM_PEER", address.to_string())
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
    assert_eq!(result.status.code(), Some(0), "{stdout}\n{stderr}");
    assert!(
        stdout.contains("1 passed") && stdout.contains("0 failed") && stdout.contains("0 ignored")
    );
    assert!(!stderr.contains("panicked"), "{stderr}");
}

#[test]
fn independent_download_processes_persist_distinct_destination_bound_states() {
    if let Some(root) = std::env::var_os(CHILD) {
        let root = PathBuf::from(root);
        let base = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(".ci-work/download-peers")
            .canonicalize()
            .unwrap();
        assert!(root.is_absolute() && root.canonicalize().unwrap().starts_with(base));
        let address: std::net::SocketAddr = std::env::var("MB_DOWNLOAD_CLAIM_PEER")
            .unwrap()
            .parse()
            .unwrap();
        assert!(address.ip().is_loopback() && address.port() != 0);
        let states = root.join("private state");
        failed_download(address, &root.join("movie.mkv"), &states);
        let saved = saved_states(&states);
        assert_eq!(saved.len(), 1);
        assert_staging(&root, &saved[0].2, &root.join("movie (1).mkv"));
        return;
    }
    let scratch = scratch();
    let root = scratch.path().canonicalize().unwrap();
    let destination = root.join("movie.mkv");
    let alternate = root.join("movie (1).mkv");
    let states = root.join("private state");
    let claim = Claim::acquire(&destination, false, |_| Ok(false)).unwrap();
    assert_eq!(claim.path, destination);
    let ((), calls) = test_peer::with_peer(
        |request| {
            assert_eq!(request.method, "GET");
            assert_eq!(request.path, "/cdn");
            assert_eq!(request.headers["range"], "bytes=0-16");
            assert!(request.body.is_empty());
            Some(Response {
                status: 400,
                headers: vec![],
                body: vec![],
            })
        },
        |address| {
            child(&root, address);
            let before = saved_states(&states);
            assert_eq!(before.len(), 1);
            let child_stage = assert_staging(&root, &before[0].2, &alternate);
            drop(claim);
            failed_download(address, &destination, &states);
            let after = saved_states(&states);
            assert_eq!(after.len(), 2);
            let retained = after
                .iter()
                .find(|(path, _, _)| path == &before[0].0)
                .unwrap();
            assert_eq!(retained.1, before[0].1);
            assert_eq!(assert_staging(&root, &retained.2, &alternate), child_stage);
            let parent = after
                .iter()
                .find(|(path, _, _)| path != &before[0].0)
                .unwrap();
            let parent_stage = assert_staging(&root, &parent.2, &destination);
            assert_ne!(parent_stage, child_stage);
            assert_ne!(parent.2.staging_identity, retained.2.staging_identity);
            assert_eq!(parent.2.source_hash, retained.2.source_hash);
            assert_eq!(parent.2.key_hash, retained.2.key_hash);
        },
    );
    assert_eq!(calls.len(), 2);
    assert!(!destination.exists() && !alternate.exists());
}
