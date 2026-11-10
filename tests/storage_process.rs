//! Persistent store sidecars exclude independent processes across atomic data replacement.
#![allow(clippy::unwrap_used)]

use std::{fs, path::Path, process::Command, time::Duration};

use megabasterd_cli::{
    error::Error,
    platform::{
        process,
        secure_files::{PrivateDirectory, file_identity},
    },
    storage::files::Store,
    transfers::{claims::Claim, control::Control},
};
use serde_json::json;

const CHILD_MODE: &str = "MB_STORAGE_PROCESS_MODE";
const CHILD_PATH: &str = "MB_STORAGE_PROCESS_PATH";

fn child(cwd: &Path, path: &Path, test: &str, mode: &str, expected_exit: i32) {
    let temporary = cwd.join("child temporary");
    fs::create_dir_all(&temporary).unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.current_dir(cwd).env_clear();
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
        .env(CHILD_MODE, mode)
        .env(CHILD_PATH, path)
        .env("HOOKMAKER_MAX_TEST_WORKERS", "1")
        .args(["--exact", test, "--test-threads=1"]);
    let result = process::run_command(
        command,
        Duration::from_secs(5),
        16 * 1024,
        16 * 1024,
        &Control::new(),
        None,
    )
    .unwrap();
    assert_eq!(
        result.status.code(),
        Some(expected_exit),
        "unexpected storage child exit: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let stdout = String::from_utf8(result.stdout).unwrap();
    if expected_exit == 0 {
        assert!(
            stdout.contains("1 passed")
                && stdout.contains("0 failed")
                && stdout.contains("0 ignored")
        );
    } else {
        assert!(stdout.contains("CLAIM_HELD_BEFORE_EXIT"));
        assert!(
            !String::from_utf8(result.stderr)
                .unwrap()
                .contains("panicked")
        );
    }
}

#[test]
fn persistent_store_lock_excludes_another_process_and_reloads_after_owner_release() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/storage-process");
    if let Some(mode) = std::env::var_os(CHILD_MODE) {
        let path = std::path::PathBuf::from(std::env::var_os(CHILD_PATH).unwrap());
        let canonical = path.canonicalize().unwrap();
        assert!(canonical.starts_with(base.canonicalize().unwrap()));
        let store = Store::new(path).with_timeout(Duration::ZERO);
        match mode.to_str().unwrap() {
            "held" => assert!(matches!(store.lock(), Err(Error::Busy(_)))),
            "released" => {
                let locked = store.lock().unwrap();
                let mut data = locked.load::<serde_json::Value>().unwrap().unwrap();
                assert_eq!(data["counter"], 7);
                data["counter"] = 8.into();
                locked.save(&data).unwrap();
            }
            _ => panic!("unknown storage process mode"),
        }
        return;
    }
    fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(&base).unwrap();
    let path = scratch.path().join("private/store.json");
    let store = Store::new(&path);
    store.lock().unwrap().save(&json!({"counter":7})).unwrap();
    let directory = PrivateDirectory::open(path.parent().unwrap()).unwrap();
    let original_sidecar = directory
        .open_private(std::ffi::OsStr::new("store.json.lock"), false)
        .unwrap();
    let sidecar_identity = file_identity(&original_sidecar).unwrap();
    let run_child = |mode: &str| {
        child(
            scratch.path(),
            &path,
            "persistent_store_lock_excludes_another_process_and_reloads_after_owner_release",
            mode,
            0,
        );
    };
    let locked = store.lock().unwrap();
    let original = fs::read(&path).unwrap();
    run_child("held");
    assert_eq!(fs::read(&path).unwrap(), original);
    assert_eq!(
        locked.load::<serde_json::Value>().unwrap().unwrap()["counter"],
        7
    );
    drop(locked);
    run_child("released");
    assert_eq!(
        store
            .lock()
            .unwrap()
            .load::<serde_json::Value>()
            .unwrap()
            .unwrap()["counter"],
        8
    );
    let current_sidecar = directory
        .open_private(std::ffi::OsStr::new("store.json.lock"), false)
        .unwrap();
    assert_eq!(file_identity(&current_sidecar).unwrap(), sidecar_identity);
    assert!(!fs::read_dir(path.parent().unwrap()).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")
    }));
    drop(current_sidecar);
    drop(original_sidecar);
    drop(directory);
}

#[test]
fn destination_claim_excludes_an_independent_process_and_reuses_its_original_sidecar() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/storage-process");
    if let Some(mode) = std::env::var_os(CHILD_MODE) {
        let path = std::path::PathBuf::from(std::env::var_os(CHILD_PATH).unwrap());
        assert!(path.is_absolute());
        assert!(
            path.parent()
                .unwrap()
                .canonicalize()
                .unwrap()
                .starts_with(base.canonicalize().unwrap())
        );
        match mode.to_str().unwrap() {
            "claim-held" => {
                let alternate = Claim::acquire(&path, false, |_| Ok(false)).unwrap();
                assert_eq!(alternate.path, path.with_file_name("movie (1).mkv"));
                assert!(matches!(
                    Claim::acquire(&path, true, |_| Ok(false)),
                    Err(Error::Busy(_))
                ));
                assert!(!path.exists() && !alternate.path.exists());
            }
            "claim-released" => {
                let claim = Claim::acquire(&path, false, |_| Ok(false)).unwrap();
                assert_eq!(claim.path, path);
            }
            "claim-exit" => {
                let claim = Claim::acquire(&path, false, |_| Ok(false)).unwrap();
                assert_eq!(claim.path, path);
                // Bypass libtest capture so the parent can distinguish exit from an assertion failure.
                std::io::Write::write_all(&mut std::io::stdout(), b"CLAIM_HELD_BEFORE_EXIT\n")
                    .unwrap();
                std::io::Write::flush(&mut std::io::stdout()).unwrap();
                // No Claim destructor runs: the OS must release this child's actual lock.
                std::process::exit(1);
            }
            _ => panic!("unknown destination-claim process mode"),
        }
        return;
    }
    fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    let path = scratch.path().join("output with spaces/movie.mkv");
    let claim = Claim::acquire(&path, false, |_| Ok(false)).unwrap();
    let sidecar = claim
        .directory
        .open_read(std::ffi::OsStr::new("movie.mkv.mbclaim"))
        .unwrap();
    let identity = file_identity(&sidecar).unwrap();
    assert_eq!(sidecar.metadata().unwrap().len(), 0);
    let test = "destination_claim_excludes_an_independent_process_and_reuses_its_original_sidecar";
    child(scratch.path(), &path, test, "claim-held", 0);
    assert_eq!(claim.path, path);
    drop(claim);
    child(scratch.path(), &path, test, "claim-released", 0);
    child(scratch.path(), &path, test, "claim-exit", 1);
    let claim = Claim::acquire(&path, false, |_| Ok(false)).unwrap();
    assert_eq!(claim.path, path);
    let current = claim
        .directory
        .open_read(std::ffi::OsStr::new("movie.mkv.mbclaim"))
        .unwrap();
    assert_eq!(file_identity(&current).unwrap(), identity);
    assert_eq!(claim.directory.entries(4).unwrap().len(), 2);
    assert!(!path.exists());
}
