//! Independent native processes serialize exact recovery copies and whole transfer snapshots.
#![allow(clippy::unwrap_used)]

use megabasterd_cli::{
    error::Error,
    storage::{
        config_store::ConfigStore,
        files::Store,
        transfer_state::{States, TransferState},
    },
};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const CHILD_PATH: &str = "MB_RECOVERY_PROCESS_PATH";
const MODE: &str = "MB_RECOVERY_PROCESS_MODE";
const INDEX: &str = "MB_RECOVERY_PROCESS_INDEX";
const CORRUPT: &[u8] = b"{\"episode\": \"A\",,,";

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn base() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/storage-recovery-processes")
}

fn wait_for(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !predicate() {
        assert!(
            Instant::now() < deadline,
            "storage child readiness/exit deadline expired"
        );
        // Native cross-process file readiness has no portable event; bounded polling only.
        std::thread::park_timeout(Duration::from_millis(5));
    }
}

fn child(path: &Path, index: usize, mode: &str, test: &str) -> OwnedChild {
    let parent = path.parent().unwrap();
    let temporary = parent.join(format!("child-{index}"));
    fs::create_dir(&temporary).unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.current_dir(parent).env_clear();
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
    let log = fs::File::create(parent.join(format!("child-{index}.txt"))).unwrap();
    command
        .env(CHILD_PATH, path)
        .env(MODE, mode)
        .env(INDEX, index.to_string())
        .env("HOOKMAKER_MAX_TEST_WORKERS", "1")
        .args(["--exact", test, "--test-threads=1"])
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log));
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    OwnedChild(command.spawn().unwrap())
}

fn child_mode() -> bool {
    let Some(path) = std::env::var_os(CHILD_PATH) else {
        return false;
    };
    let path = PathBuf::from(path);
    // Validate containment without changing the parent's exact saved identity
    // into Windows' verbatim \\?\ spelling in the child.
    assert!(
        path.canonicalize()
            .unwrap()
            .starts_with(base().canonicalize().unwrap())
    );
    let parent = path.parent().unwrap();
    let index = std::env::var(INDEX).unwrap();
    fs::write(parent.join(format!("ready-{index}")), b"ready").unwrap();
    wait_for(|| parent.join("start").exists());
    match std::env::var(MODE).unwrap().as_str() {
        "preserve" => {
            for _ in 0..3 {
                assert!(matches!(
                    ConfigStore::new(&path).load(),
                    Err(Error::Corrupt(_))
                ));
                assert_eq!(fs::read(&path).unwrap(), CORRUPT);
            }
        }
        "state" => {
            let states = States::new(&path);
            let mut state = TransferState::new(
                "download",
                "fixture",
                &parent.join("output.bin"),
                1_000_000,
                &[1; 32],
            )
            .unwrap();
            for round in 0..4 {
                state
                    .completed
                    .insert(usize::from(index == "1"), [0xaa; 16]);
                state.revision = round;
                states.save(&state).unwrap();
                assert!(!states.load().unwrap().unwrap().completed.is_empty());
            }
        }
        _ => panic!("unknown native storage child mode"),
    }
    fs::write(parent.join(format!("done-{index}")), b"done").unwrap();
    true
}

fn run_children(path: &Path, mode: &str, test: &str, count: usize) {
    assert!((2..=4).contains(&count));
    let mut children = Vec::with_capacity(count);
    for index in 0..count {
        children.push(child(path, index, mode, test));
    }
    let parent = path.parent().unwrap();
    wait_for(|| (0..count).all(|index| parent.join(format!("ready-{index}")).exists()));
    fs::write(parent.join("start"), b"start").unwrap();
    for (index, child) in children.iter_mut().enumerate() {
        let mut result = None;
        wait_for(|| {
            result = child.0.try_wait().unwrap();
            result.is_some()
        });
        assert!(
            result.unwrap().success(),
            "native storage child failed: {}",
            fs::read_to_string(parent.join(format!("child-{index}.txt"))).unwrap()
        );
    }
    for index in 0..count {
        assert_eq!(
            fs::read(parent.join(format!("done-{index}"))).unwrap(),
            b"done"
        );
    }
}

#[test]
fn independent_config_readers_preserve_one_exact_backup_and_leave_the_corrupt_original_unchanged() {
    if child_mode() {
        return;
    }
    fs::create_dir_all(base()).unwrap();
    let scratch = private_tempfile::tempdir_in(base()).unwrap();
    let path = scratch.path().join("private/config.json");
    Store::new(&path)
        .lock()
        .unwrap()
        .write_bytes(CORRUPT)
        .unwrap();
    run_children(
        &path,
        "preserve",
        "independent_config_readers_preserve_one_exact_backup_and_leave_the_corrupt_original_unchanged",
        4,
    );
    let copies: Vec<_> = fs::read_dir(path.parent().unwrap())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("config.json.corrupt-")
        })
        .collect();
    assert_eq!(copies.len(), 1);
    assert_eq!(fs::read(&copies[0]).unwrap(), CORRUPT);
    assert_eq!(fs::read(&path).unwrap(), CORRUPT);
}

#[test]
fn independent_state_writers_leave_one_parseable_valid_snapshot_without_staging_debris() {
    if child_mode() {
        return;
    }
    fs::create_dir_all(base()).unwrap();
    let scratch = private_tempfile::tempdir_in(base()).unwrap();
    let path = scratch.path().join("private/state.json");
    let state = TransferState::new(
        "download",
        "fixture",
        &path.parent().unwrap().join("output.bin"),
        1_000_000,
        &[1; 32],
    )
    .unwrap();
    States::new(&path).save(&state).unwrap();
    run_children(
        &path,
        "state",
        "independent_state_writers_leave_one_parseable_valid_snapshot_without_staging_debris",
        2,
    );
    let loaded = States::new(&path).load().unwrap().unwrap();
    loaded.validate().unwrap();
    assert!(!loaded.completed.is_empty());
    assert_eq!(loaded.revision, 3);
    assert_eq!(
        loaded.completed.len(),
        1,
        "snapshot replacement became an unsound union"
    );
    assert!(!fs::read_dir(path.parent().unwrap()).unwrap().any(|entry| {
        let name = entry.unwrap().file_name().to_string_lossy().into_owned();
        name.ends_with(".tmp") || name.contains(".corrupt-")
    }));
}

#[path = "common/private_tempfile.rs"]
mod private_tempfile;
