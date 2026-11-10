//! Four independent claim owners write distinct PID files while every reservation remains held.
#![allow(clippy::unwrap_used)]

use megabasterd_cli::transfers::claims::Claim;
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const MODE: &str = "MB_DESTINATION_PROCESS_MODE";
const ROOT: &str = "MB_DESTINATION_PROCESS_ROOT";
const INDEX: &str = "MB_DESTINATION_PROCESS_INDEX";
const CASE: &str =
    "four_independent_processes_hold_distinct_destinations_and_preserve_each_owners_pid_bytes";

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn base() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/destination-processes")
}

fn wait_for(deadline: Instant, mut ready: impl FnMut() -> bool) {
    while !ready() {
        assert!(
            Instant::now() < deadline,
            "destination process readiness/exit deadline expired"
        );
        // Cross-process file readiness has no portable event; polling is bounded by the deadline.
        std::thread::park_timeout(Duration::from_millis(5));
    }
}

fn child_mode() -> bool {
    if std::env::var_os(MODE).is_none() {
        return false;
    }
    let root = PathBuf::from(std::env::var_os(ROOT).unwrap())
        .canonicalize()
        .unwrap();
    assert!(root.starts_with(base().canonicalize().unwrap()));
    let index: usize = std::env::var(INDEX).unwrap().parse().unwrap();
    assert!(index < 4);
    fs::write(root.join(format!("ready-{index}")), b"ready").unwrap();
    wait_for(Instant::now() + Duration::from_secs(5), || {
        root.join("start").is_file()
    });
    let target = root.join("output with spaces/shared.bin");
    let claim = Claim::acquire(&target, false, |_| Ok(false)).unwrap();
    let pid = std::process::id();
    let report = root.join(format!("claimed-{index}.json"));
    let temporary = root.join(format!("claimed-{index}.tmp"));
    fs::write(
        &temporary,
        serde_json::to_vec(&json!({"index":index,"pid":pid,"path":claim.path})).unwrap(),
    )
    .unwrap();
    fs::rename(temporary, report).unwrap();
    wait_for(Instant::now() + Duration::from_secs(5), || {
        root.join("write").is_file()
    });
    let mut file = claim.open(false).unwrap();
    file.write_all(pid.to_string().as_bytes()).unwrap();
    file.sync_all().unwrap();
    drop(file);
    fs::write(root.join(format!("written-{index}")), b"written").unwrap();
    wait_for(Instant::now() + Duration::from_secs(5), || {
        root.join("release").is_file()
    });
    assert_eq!(fs::read(&claim.path).unwrap(), pid.to_string().as_bytes());
    drop(claim);
    fs::write(root.join(format!("done-{index}")), b"done").unwrap();
    true
}

fn child(root: &Path, index: usize) -> OwnedChild {
    let temporary = root.join(format!("child-{index}"));
    fs::create_dir(&temporary).unwrap();
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
        .env(MODE, "claim")
        .env(ROOT, root)
        .env(INDEX, index.to_string())
        .env("HOOKMAKER_MAX_TEST_WORKERS", "1")
        .args(["--exact", CASE, "--test-threads=1"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    OwnedChild(command.spawn().unwrap())
}

#[test]
fn four_independent_processes_hold_distinct_destinations_and_preserve_each_owners_pid_bytes() {
    if child_mode() {
        return;
    }
    fs::create_dir_all(base()).unwrap();
    let scratch = private_tempfile::tempdir_in(base()).unwrap();
    let root = scratch.path().canonicalize().unwrap();
    fs::create_dir(root.join("output with spaces")).unwrap();
    // Four owners are the exact source invariant, not an auto-sized worker pool.
    let mut children: Vec<_> = (0..4).map(|index| child(&root, index)).collect();
    let deadline = Instant::now() + Duration::from_secs(15);
    wait_for(deadline, || {
        (0..4).all(|index| root.join(format!("ready-{index}")).is_file())
    });
    fs::write(root.join("start"), b"start").unwrap();
    wait_for(deadline, || {
        (0..4).all(|index| root.join(format!("claimed-{index}.json")).is_file())
    });
    fs::write(root.join("write"), b"write").unwrap();
    wait_for(deadline, || {
        (0..4).all(|index| root.join(format!("written-{index}")).is_file())
    });
    let mut claimed = BTreeSet::new();
    let mut contents = BTreeSet::new();
    for (index, child) in children.iter_mut().enumerate() {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "claim owner exited before verification"
        );
        let report: Value =
            serde_json::from_slice(&fs::read(root.join(format!("claimed-{index}.json"))).unwrap())
                .unwrap();
        assert_eq!(report["index"], index);
        assert_eq!(report["pid"], child.0.id());
        let path = PathBuf::from(report["path"].as_str().unwrap());
        assert_eq!(path.parent().unwrap(), root.join("output with spaces"));
        let bytes = fs::read(&path).unwrap();
        assert_eq!(bytes, child.0.id().to_string().as_bytes());
        assert!(claimed.insert(path));
        assert!(contents.insert(bytes));
    }
    assert_eq!(claimed.len(), 4);
    assert_eq!(contents.len(), 4);
    assert_eq!(
        claimed,
        [
            "shared.bin",
            "shared (1).bin",
            "shared (2).bin",
            "shared (3).bin"
        ]
        .map(|name| root.join("output with spaces").join(name))
        .into_iter()
        .collect()
    );
    fs::write(root.join("release"), b"release").unwrap();
    for (index, child) in children.iter_mut().enumerate() {
        let mut status = None;
        wait_for(deadline, || {
            status = child.0.try_wait().unwrap();
            status.is_some()
        });
        assert!(
            status.unwrap().success(),
            "destination claimant child failed"
        );
        assert_eq!(
            fs::read(root.join(format!("done-{index}"))).unwrap(),
            b"done"
        );
    }
    assert_eq!(
        claimed
            .iter()
            .map(|path| fs::read(path).unwrap())
            .collect::<BTreeSet<_>>(),
        contents
    );
}

#[path = "common/private_tempfile.rs"]
mod private_tempfile;
