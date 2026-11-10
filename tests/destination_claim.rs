//! Destination ownership is atomic, collision-safe and never unlinks a live lock name.
#![allow(clippy::unwrap_used)]

use std::{
    collections::BTreeSet,
    ffi::OsStr,
    fs,
    path::Path,
    sync::{Condvar, Mutex},
    time::Duration,
};

use megabasterd_cli::{
    platform::secure_files::file_identity,
    transfers::{claims::Claim, planner::filename},
};

fn scratch() -> tempfile::TempDir {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/destination-claims");
    fs::create_dir_all(&base).unwrap();
    tempfile::tempdir_in(base).unwrap()
}

#[test]
fn parallel_identical_names_keep_eight_distinct_owners_until_release() {
    let scratch = scratch();
    let target = scratch.path().join("video.mp4");
    let workers = std::env::var("HOOKMAKER_MAX_TEST_WORKERS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(2)
        .clamp(1, 2);
    let ready = (Mutex::new(0usize), Condvar::new());
    let next = std::sync::atomic::AtomicUsize::new(0);
    let claims = std::thread::scope(|scope| {
        let mut threads = Vec::new();
        for _ in 0..workers {
            threads.push(scope.spawn(|| {
                let mut count = ready.0.lock().unwrap();
                *count += 1;
                ready.1.notify_all();
                let (count, _) = ready
                    .1
                    .wait_timeout_while(count, Duration::from_secs(2), |count| *count < workers)
                    .unwrap();
                assert_eq!(*count, workers, "claim workers did not rendezvous");
                drop(count);
                let mut owned = Vec::new();
                while next.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 8 {
                    owned.push(Claim::acquire(&target, false, |_| Ok(false)).unwrap());
                }
                owned
            }));
        }
        threads
            .into_iter()
            .flat_map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>()
    });
    let actual: BTreeSet<_> = claims.iter().map(|claim| claim.path.clone()).collect();
    let expected: BTreeSet<_> = (0..8)
        .map(|index| {
            target.with_file_name(if index == 0 {
                "video.mp4".to_owned()
            } else {
                format!("video ({index}).mp4")
            })
        })
        .collect();
    assert_eq!(claims.len(), 8);
    assert_eq!(actual, expected);
    assert!(actual.iter().all(|path| !path.exists()));
    drop(claims);
    for path in actual {
        let claim = Claim::acquire(&path, false, |_| Ok(false)).unwrap();
        assert_eq!(claim.path, path);
    }
    assert_eq!(fs::read_dir(scratch.path()).unwrap().count(), 8);
}

#[test]
fn sanitized_collisions_and_existing_files_require_distinct_claims_unless_explicitly_reused() {
    let scratch = scratch();
    let target = scratch.path().join("file.txt");
    let available = Claim::acquire(&target, false, |_| Ok(false)).unwrap();
    assert_eq!(available.path, target);
    assert!(!target.exists());
    drop(available);
    fs::write(&target, b"x").unwrap();
    let occupied = Claim::acquire(&target, false, |_| Ok(false)).unwrap();
    assert_eq!(occupied.path, scratch.path().join("file (1).txt"));
    assert!(!occupied.path.exists());
    assert_eq!(fs::read(&target).unwrap(), b"x");
    drop(occupied);
    let first_name = filename("report?.txt");
    assert_eq!(first_name, filename("report*.txt"));
    let first = Claim::acquire(&scratch.path().join(&first_name), false, |_| Ok(false)).unwrap();
    let second = Claim::acquire(&scratch.path().join(filename("report*.txt")), false, |_| {
        Ok(false)
    })
    .unwrap();
    assert_ne!(first.path, second.path);
    drop(first);
    drop(second);
    let target = scratch.path().join("keep.bin");
    fs::write(&target, b"precious").unwrap();
    for (overwrite, resumable, expected) in [
        (false, false, "keep (1).bin"),
        (true, false, "keep.bin"),
        (false, true, "keep.bin"),
    ] {
        let claim = Claim::acquire(&target, overwrite, |_| Ok(resumable)).unwrap();
        assert_eq!(claim.path, target.with_file_name(expected));
        assert_eq!(fs::read(&target).unwrap(), b"precious");
    }
}

#[test]
fn released_sidecars_remain_inert_reusable_and_cannot_split_three_party_ownership() {
    let scratch = scratch();
    let target = scratch.path().join("shared.bin");
    let first = Claim::acquire(&target, false, |_| Ok(false)).unwrap();
    let sidecar = first
        .directory
        .open_file(OsStr::new("shared.bin.mbclaim"), false)
        .unwrap();
    let identity = file_identity(&sidecar).unwrap();
    drop(first);
    assert_eq!(sidecar.metadata().unwrap().len(), 0);
    sidecar.try_lock().unwrap();
    let third = Claim::acquire(&target, false, |_| Ok(false)).unwrap();
    assert_eq!(third.path, target.with_file_name("shared (1).bin"));
    drop(third);
    sidecar.unlock().unwrap();
    for _ in 0..3 {
        let claim = Claim::acquire(&target, false, |_| Ok(false)).unwrap();
        assert_eq!(claim.path, target);
        let current = claim
            .directory
            .open_read(OsStr::new("shared.bin.mbclaim"))
            .unwrap();
        assert_eq!(file_identity(&current).unwrap(), identity);
    }
    let claim = Claim::acquire(&target, false, |_| Ok(false)).unwrap();
    assert_eq!(claim.path, target);
    assert_eq!(claim.directory.entries(4).unwrap().len(), 2);
    assert!(!target.exists());

    let cycle = scratch.path().join("cycle.bin");
    for expected in ["cycle.bin", "cycle (1).bin", "cycle (2).bin"] {
        let claim = Claim::acquire(&cycle, false, |_| Ok(false)).unwrap();
        assert_eq!(claim.path.file_name().unwrap(), expected);
        let mut file = claim.directory.open_file(&claim.name, true).unwrap();
        std::io::Write::write_all(&mut file, b"done").unwrap();
        file.sync_all().unwrap();
    }
    for name in [
        "cycle.bin.mbclaim",
        "cycle (1).bin.mbclaim",
        "cycle (2).bin.mbclaim",
    ] {
        let file = claim.directory.open_file(OsStr::new(name), false).unwrap();
        file.try_lock().unwrap();
        assert_eq!(file.metadata().unwrap().len(), 0);
    }
    assert_eq!(fs::read_dir(scratch.path()).unwrap().count(), 8);
}
