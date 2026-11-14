//! Whole-transfer leases exercised by real uploads, independent of queued-operation ownership.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::platform::secure_files::{PrivateDirectory, file_identity};
use crate::storage::files::Store;
use std::time::Duration;

#[path = "upload_lease_process_tests.rs"]
mod process_tests;

fn unqueued(
    cloud: &mut Cloud,
    source: &Path,
    states: &Path,
    vault: &Vault,
) -> crate::error::Result<Uploaded> {
    let control = cloud.api.control.clone();
    let progress = Progress::new(false);
    let item = progress.add("lease fixture", std::fs::metadata(source)?.len())?;
    upload(
        cloud,
        source,
        "target",
        None,
        1,
        states,
        vault,
        true,
        None,
        &RateLimiter::new(0.0)?,
        &progress,
        item,
        &control,
    )
}

fn lease(states: &Path, data: &Path) -> PathBuf {
    let path = data.with_extension("lease");
    assert_eq!(path.parent(), Some(states));
    assert!(path.with_extension("lease.lock").is_file());
    path
}

fn data_paths(states: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(states)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect()
}

#[test]
fn actual_upload_retains_its_lease_until_receipt_drop_and_distinct_sources_do_not_contend() {
    let scratch = scratch();
    let source = source(scratch.path(), 17);
    let other = scratch.path().join("other.bin");
    std::fs::write(&other, b"independent bytes").unwrap();
    let original = std::fs::read(&source).unwrap();
    let states = scratch.path().join("private state");
    let vault = Vault::new("synthetic upload passphrase");
    let mut slots = 0;
    let mut registrations = 0;
    let ((), calls) = test_peer::with_peer(
        |request| {
            if request.path.starts_with("/native-peer-upload/lease/") {
                assert_eq!(request.body.len(), 17);
                return Some(Response {
                    status: 200,
                    headers: vec![],
                    body: TOKEN.as_bytes().to_vec(),
                });
            }
            Some(match command(request)["a"].as_str().unwrap() {
                "u" => {
                    slots += 1;
                    api(
                        json!({"p":format!("https://upload.mega.nz/native-peer-upload/lease/{slots}")}),
                    )
                }
                "p" => {
                    registrations += 1;
                    api(json!({"f":[{"h":"AQIDBAUG"}]}))
                }
                _ => panic!("lease fixture contacted an unexpected action"),
            })
        },
        |address| {
            let mut first_cloud = cloud(address);
            let first = unqueued(&mut first_cloud, &source, &states, &vault).unwrap();
            let first_paths = data_paths(&states);
            assert_eq!(first_paths.len(), 1);
            let lease_path = lease(&states, &first_paths[0]);
            let directory = PrivateDirectory::open(&states).unwrap();
            let sidecar_name =
                format!("{}.lock", lease_path.file_name().unwrap().to_str().unwrap());
            let original_sidecar = directory
                .open_private(std::ffi::OsStr::new(&sidecar_name), false)
                .unwrap();
            let identity = file_identity(&original_sidecar).unwrap();
            let saved = std::fs::read(&first_paths[0]).unwrap();
            for _ in 0..2 {
                let error = unqueued(&mut cloud(address), &source, &states, &vault)
                    .err()
                    .unwrap();
                assert!(matches!(error, Error::Busy(_)));
                assert_eq!(data_paths(&states), first_paths);
                assert_eq!(std::fs::read(&first_paths[0]).unwrap(), saved);
            }
            let second = unqueued(&mut cloud(address), &other, &states, &vault).unwrap();
            let paths = data_paths(&states);
            assert_eq!(paths.len(), 2);
            let second_path = paths
                .iter()
                .find(|path| !first_paths.contains(path))
                .unwrap();
            assert_ne!(lease(&states, second_path), lease_path);
            for path in &paths {
                assert!(matches!(
                    Store::new(path.with_extension("lease"))
                        .with_timeout(Duration::ZERO)
                        .lock(),
                    Err(Error::Busy(_))
                ));
            }
            first.acknowledge().unwrap();
            assert!(matches!(
                unqueued(&mut first_cloud, &source, &states, &vault),
                Err(Error::Busy(_))
            ));
            drop(first);
            let third = unqueued(&mut first_cloud, &source, &states, &vault).unwrap();
            assert_eq!(third.size, 17);
            let current_sidecar = directory
                .open_private(std::ffi::OsStr::new(&sidecar_name), false)
                .unwrap();
            assert_eq!(file_identity(&current_sidecar).unwrap(), identity);
            assert_eq!(current_sidecar.metadata().unwrap().len(), 0);
            third.acknowledge().unwrap();
            second.acknowledge().unwrap();
            drop(third);
            drop(second);
            assert!(data_paths(&states).is_empty());
            for path in paths {
                assert!(
                    Store::new(path.with_extension("lease"))
                        .with_timeout(Duration::ZERO)
                        .lock()
                        .is_ok()
                );
                assert!(path.with_extension("lease.lock").is_file());
            }
            assert_eq!(std::fs::read(&source).unwrap(), original);
            assert_eq!(std::fs::read(&other).unwrap(), b"independent bytes");
        },
    );
    assert_eq!((slots, registrations, calls.len()), (3, 3, 9));
}

#[test]
fn actual_upload_error_releases_the_same_persistent_lease_before_a_successful_resume() {
    let scratch = scratch();
    let source = source(scratch.path(), 17);
    let original = std::fs::read(&source).unwrap();
    let states = scratch.path().join("private state");
    let vault = Vault::new("synthetic upload passphrase");
    let mut bodies = 0;
    let mut first_body = None;
    let ((), calls) = test_peer::with_peer(
        |request| {
            if request.path.starts_with("/native-peer-upload/") {
                bodies += 1;
                if let Some(first) = &first_body {
                    assert_eq!(&request.body, first);
                } else {
                    first_body = Some(request.body.clone());
                }
                return Some(Response {
                    status: if bodies == 1 { 400 } else { 200 },
                    headers: vec![],
                    body: if bodies == 1 {
                        vec![]
                    } else {
                        TOKEN.as_bytes().to_vec()
                    },
                });
            }
            Some(match command(request)["a"].as_str().unwrap() {
                "u" => api(json!({"p":SLOT})),
                "p" => api(json!({"f":[{"h":"AQIDBAUG"}]})),
                _ => panic!("failed lease fixture contacted an unexpected action"),
            })
        },
        |address| {
            let error = unqueued(&mut cloud(address), &source, &states, &vault)
                .err()
                .unwrap();
            assert!(
                matches!(error, Error::Protocol(message) if message == "Upload chunk returned HTTP 400")
            );
            let paths = data_paths(&states);
            assert_eq!(paths.len(), 1);
            let lease_path = lease(&states, &paths[0]);
            let directory = PrivateDirectory::open(&states).unwrap();
            let sidecar_name =
                format!("{}.lock", lease_path.file_name().unwrap().to_str().unwrap());
            let original_sidecar = directory
                .open_private(std::ffi::OsStr::new(&sidecar_name), false)
                .unwrap();
            let identity = file_identity(&original_sidecar).unwrap();
            let held = Store::new(&lease_path)
                .with_timeout(Duration::ZERO)
                .lock()
                .unwrap();
            assert!(matches!(
                unqueued(&mut cloud(address), &source, &states, &vault),
                Err(Error::Busy(_))
            ));
            drop(held);
            let uploaded = unqueued(&mut cloud(address), &source, &states, &vault).unwrap();
            assert_eq!(uploaded.size, 17);
            uploaded.acknowledge().unwrap();
            drop(uploaded);
            assert!(
                Store::new(&lease_path)
                    .with_timeout(Duration::ZERO)
                    .lock()
                    .is_ok()
            );
            let current_sidecar = directory
                .open_private(std::ffi::OsStr::new(&sidecar_name), false)
                .unwrap();
            assert_eq!(file_identity(&current_sidecar).unwrap(), identity);
            assert!(data_paths(&states).is_empty());
            assert_eq!(std::fs::read(&source).unwrap(), original);
        },
    );
    assert_eq!(bodies, 2);
    assert_eq!(
        calls.len(),
        4,
        "lease refusal requested a slot or replayed registration"
    );
    assert_eq!(
        calls
            .iter()
            .filter(|request| request.path.starts_with("/cs?") && command(request)["a"] == "u")
            .count(),
        1
    );
}
