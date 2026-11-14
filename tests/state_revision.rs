//! Older resume snapshots cannot erase newer coverage or metadata.
#![allow(clippy::unwrap_used)]

use std::{fs, path::Path};

use megabasterd_cli::{
    error::Error,
    storage::{
        files::Store,
        transfer_state::{States, TransferState},
    },
};
use serde_json::{Value, json};

#[test]
fn revisions_increase_and_stale_snapshots_leave_newer_coverage_and_metadata_untouched() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/state-revision");
    fs::create_dir_all(&base).unwrap();
    let scratch = private_tempfile::tempdir_in(base).unwrap();
    let path = scratch.path().join("private/transfer.json");
    let states = States::new(&path);
    let mut live = TransferState::new(
        "download",
        "public:fixture",
        &scratch.path().join("output.bin"),
        1024 * 1024,
        &[1; 32],
    )
    .unwrap();
    live.staging_name = Some(".mb-fixture.part".into());
    live.staging_identity = Some("held-fixture-object".into());
    live.completed.insert(0, [0xaa; 16]);
    let stale = live.snapshot().unwrap();
    live.completed.insert(1, [0xbb; 16]);
    live.staging_identity = Some("newer-held-fixture-object".into());
    let fresh = live.snapshot().unwrap();
    assert_eq!((stale.revision, fresh.revision, live.revision), (1, 2, 2));
    assert_eq!(stale.completed.keys().copied().collect::<Vec<_>>(), [0]);
    assert_eq!(
        stale.staging_identity.as_deref(),
        Some("held-fixture-object")
    );
    states.save(&fresh).unwrap();
    let committed = fs::read(&path).unwrap();
    states.save(&stale).unwrap();
    assert_eq!(fs::read(&path).unwrap(), committed);
    let restored = states.load().unwrap().unwrap();
    assert_eq!(restored.revision, 2);
    assert_eq!(restored.completed, fresh.completed);
    assert_eq!(restored.completed[&1], [0xbb; 16]);
    assert_eq!(restored.staging_identity, fresh.staging_identity);
    states.save(&fresh).unwrap();
    assert_eq!(fs::read(&path).unwrap(), committed);

    // Resume validation may deliberately remove bad coverage in a newer snapshot.
    live.completed.remove(&1);
    let repaired = live.snapshot().unwrap();
    assert_eq!(repaired.revision, 3);
    states.save(&repaired).unwrap();
    states.save(&fresh).unwrap();
    let restored = states.load().unwrap().unwrap();
    assert_eq!(restored.revision, 3);
    assert_eq!(restored.completed.keys().copied().collect::<Vec<_>>(), [0]);
    assert_eq!(restored.completed[&0], [0xaa; 16]);

    let committed = fs::read(&path).unwrap();
    live.revision = u64::MAX;
    assert!(matches!(live.snapshot(), Err(Error::Corrupt(reason)) if reason.contains("revision")));
    assert_eq!(live.revision, u64::MAX);
    assert_eq!(live.completed, repaired.completed);
    assert_eq!(fs::read(&path).unwrap(), committed);
    assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 2);
}

#[test]
fn a_committed_foreign_source_at_revision_200_refuses_revision_one_without_changing_bytes() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/state-revision");
    fs::create_dir_all(&base).unwrap();
    let scratch = private_tempfile::tempdir_in(base).unwrap();
    let destination = scratch.path().join("file.bin");
    fs::write(&destination, vec![0; 1024]).unwrap();
    let path = scratch.path().join("private/transfer.json");
    let states = States::new(&path);
    let mut committed =
        TransferState::new("download", "committed-source", &destination, 1024, &[1; 32]).unwrap();
    committed.revision = 200;
    states.save(&committed).unwrap();
    let before = fs::read(&path).unwrap();
    let mut stale =
        TransferState::new("download", "stale-worker", &destination, 1024, &[1; 32]).unwrap();
    stale.revision = 1;
    assert!(matches!(
        states.save(&stale),
        Err(Error::Corrupt(reason)) if reason.contains("unrelated")
    ));
    assert_eq!(fs::read(&path).unwrap(), before);
    let restored = states.load().unwrap().unwrap();
    assert_eq!(restored.source_hash, committed.source_hash);
    assert_ne!(restored.source_hash, stale.source_hash);
    assert_eq!(restored.revision, 200);
    assert!(restored.completed.is_empty());
    assert_eq!(fs::read(&destination).unwrap(), vec![0; 1024]);
}

#[test]
fn a_positive_size_empty_coverage_state_persists_without_creating_its_destination() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/state-revision");
    fs::create_dir_all(&base).unwrap();
    let scratch = private_tempfile::tempdir_in(base).unwrap();
    let destination = scratch.path().join("not-created-yet.mkv");
    let path = scratch.path().join("private/transfer.json");
    assert_ne!(destination, path);
    assert!(!destination.exists() && !path.exists());
    let states = States::new(&path);
    let mut state = TransferState::new(
        "download",
        "https://mega.invalid/file/X",
        &destination,
        4096,
        &[1; 32],
    )
    .unwrap();
    state.revision = 1;
    assert!(state.completed.is_empty());
    states.save(&state).unwrap();
    assert!(path.is_file());
    assert!(!destination.exists());
    let restored = states.load().unwrap().unwrap();
    assert_eq!(restored.size, 4096);
    assert_eq!(restored.destination, destination.to_string_lossy().as_ref());
    assert_eq!(restored.revision, 1);
    assert!(restored.completed.is_empty());
    assert!(!destination.exists());
}

#[test]
fn native_revision_defaults_to_zero_but_invalid_saved_types_never_become_usable() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/state-revision");
    fs::create_dir_all(&base).unwrap();
    let scratch = private_tempfile::tempdir_in(base).unwrap();
    let path = scratch.path().join("private/transfer.json");
    let state = TransferState::new("download", "fixture", &path, 0, &[1; 32]).unwrap();
    let mut data = serde_json::to_value(&state).unwrap();
    data.as_object_mut().unwrap().remove("revision");
    let restored: TransferState = serde_json::from_value(data.clone()).unwrap();
    assert_eq!(restored.revision, 0);
    let store = Store::new(&path);
    let states = States::new(&path);
    store.lock().unwrap().save(&data).unwrap();
    assert_eq!(states.load().unwrap().unwrap().revision, 0);
    for invalid in [json!(true), json!(-1), json!(1.5), json!("2"), Value::Null] {
        data["revision"] = invalid;
        let bytes = serde_json::to_vec(&json!({"version":2,"data":data})).unwrap();
        store.lock().unwrap().write_bytes(&bytes).unwrap();
        assert!(matches!(states.load(), Err(Error::Corrupt(_))));
        assert!(matches!(states.save(&state), Err(Error::Corrupt(_))));
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 2);
    }
}

#[path = "common/private_tempfile.rs"]
mod private_tempfile;
