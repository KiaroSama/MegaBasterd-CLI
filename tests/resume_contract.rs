#![allow(clippy::unwrap_used)]
use megabasterd_cli::storage::transfer_state::{States, TransferState};

#[test]
fn changed_source_cleanup_removes_only_matching_unregistered_upload_state() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/state-cleanup");
    std::fs::create_dir_all(&root).unwrap();
    let scratch = private_tempfile::tempdir_in(root).unwrap();
    let path = scratch.path().join("upload.json");
    let states = States::new(&path);
    let mut state = TransferState::new("upload", "account:target", &path, 17, &[1; 16]).unwrap();
    state.source_identity = Some("original-identity".into());
    states.save(&state).unwrap();
    let bytes = std::fs::read(&path).unwrap();
    let mut foreign = state.clone();
    foreign.source_identity = Some("different-identity".into());
    assert!(states.discard_unregistered_upload(&foreign).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    states.discard_unregistered_upload(&state).unwrap();
    assert!(states.load().unwrap().is_none());

    state.completion_token = Some("FCCyf3QV62uAsbARFKbVd8zWyqOQXPFgEL9i".into());
    state.registration_started = true;
    for handle in [None, Some("AQIDBAUG".to_owned())] {
        state.registered_handle = handle;
        state.completed.insert(0, [0; 16]);
        states.save(&state).unwrap();
        let before = std::fs::read(&path).unwrap();
        assert!(states.discard_unregistered_upload(&state).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    let future = b"{\"version\":999,\"data\":{}}";
    let store = megabasterd_cli::storage::files::Store::new(&path);
    store.lock().unwrap().write_bytes(future).unwrap();
    assert!(states.discard_unregistered_upload(&state).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), future);
}

#[test]
fn completion_requires_every_chunk_even_when_integrity_verification_is_disabled() {
    use megabasterd_cli::error::Error;

    let mut state = TransferState::new(
        "download",
        "public:file",
        std::path::Path::new("file.bin"),
        1024 * 1024,
        &[1; 32],
    )
    .unwrap();
    for indices in [vec![], vec![1, 2, 3], vec![0, 2, 3], vec![0, 1, 2]] {
        state.completed = indices.into_iter().map(|index| (index, [0; 16])).collect();
        assert!(
            matches!(state.require_complete(), Err(Error::Integrity(message))
            if message == "Transfer is missing completed chunks")
        );
    }
    state.completed = (0..4).map(|index| (index, [0; 16])).collect();
    state.require_complete().unwrap();
    state.completed.remove(&3);
    state.completed.insert(4, [0; 16]);
    assert!(matches!(state.require_complete(), Err(Error::Corrupt(_))));

    let empty = TransferState::new(
        "download",
        "public:empty",
        std::path::Path::new("empty.bin"),
        0,
        &[1; 32],
    )
    .unwrap();
    empty.require_complete().unwrap();
}

#[test]
fn resume_identity_and_coverage_cannot_silently_switch_file_or_key() {
    let original = TransferState::new(
        "download",
        "public:file",
        std::path::Path::new("file.bin"),
        1024,
        &[1; 32],
    )
    .unwrap();
    assert!(original.compatible(&original));
    let different = TransferState::new(
        "download",
        "public:file",
        std::path::Path::new("file.bin"),
        1024,
        &[2; 32],
    )
    .unwrap();
    assert!(!original.compatible(&different));
    for (source, destination, size) in [
        ("public:other", "file.bin", 1024),
        ("public:file", "other.bin", 1024),
        ("public:file", "file.bin", 2048),
    ] {
        let changed = TransferState::new(
            "download",
            source,
            std::path::Path::new(destination),
            size,
            &[1; 32],
        )
        .unwrap();
        assert!(
            !original.compatible(&changed),
            "unrelated state accepted: {source}, {destination}, {size}"
        );
    }
    let mut corrupt = original.clone();
    corrupt.completed.insert(1000, [0; 16]);
    assert!(corrupt.validate().is_err());
    corrupt.completed.clear();
    corrupt.key_hash.clear();
    assert!(corrupt.validate().is_err());
    let mut upload = TransferState::new(
        "upload",
        "account:target",
        std::path::Path::new("upload"),
        32,
        &[1; 16],
    )
    .unwrap();
    upload.registration_started = true;
    assert!(upload.validate().is_err());
    upload.completion_token = Some("FCCyf3QV62uAsbARFKbVd8zWyqOQXPFgEL9i".into());
    assert!(upload.validate().is_ok());
    upload.registered_handle = Some("AQIDBAUG".into());
    assert!(
        upload.validate().is_err(),
        "confirmed receipt needs complete chunk coverage"
    );
    upload.completed.insert(0, [0; 16]);
    assert!(upload.validate().is_ok());
    upload.registration_started = false;
    assert!(upload.validate().is_err());
    upload.registration_started = true;
    upload.registered_handle = Some("../unsafe".into());
    assert!(upload.validate().is_err());
    upload.registered_handle = None;
    upload.completion_token = Some(" ".repeat(27));
    assert!(upload.validate().is_err());
}

#[path = "common/private_tempfile.rs"]
mod private_tempfile;
