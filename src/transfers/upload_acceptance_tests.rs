//! Persist first-valid token ownership through the same acceptance step used by upload workers.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::protocol::uploads::completion_token;
use std::collections::BTreeMap;

#[test]
fn late_final_response_never_replaces_the_first_valid_durable_completion_token() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/upload-acceptance");
    std::fs::create_dir_all(&root).unwrap();
    let scratch = tempfile::tempdir_in(root).unwrap();
    let source = scratch.path().join("source.bin");
    std::fs::write(&source, [7; 131089]).unwrap();
    let path = scratch.path().join("private state/receipt.json");
    let states = States::new(&path);
    let state = TransferState::new("upload", "synthetic source", &path, 131089, &[1; 16]).unwrap();
    let mut shared = Shared {
        file: File::open(&source).unwrap(),
        state,
        done: 0,
        error: None,
        expired: false,
    };
    let mut chunks = chunks::iter_chunks(131089).unwrap();
    let first = chunks.next().unwrap();
    let final_chunk = chunks.next().unwrap();
    assert!(final_chunk.end().unwrap() == shared.state.size);
    for body in [b"FIRST".as_slice(), b"SECOND".as_slice()] {
        let token = completion_token(body, true).unwrap();
        shared.accept(final_chunk, [2; 16], token, &states).unwrap();
        assert_eq!(shared.state.completion_token.as_deref(), Some("FIRST"));
        let saved = states.load().unwrap().unwrap();
        assert_eq!(saved.completion_token.as_deref(), Some("FIRST"));
        assert_eq!(saved.completed, BTreeMap::from([(1, [2; 16])]));
        assert!(!saved.registration_started && saved.registered_handle.is_none());
    }
    assert!(first.end().unwrap() < shared.state.size);
    shared
        .accept(
            first,
            [3; 16],
            completion_token(b"", false).unwrap(),
            &states,
        )
        .unwrap();
    let saved = states.load().unwrap().unwrap();
    assert_eq!(shared.state.completion_token.as_deref(), Some("FIRST"));
    assert_eq!(saved.completion_token.as_deref(), Some("FIRST"));
    assert_eq!(
        saved.completed,
        BTreeMap::from([(0, [3; 16]), (1, [2; 16])])
    );
    assert_eq!(std::fs::read(&source).unwrap(), vec![7; 131089]);
}
