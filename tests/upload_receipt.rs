#![allow(clippy::unwrap_used)]

use megabasterd_cli::{
    error::Error,
    storage::{
        transfer_state::{States, TransferState},
        vault::Vault,
    },
    transfers::upload::confirmed_receipt,
};

#[test]
fn confirmed_upload_receipt_reconstructs_keys_without_a_second_registration() {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/upload-receipt");
    std::fs::create_dir_all(&base).unwrap();
    let scratch = private_tempfile::tempdir_in(base).unwrap();
    let path = scratch.path().join("private/upload.json");
    let material: Vec<u8> = (0u8..16).chain(0..8).collect();
    let vault = Vault::new("synthetic fixture passphrase");
    let mut state = TransferState::new("upload", "binding", &path, 3, &material[..16]).unwrap();
    state.completed.insert(0, [2; 16]);
    state.completion_token = Some("FCCyf3QV62uAsbARFKbVd8zWyqOQXPFgEL9i".into());
    state.sealed_upload_key = Some(vault.seal(&material, b"fixture").unwrap());
    state.upload_url = Some("https://gfs270n123.userstorage.mega.co.nz/ul/fake".into());
    state.registration_started = true;
    let states = States::new(&path);
    states.save(&state).unwrap();
    assert!(confirmed_receipt(&state, &material, "name.txt", &path).is_err());
    state.registered_handle = Some("AQIDBAUG".into());
    states.save(&state).unwrap();
    let reopened = states.load().unwrap().unwrap();
    let key = vault
        .open(reopened.sealed_upload_key.as_deref().unwrap(), b"fixture")
        .unwrap();
    assert_eq!(&key[..16], (0u8..16).collect::<Vec<_>>());
    assert_eq!(&key[16..], (0u8..8).collect::<Vec<_>>());
    assert_eq!(
        reopened.upload_url.as_deref(),
        Some("https://gfs270n123.userstorage.mega.co.nz/ul/fake")
    );
    let stored: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert!(stored["data"].get("aes_key").is_none());
    assert!(stored["data"].get("nonce").is_none());
    assert_eq!(
        std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
        2
    );
    let uploaded = confirmed_receipt(&reopened, &key, "name.txt", &path).unwrap();
    assert_eq!(uploaded.handle, "AQIDBAUG");
    assert_eq!(uploaded.name, "name.txt");
    assert_eq!(uploaded.size, 3);
    assert_eq!(uploaded.raw_key.len(), 32);
    assert!(states.load().unwrap().unwrap().registered_handle.is_some());
    assert!(confirmed_receipt(&reopened, &[0; 23], "name.txt", &path).is_err());
}

#[test]
fn finalization_flags_cannot_claim_unregistered_or_unstarted_completion() {
    let mut state = TransferState::new(
        "upload",
        "binding",
        std::path::Path::new("receipt.json"),
        0,
        &[1; 16],
    )
    .unwrap();
    state.finalization_started = true;
    assert!(matches!(state.validate(), Err(Error::Corrupt(_))));
    state.finalization_started = false;
    state.finalization_completed = true;
    assert!(matches!(state.validate(), Err(Error::Corrupt(_))));
    state.completion_token = Some("FCCyf3QV62uAsbARFKbVd8zWyqOQXPFgEL9i".into());
    state.registration_started = true;
    state.registered_handle = Some("FILE0001".into());
    assert!(matches!(state.validate(), Err(Error::Corrupt(_))));
    state.finalization_started = true;
    state.validate().unwrap();
}

#[test]
fn confirmed_receipt_fences_side_effects_and_never_replays_completed_or_unknown_finalization() {
    let base =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/upload-finalization");
    std::fs::create_dir_all(&base).unwrap();
    for completes in [false, true] {
        let scratch = private_tempfile::tempdir_in(&base).unwrap();
        let path = scratch.path().join("private/upload.json");
        let material = [1; 24];
        let mut state = TransferState::new("upload", "binding", &path, 3, &material[..16]).unwrap();
        state.completed.insert(0, [2; 16]);
        state.completion_token = Some("FCCyf3QV62uAsbARFKbVd8zWyqOQXPFgEL9i".into());
        state.registration_started = true;
        state.registered_handle = Some("FILE0001".into());
        let states = States::new(&path);
        states.save(&state).unwrap();
        let uploaded = confirmed_receipt(&state, &material, "file.bin", &path).unwrap();
        let mut callbacks = 0;
        let result = uploaded.finalize(|| {
            callbacks += 1;
            assert!(matches!(
                uploaded.finalize(|| panic!("overlapping finalization")),
                Err(Error::Busy(_))
            ));
            if completes {
                Ok(())
            } else {
                Err(Error::Timeout)
            }
        });
        assert_eq!(callbacks, 1);
        if completes {
            result.unwrap();
        } else {
            assert!(matches!(result, Err(Error::AmbiguousMutation(_))));
        }
        let saved = states.load().unwrap().unwrap();
        assert!(saved.finalization_started);
        assert_eq!(saved.finalization_completed, completes);
        let reopened = confirmed_receipt(&saved, &material, "file.bin", &path).unwrap();
        let retry = reopened.finalize(|| panic!("side effect replayed"));
        if completes {
            retry.unwrap();
        } else {
            assert!(matches!(retry, Err(Error::AmbiguousMutation(_))));
        }
        assert_eq!(
            states.load().unwrap().unwrap().registered_handle.as_deref(),
            Some("FILE0001")
        );
    }
}

#[path = "common/private_tempfile.rs"]
mod private_tempfile;
