//! State entry points must not read, replace or unlink behind another native writer.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::platform::secure_files::{PrivateDirectory, file_identity};
use std::{ffi::OsStr, fs, time::Duration};

#[test]
fn state_entry_points_refuse_a_held_writer_and_clear_only_after_release() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/state-lock");
    fs::create_dir_all(&base).unwrap();
    for mode in ["missing", "valid", "corrupt", "future"] {
        let scratch = crate::test_support::tempdir_in(&base).unwrap();
        let path = scratch.path().join("private/state.json");
        let states = States(Store::new(&path).with_timeout(Duration::ZERO));
        let state = TransferState::new("upload", "fixture", &path, 0, &[1; 16]).unwrap();
        let owner = Store::new(&path).lock().unwrap();
        match mode {
            "valid" => owner.save(&state).unwrap(),
            "corrupt" => owner.write_bytes(b"{ broken state").unwrap(),
            "future" => owner
                .write_bytes(br#"{"version":99,"new_schema":true}"#)
                .unwrap(),
            _ => (),
        }
        let before = fs::read(&path).ok();
        let directory = PrivateDirectory::open(path.parent().unwrap()).unwrap();
        let sidecar = directory
            .open_private(OsStr::new("state.json.lock"), false)
            .unwrap();
        let identity = file_identity(&sidecar).unwrap();
        for action in 0..4 {
            let result = match action {
                0 => states.load().map(|_| ()),
                1 => states.save(&state),
                2 => states.clear(),
                _ => states.discard_unregistered_upload(&state),
            };
            let error = result.unwrap_err();
            assert!(matches!(error, Error::Busy(_)));
            assert_eq!(error.code(), "resource_busy");
            assert_eq!(error.exit_code(), 1);
            assert_eq!(fs::read(&path).ok(), before);
            assert_eq!(
                fs::read_dir(path.parent().unwrap()).unwrap().count(),
                1 + usize::from(before.is_some())
            );
        }
        drop(owner);
        if matches!(mode, "corrupt" | "future") {
            assert!(matches!(states.clear(), Err(Error::Corrupt(_))));
            assert_eq!(fs::read(&path).ok(), before);
        } else {
            states.clear().unwrap();
            states.clear().unwrap();
            assert!(!path.exists());
            assert!(states.load().unwrap().is_none());
            assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
            states.save(&state).unwrap();
            states.discard_unregistered_upload(&state).unwrap();
            assert!(!path.exists());
        }
        let current = directory
            .open_private(OsStr::new("state.json.lock"), false)
            .unwrap();
        assert_eq!(file_identity(&current).unwrap(), identity);
    }
}
