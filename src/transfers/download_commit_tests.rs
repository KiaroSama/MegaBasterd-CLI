//! The production chunk commit cannot record coverage before its data-sync barrier succeeds.
#![allow(clippy::unwrap_used)]

use super::*;
use std::io::{Read, Seek};

#[test]
fn chunk_sync_failure_never_publishes_coverage_and_success_syncs_before_the_eighth_chunk_checkpoint()
 {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/download-commit");
    std::fs::create_dir_all(&base).unwrap();
    for failure in [
        Some(std::io::ErrorKind::PermissionDenied),
        Some(std::io::ErrorKind::StorageFull),
        Some(std::io::ErrorKind::Other),
        None,
    ] {
        let scratch = tempfile::tempdir_in(&base).unwrap();
        let destination = scratch.path().join("staging.bin");
        let mut file = File::create(&destination).unwrap();
        file.set_len(4_718_592).unwrap();
        file.sync_all().unwrap();
        let path = scratch.path().join("private/state.json");
        let states = States::new(&path);
        let mut state =
            TransferState::new("download", "fixture", &destination, 4_718_592, &[1; 32]).unwrap();
        for index in 1..8 {
            state.completed.insert(index, [0xbb; 16]);
        }
        states.save(&state).unwrap();
        let previous = std::fs::read(&path).unwrap();
        let coverage = state.completed.clone();
        let chunk = chunks::iter_chunks(state.size).unwrap().next().unwrap();
        let plain = vec![0x5a; 128 * 1024];
        let mut synchronizations = 0;
        let result = commit_download_chunk(
            &mut file,
            &mut state,
            chunk,
            &plain,
            [0xaa; 16],
            &states,
            |file| {
                synchronizations += 1;
                assert_eq!(std::fs::read(&path).unwrap(), previous);
                let mut written = File::open(&destination).unwrap();
                let mut actual = vec![0; plain.len()];
                written.read_exact(&mut actual).unwrap();
                assert_eq!(actual, plain);
                assert_eq!(
                    std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
                    2
                );
                if let Some(kind) = failure {
                    Err(std::io::Error::new(
                        kind,
                        match kind {
                            std::io::ErrorKind::StorageFull => "No space",
                            std::io::ErrorKind::PermissionDenied => "Permission denied",
                            _ => "Input/output error",
                        },
                    ))
                } else {
                    file.sync_data()
                }
            },
        );
        assert_eq!(synchronizations, 1);
        if let Some(kind) = failure {
            let error = result.unwrap_err();
            assert_eq!(error.code(), "io_error");
            assert_eq!(error.exit_code(), 1);
            let message = match kind {
                std::io::ErrorKind::StorageFull => "No space",
                std::io::ErrorKind::PermissionDenied => "Permission denied",
                _ => "Input/output error",
            };
            assert!(error.to_string().contains(message));
            assert!(
                matches!(error, Error::Io(error) if error.kind() == kind && error.to_string() == message)
            );
            assert_eq!(state.completed, coverage);
            assert_eq!(state.revision, 0);
            assert_eq!(std::fs::read(&path).unwrap(), previous);
            assert_eq!(states.load().unwrap().unwrap().completed, coverage);
        } else {
            result.unwrap();
            let saved = states.load().unwrap().unwrap();
            assert_eq!(saved.completed.len(), 8);
            assert_eq!(saved.completed[&0], [0xaa; 16]);
            assert_eq!(saved.revision, 1);
            assert_eq!(saved.completed, state.completed);
        }
        assert_eq!(
            std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
            2
        );
        file.seek(SeekFrom::Start(0)).unwrap();
        drop(file);
        let mut read_only = File::open(&destination).unwrap();
        let before = std::fs::read(&path).unwrap();
        let revision = state.revision;
        let coverage = state.completed.clone();
        let result = commit_download_chunk(
            &mut read_only,
            &mut state,
            chunk,
            &plain,
            [0xcc; 16],
            &states,
            |_| panic!("failed data write must not reach synchronization"),
        );
        assert!(matches!(result, Err(Error::Io(_))));
        assert_eq!(state.revision, revision);
        assert_eq!(state.completed, coverage);
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}
