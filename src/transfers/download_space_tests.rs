//! Free-space preflight enters the production download path before staging or CDN work.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::platform::secure_files::OutputDirectory;
use crate::protocol::{metadata::DownloadSource, test_peer};

#[test]
fn anchored_space_query_remains_usable_without_creating_output() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/download-space");
    std::fs::create_dir_all(&base).unwrap();
    let scratch = crate::test_support::tempdir_in(base).unwrap();
    let path = scratch.path().join("output with spaces");
    std::fs::create_dir(&path).unwrap();
    let directory = OutputDirectory::open(&path).unwrap();
    let _available_bytes: u64 = directory.available_space().unwrap();
    assert!(directory.entries(1).unwrap().is_empty());
    #[cfg(unix)]
    {
        // The descriptor, not a now-vacant pathname, selects the filesystem.
        let moved = scratch.path().join("moved output");
        std::fs::rename(&path, &moved).unwrap();
        let _available_bytes: u64 = directory.available_space().unwrap();
        assert!(directory.entries(1).unwrap().is_empty());
        assert!(!path.exists());
    }
}

#[test]
fn insufficient_or_unreadable_free_space_preserves_destination_and_never_preallocates() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/download-space");
    std::fs::create_dir_all(&base).unwrap();
    for query_failure in [false, true] {
        for existing in [false, true] {
            let scratch = crate::test_support::tempdir_in(&base).unwrap();
            let destination = scratch.path().join("output with spaces").join("keep.bin");
            std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
            if existing {
                std::fs::write(&destination, b"unrelated original").unwrap();
            }
            let state_directory = scratch.path().join("private state");
            let mut queries = 0;
            let ((), calls) = test_peer::with_peer(
                |_| panic!("disk-space refusal contacted the CDN"),
                |address| {
                    let api = Api::test_peer(address).unwrap();
                    let control = api.control.clone();
                    let info = FileInfo {
                        name: "keep.bin".into(),
                        size: 10 * 1024 * 1024,
                        raw_key: Zeroizing::new(vec![0; 32]),
                        url: format!("https://testserver.com:{}/cdn", address.port()),
                        handle: "FILEID".into(),
                        public_id: "FILEID".into(),
                        source: DownloadSource::Public,
                    };
                    let progress = Progress::new(false);
                    let item = progress.add(&info.name, info.size).unwrap();
                    let options = DownloadOptions {
                        workers: 1,
                        verify: false,
                        overwrite: true,
                        resume: true,
                        keep_state: true,
                        quota_wait: 0,
                        quota_attempts: 1,
                    };
                    let error = download_with_space(
                        api,
                        info,
                        &destination,
                        &state_directory,
                        &options,
                        &RateLimiter::new(0.0).unwrap(),
                        &progress,
                        item,
                        &control,
                        |directory| {
                            queries += 1;
                            let names = directory.entries(8).unwrap();
                            assert_eq!(names.len(), 1 + usize::from(existing));
                            assert!(
                                names
                                    .iter()
                                    .all(|entry| !entry.name.to_string_lossy().ends_with(".tmp"))
                            );
                            if query_failure {
                                Err(std::io::Error::new(
                                    std::io::ErrorKind::PermissionDenied,
                                    "synthetic space query failure",
                                )
                                .into())
                            } else {
                                Ok(1024)
                            }
                        },
                        OutputDirectory::open_file,
                    )
                    .unwrap_err();
                    if query_failure {
                        assert!(
                            matches!(error, Error::Io(error) if error.kind() == std::io::ErrorKind::PermissionDenied)
                        );
                    } else {
                        assert!(matches!(error, Error::Protocol(message)
                            if message == "Not enough free space for download: need 10485760 bytes, 1024 available"));
                    }
                },
            );
            assert_eq!(queries, 1);
            assert!(calls.is_empty());
            if existing {
                assert_eq!(std::fs::read(&destination).unwrap(), b"unrelated original");
            } else {
                assert!(!destination.exists());
            }
            assert!(std::fs::read_dir(&state_directory).unwrap().all(|entry| {
                entry
                    .unwrap()
                    .path()
                    .extension()
                    .is_some_and(|extension| extension == "lock")
            }));
            let directory = OutputDirectory::open(destination.parent().unwrap()).unwrap();
            assert_eq!(
                directory.entries(8).unwrap().len(),
                1 + usize::from(existing)
            );
            drop(directory);
            // Intentional persistent sidecar remains, but the actual failed download released its lock.
            let claim = Claim::acquire(&destination, true, |_| Ok(false)).unwrap();
            assert_eq!(claim.path, destination);
        }
    }
}
