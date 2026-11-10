//! Resume open failures precede new coverage through the actual retained-staging pipeline.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::platform::secure_files::OutputDirectory;
use crate::protocol::{metadata::DownloadSource, test_peer};

#[test]
fn resume_open_failures_preserve_committed_coverage_and_bytes_before_any_snapshot_or_network() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/download-open");
    std::fs::create_dir_all(&base).unwrap();
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/fixtures/transfers/vectors.json")).unwrap();
    let vector = vectors["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vector| vector["size"] == 17)
        .unwrap();
    let key = hex::decode(vector["raw_key"].as_str().unwrap()).unwrap();
    let mac: [u8; 16] = hex::decode(vector["chunks"][0]["mac"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let plaintext: Vec<u8> = (0..17)
        .map(|index| ((13 * index + 7) % 256) as u8)
        .collect();
    for verify in [false, true] {
        for failure in ["permission", "io", "descriptors", "success"] {
            let scratch = tempfile::tempdir_in(&base).unwrap();
            let destination = scratch.path().join("movie.mkv");
            let directory = OutputDirectory::open(scratch.path()).unwrap();
            let staging = std::ffi::OsStr::new(".mb-resume.tmp");
            let mut file = directory.open_file(staging, true).unwrap();
            file.write_all(&plaintext).unwrap();
            file.sync_all().unwrap();
            let identity = file_identity(&file).unwrap();
            drop(file);
            let state_directory = scratch.path().join("private state");
            let saved_path = state_path(&state_directory, &destination);
            let mut opens = 0;
            let ((), calls) = test_peer::with_peer(
                |_| panic!("complete or refused resume contacted the CDN"),
                |address| {
                    let info = FileInfo {
                        name: "movie.mkv".into(),
                        size: 17,
                        raw_key: Zeroizing::new(key.clone()),
                        url: format!("https://testserver.com:{}/cdn", address.port()),
                        handle: "fixture".into(),
                        public_id: "fixture".into(),
                        source: DownloadSource::Public,
                    };
                    let mut state = TransferState::new(
                        "download",
                        &info.source_identity().unwrap(),
                        &destination,
                        17,
                        &key,
                    )
                    .unwrap();
                    state.staging_name = Some(staging.to_string_lossy().into_owned());
                    state.staging_identity = Some(identity.clone());
                    state.completed.insert(0, mac);
                    state.revision = 1;
                    let states = States::new(&saved_path);
                    states.save(&state).unwrap();
                    let before = std::fs::read(&saved_path).unwrap();
                    let inventory = || {
                        std::fs::read_dir(&state_directory)
                            .unwrap()
                            .map(|entry| entry.unwrap().file_name())
                            .collect::<std::collections::BTreeSet<_>>()
                    };
                    let names = inventory();
                    let api = Api::test_peer(address).unwrap();
                    let control = api.control.clone();
                    let progress = Progress::new(false);
                    let item = progress.add("resume", 17).unwrap();
                    let configured = DownloadOptions {
                        workers: 1,
                        verify,
                        overwrite: false,
                        resume: true,
                        keep_state: true,
                        quota_wait: 0,
                        quota_attempts: 1,
                    };
                    let exhausted = if cfg!(windows) { 4 } else { 24 };
                    let result = download_with_space(
                        api,
                        info,
                        &destination,
                        &state_directory,
                        &configured,
                        &RateLimiter::new(0.0).unwrap(),
                        &progress,
                        item,
                        &control,
                        |_| panic!("resume queried fresh-download capacity"),
                        |anchored, name, create| {
                            opens += 1;
                            assert_eq!(name, staging);
                            assert!(!create);
                            assert_eq!(std::fs::read(&saved_path).unwrap(), before);
                            match failure {
                                "permission" => Err(std::io::Error::new(
                                    std::io::ErrorKind::PermissionDenied,
                                    "controlled staging permission refusal",
                                )
                                .into()),
                                "io" => Err(std::io::Error::new(
                                    std::io::ErrorKind::InputOutputError,
                                    "controlled staging I/O refusal",
                                )
                                .into()),
                                "descriptors" => {
                                    Err(std::io::Error::from_raw_os_error(exhausted).into())
                                }
                                "success" => anchored.open_file(name, create),
                                _ => unreachable!(),
                            }
                        },
                    );
                    if failure == "success" {
                        assert_eq!(result.unwrap(), destination);
                        assert_eq!(std::fs::read(&destination).unwrap(), plaintext);
                        assert!(states.load().unwrap().is_none());
                        assert!(!scratch.path().join(staging).exists());
                        assert_eq!(progress.snapshot(item).unwrap().completed, 17);
                    } else {
                        let error = result.unwrap_err();
                        assert_eq!(error.exit_code(), 1);
                        assert_eq!(error.code(), "io_error");
                        match error {
                            Error::Io(cause) => match failure {
                                "permission" => {
                                    assert_eq!(cause.kind(), std::io::ErrorKind::PermissionDenied)
                                }
                                "io" => {
                                    assert_eq!(cause.kind(), std::io::ErrorKind::InputOutputError)
                                }
                                "descriptors" => assert_eq!(cause.raw_os_error(), Some(exhausted)),
                                _ => unreachable!(),
                            },
                            other => panic!("staging open failure changed type: {other}"),
                        }
                        assert_eq!(std::fs::read(&saved_path).unwrap(), before);
                        let saved = states.load().unwrap().unwrap();
                        assert_eq!(saved.revision, 1);
                        assert_eq!(saved.completed, state.completed);
                        assert_eq!(inventory(), names);
                        assert_eq!(
                            std::fs::read(scratch.path().join(staging)).unwrap(),
                            plaintext
                        );
                        assert!(!destination.exists());
                        assert_eq!(progress.snapshot(item).unwrap().completed, 0);
                        let mut output_names = directory
                            .entries(4)
                            .unwrap()
                            .into_iter()
                            .map(|entry| entry.name.to_string_lossy().into_owned())
                            .collect::<Vec<_>>();
                        output_names.sort();
                        assert_eq!(
                            output_names,
                            [".mb-resume.tmp", "movie.mkv.mbclaim", "private state"]
                        );
                    }
                    let claim = Claim::acquire(&destination, true, |_| Ok(true)).unwrap();
                    assert_eq!(claim.path, destination);
                },
            );
            assert_eq!(opens, 1);
            assert!(calls.is_empty());
        }
    }
}
