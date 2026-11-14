//! Saved identity, staged bytes and error cleanup enter the actual download pipeline.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::{
    platform::secure_files::{OutputDirectory, file_identity},
    storage::{files::Store, transfer_state::TransferState},
    transfers::claims::Claim,
};

#[test]
fn resume_refuses_foreign_keyless_or_short_staging_without_contact_and_preserves_evidence() {
    let fixture = Fixture::new(17);
    let vectors: Value =
        serde_json::from_str(include_str!("../../tests/fixtures/transfers/vectors.json")).unwrap();
    let mac: [u8; 16] = hex::decode(vectors["vectors"][1]["chunks"][0]["mac"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    for verify in [false, true] {
        for variant in [
            "source",
            "destination",
            "size",
            "key",
            "keyless",
            "short",
            "missing",
            "matching",
        ] {
            let scratch = scratch();
            let destination = scratch.path().join("resume.bin");
            let state_directory = scratch.path().join("private state");
            let saved_path = state_path(&state_directory, &destination);
            let plaintext: Vec<u8> = (0..17)
                .map(|index| ((13 * index + 7) % 256) as u8)
                .collect();
            let staged = if variant == "short" {
                &plaintext[..16]
            } else {
                &plaintext[..]
            };
            let directory = OutputDirectory::open(scratch.path()).unwrap();
            let staging = std::ffi::OsStr::new(".mb-resume.tmp");
            let mut file = directory.open_file(staging, true).unwrap();
            file.write_all(staged).unwrap();
            file.sync_all().unwrap();
            let identity = file_identity(&file).unwrap();
            drop(file);
            let ((), calls) = test_peer::with_peer(
                |_| panic!("complete or refused resume contacted the CDN"),
                |address| {
                    let info = fixture.info(address);
                    let mut state = TransferState::new(
                        "download",
                        &info.source_identity().unwrap(),
                        &destination,
                        fixture.size,
                        &fixture.key,
                    )
                    .unwrap();
                    state.staging_name = Some(staging.to_string_lossy().into_owned());
                    state.staging_identity = Some(identity);
                    state.completed.insert(0, mac);
                    match variant {
                        "source" => state.source_hash = "00".repeat(32),
                        "destination" => {
                            state.destination = scratch
                                .path()
                                .join("other.bin")
                                .to_string_lossy()
                                .into_owned()
                        }
                        "size" => state.size = 34,
                        "key" => state.key_hash = "00".repeat(32),
                        "keyless" => state.key_hash.clear(),
                        "short" | "missing" | "matching" => (),
                        _ => unreachable!(),
                    }
                    if variant == "missing" {
                        state.revision = 1;
                        States::new(&saved_path).save(&state).unwrap();
                        std::fs::remove_file(scratch.path().join(staging)).unwrap();
                        assert!(!scratch.path().join(staging).exists());
                        assert!(!destination.exists());
                    } else {
                        // The envelope writer permits a deliberately invalid payload for load validation.
                        Store::new(&saved_path)
                            .lock()
                            .unwrap()
                            .save(&state)
                            .unwrap();
                    }
                    let before = std::fs::read(&saved_path).unwrap();
                    let state_inventory = std::fs::read_dir(&state_directory)
                        .unwrap()
                        .map(|entry| entry.unwrap().file_name())
                        .collect::<std::collections::BTreeSet<_>>();
                    let result = run(
                        &fixture,
                        address,
                        &destination,
                        &state_directory,
                        &Control::new(),
                        verify,
                    );
                    if variant == "matching" {
                        assert_eq!(result.unwrap(), destination);
                        fixture.assert_output(&destination);
                        assert!(States::new(&saved_path).load().unwrap().is_none());
                        assert!(!scratch.path().join(staging).exists());
                    } else {
                        let error = result.unwrap_err();
                        if variant == "short" {
                            assert!(matches!(error, Error::Integrity(message)
                                if message == "Resume staging file size changed"));
                        } else if variant == "missing" {
                            assert!(matches!(error, Error::Io(cause)
                                if cause.kind() == std::io::ErrorKind::NotFound));
                        } else {
                            assert!(matches!(error, Error::Corrupt(_)), "{variant}: {error}");
                        }
                        assert!(!destination.exists());
                        assert_eq!(std::fs::read(&saved_path).unwrap(), before);
                        if variant == "missing" {
                            assert!(!scratch.path().join(staging).exists());
                            let saved = States::new(&saved_path).load().unwrap().unwrap();
                            assert_eq!(saved.revision, 1);
                            assert_eq!(saved.completed, state.completed);
                            assert_eq!(
                                std::fs::read_dir(&state_directory)
                                    .unwrap()
                                    .map(|entry| entry.unwrap().file_name())
                                    .collect::<std::collections::BTreeSet<_>>(),
                                state_inventory
                            );
                            let mut names = directory
                                .entries(4)
                                .unwrap()
                                .into_iter()
                                .map(|entry| entry.name.to_string_lossy().into_owned())
                                .collect::<Vec<_>>();
                            names.sort();
                            assert_eq!(names, ["private state", "resume.bin.mbclaim"]);
                        } else {
                            assert_eq!(
                                std::fs::read(scratch.path().join(staging)).unwrap(),
                                staged
                            );
                        }
                    }
                    let claim = Claim::acquire(&destination, true, |_| Ok(true)).unwrap();
                    assert_eq!(claim.path, destination);
                },
            );
            assert!(calls.is_empty());
        }
    }
}

#[test]
fn invalid_or_future_state_refuses_before_staging_or_network_and_preserves_evidence() {
    let fixture = Fixture::new(17);
    for verify in [false, true] {
        for variant in [
            "future",
            "future_shape",
            "malformed",
            "null",
            "missing_size",
            "unknown_payload",
            "unknown_envelope",
        ] {
            let scratch = scratch();
            let destination = scratch.path().join("future.bin");
            let state_directory = scratch.path().join("private state");
            let saved_path = state_path(&state_directory, &destination);
            let ((), calls) = test_peer::with_peer(
                |_| panic!("future-format resume contacted the CDN"),
                |address| {
                    let future = variant.starts_with("future");
                    let data = match variant {
                        "future_shape" | "missing_size" | "unknown_payload"
                        | "unknown_envelope" => {
                            let mut data = serde_json::to_value(
                                TransferState::new(
                                    "download",
                                    &fixture.info(address).source_identity().unwrap(),
                                    &destination,
                                    fixture.size,
                                    &fixture.key,
                                )
                                .unwrap(),
                            )
                            .unwrap();
                            if variant == "missing_size" {
                                assert!(data.as_object_mut().unwrap().remove("size").is_some());
                            } else if variant == "unknown_payload" {
                                data["future_field"] = serde_json::json!({"nested": 1});
                            }
                            data
                        }
                        "null" => Value::Null,
                        _ => serde_json::json!({"new_schema": {"nested": true}}),
                    };
                    let original = if variant == "malformed" {
                        b"{{{ broken".to_vec()
                    } else {
                        let mut document = serde_json::json!({
                            "version": crate::storage::files::STORE_VERSION + u64::from(future),
                            "data": data,
                        });
                        if variant == "unknown_envelope" {
                            document["future_field"] = serde_json::json!({"nested": 1});
                        }
                        serde_json::to_vec(&document).unwrap()
                    };
                    Store::new(&saved_path)
                        .lock()
                        .unwrap()
                        .write_bytes(&original)
                        .unwrap();
                    let error = run(
                        &fixture,
                        address,
                        &destination,
                        &state_directory,
                        &Control::new(),
                        verify,
                    )
                    .unwrap_err();
                    assert!(
                        matches!(error, Error::Corrupt(ref message)
                        if message == match variant {
                            "future" | "future_shape" => "Saved format version 3 is newer than supported version 2; preserve the file",
                            "malformed" => "Saved file is not valid UTF-8 JSON",
                            "unknown_envelope" => "Saved envelope has unsupported fields",
                            _ => "Saved data has an invalid structure",
                        }),
                        "{variant}: {error}"
                    );
                    assert_eq!(error.code(), "storage_corrupt");
                    assert_eq!(error.exit_code(), 1);
                    assert_eq!(std::fs::read(&saved_path).unwrap(), original);
                    let mut saved_names = std::fs::read_dir(&state_directory)
                        .unwrap()
                        .map(|entry| entry.unwrap().file_name())
                        .collect::<Vec<_>>();
                    saved_names.sort();
                    let mut lock_name = saved_path.file_name().unwrap().to_owned();
                    lock_name.push(".lock");
                    let mut expected_names =
                        vec![saved_path.file_name().unwrap().to_owned(), lock_name];
                    expected_names.sort();
                    assert_eq!(saved_names, expected_names);
                    assert!(!destination.exists());
                    let directory = OutputDirectory::open(scratch.path()).unwrap();
                    let mut names: Vec<_> = directory
                        .entries(4)
                        .unwrap()
                        .into_iter()
                        .map(|entry| entry.name.to_string_lossy().into_owned())
                        .collect();
                    names.sort();
                    assert_eq!(names, ["future.bin.mbclaim", "private state"]);
                    let claim = Claim::acquire(&destination, true, |_| Ok(true)).unwrap();
                    assert_eq!(claim.path, destination);
                },
            );
            assert!(calls.is_empty());
        }
    }
}

#[test]
fn failed_disk_mac_without_state_retention_removes_only_owned_staging_and_state() {
    let fixture = Fixture::new(17);
    let scratch = scratch();
    let destination = scratch.path().join("damaged.bin");
    let state_directory = scratch.path().join("private state");
    let unrelated = scratch.path().join("keep.bin");
    std::fs::write(&unrelated, b"unrelated original").unwrap();
    let mut staging_name = None;
    let ((), calls) = test_peer::with_peer(
        |request| {
            let saved = States::new(state_path(&state_directory, &destination))
                .load()
                .unwrap()
                .unwrap();
            staging_name = saved.staging_name;
            let mut response = fixture.reply(request);
            response.body[0] ^= 1;
            Some(response)
        },
        |address| {
            let api = Api::test_peer(address).unwrap();
            let control = api.control.clone();
            let progress = Progress::new(false);
            let item = progress.add("fixture", fixture.size).unwrap();
            let mut options = options(true);
            options.keep_state = false;
            let error = download(
                api,
                fixture.info(address),
                &destination,
                &state_directory,
                &options,
                &RateLimiter::new(0.0).unwrap(),
                &progress,
                item,
                &control,
            )
            .unwrap_err();
            assert!(matches!(error, Error::Integrity(message)
                if message == "On-disk MEGA MAC does not match the public file key"));
            assert!(!destination.exists());
            assert!(
                States::new(state_path(&state_directory, &destination))
                    .load()
                    .unwrap()
                    .is_none()
            );
            assert_eq!(std::fs::read(&unrelated).unwrap(), b"unrelated original");
            let directory = OutputDirectory::open(scratch.path()).unwrap();
            let mut names: Vec<_> = directory
                .entries(8)
                .unwrap()
                .into_iter()
                .map(|entry| entry.name.to_string_lossy().into_owned())
                .collect();
            names.sort();
            assert_eq!(names, ["damaged.bin.mbclaim", "keep.bin", "private state"]);
            let claim = Claim::acquire(&destination, false, |_| Ok(false)).unwrap();
            assert_eq!(claim.path, destination);
        },
    );
    assert_eq!(calls.len(), 1);
    assert!(!scratch.path().join(staging_name.unwrap()).exists());
}
