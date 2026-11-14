//! Supported, owned, unregistered upload state restarts without reusing stale byte coverage.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::platform::secure_files::file_identity;
use crate::storage::transfer_state::TransferState;
use std::fs::{File, FileTimes, OpenOptions};

const SIZE: u64 = 131089;
const MATERIAL: &str = "000102030405060708090a0b0c0d0e0f0001020304050607";

fn seed(source: &Path, directory: &Path, vault: &Vault) -> (PathBuf, TransferState) {
    let canonical = std::fs::canonicalize(source).unwrap();
    let binding = serde_json::to_string(&json!([
        canonical.to_string_lossy(),
        "fixture@example.invalid",
        "testuser",
        "target",
        NAME,
        Option::<&str>::None
    ]))
    .unwrap();
    let id = hex::encode(Sha256::digest(binding.as_bytes()));
    let path = directory.join(format!("{id}.json"));
    let material = hex::decode(MATERIAL).unwrap();
    let mut state = TransferState::new("upload", &binding, &path, SIZE, &material[..16]).unwrap();
    state.source_identity = Some(
        crate::transfers::upload::source_hash(&mut File::open(source).unwrap(), &Control::new())
            .unwrap(),
    );
    state.upload_url = Some(SLOT.into());
    state.sealed_upload_key = Some(
        vault
            .seal(&material, format!("upload:{id}").as_bytes())
            .unwrap(),
    );
    state.completed.insert(
        0,
        hex::decode("1f7ec6ce08f27461f268bf02cfe09156")
            .unwrap()
            .try_into()
            .unwrap(),
    );
    (path, state)
}

#[derive(Clone, Copy, Debug)]
enum Restart {
    Changed,
    Replaced,
    MissingIdentity,
    SampledIdentity,
    Disabled,
}

#[test]
fn changed_replaced_or_unidentified_sources_and_disabled_resume_upload_every_byte_fresh() {
    for mode in [
        Restart::Changed,
        Restart::Replaced,
        Restart::MissingIdentity,
        Restart::SampledIdentity,
        Restart::Disabled,
    ] {
        let scratch = scratch();
        let source = source(scratch.path(), SIZE as usize);
        let directory = scratch.path().join("private restart state");
        let vault = Vault::new("synthetic restart passphrase");
        let (state_path, mut state) = seed(&source, &directory, &vault);
        let original = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&source)
            .unwrap();
        let original_id = file_identity(&original).unwrap();
        let modified = original.metadata().unwrap().modified().unwrap();
        let mut expected = std::fs::read(&source).unwrap();
        match mode {
            Restart::Changed => {
                expected[0] ^= 0xff;
                std::fs::write(&source, &expected).unwrap();
                original
                    .set_times(FileTimes::new().set_modified(modified))
                    .unwrap();
            }
            Restart::Replaced => {
                let replacement = scratch.path().join("replacement.bin");
                std::fs::write(&replacement, &expected).unwrap();
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&replacement)
                    .unwrap()
                    .set_times(FileTimes::new().set_modified(modified))
                    .unwrap();
                // Retain the old directory entry as well as its handle: Windows rejects zero links.
                std::fs::rename(&source, scratch.path().join("original-held.bin")).unwrap();
                std::fs::rename(replacement, &source).unwrap();
            }
            Restart::MissingIdentity => state.source_identity = None,
            Restart::SampledIdentity => {
                state.source_identity = Some("v1:sampled-identity-is-not-a-full-source-hash".into())
            }
            Restart::Disabled => (),
        }
        let current = crate::transfers::upload::source_hash(
            &mut File::open(&source).unwrap(),
            &Control::new(),
        )
        .unwrap();
        if matches!(mode, Restart::Changed | Restart::Replaced) {
            assert_ne!(state.source_identity.as_deref(), Some(current.as_str()));
            assert_eq!(
                std::fs::metadata(&source).unwrap().modified().unwrap(),
                modified
            );
        }
        // The old object stays open through replacement and upload: native IDs cannot be recycled.
        assert_eq!(file_identity(&original).unwrap(), original_id);
        let current_id = file_identity(&File::open(&source).unwrap()).unwrap();
        if matches!(mode, Restart::Replaced) {
            assert_ne!(current_id, original_id);
        } else {
            assert_eq!(current_id, original_id);
        }
        States::new(&state_path).save(&state).unwrap();
        let progress = Progress::new(false);
        let item = progress.add(NAME, SIZE).unwrap();
        let mut bodies = BTreeMap::new();
        let mut slots = 0;
        let (uploaded, calls) = test_peer::with_peer(
            |request| {
                if let Some(offset) = request.path.strip_prefix("/native-peer-upload/restarted/") {
                    let offset = offset.parse::<u64>().unwrap();
                    assert_eq!(request.body.len(), if offset == 0 { 131072 } else { 17 });
                    assert!(bodies.insert(offset, request.body.clone()).is_none());
                    return Some(Response {
                        status: 200,
                        headers: vec![],
                        body: if offset == 131072 {
                            TOKEN.as_bytes().to_vec()
                        } else {
                            vec![]
                        },
                    });
                }
                let value = command(request);
                Some(match value["a"].as_str().unwrap() {
                    "u" => {
                        slots += 1;
                        assert_eq!(slots, 1);
                        assert_eq!(value["s"], SIZE);
                        assert!(States::new(&state_path).load().unwrap().is_none());
                        api(json!({"p":"https://upload.mega.nz/native-peer-upload/restarted"}))
                    }
                    "p" => {
                        assert_eq!(bodies.keys().copied().collect::<Vec<_>>(), [0, 131072]);
                        let node = &value["n"][0];
                        assert_eq!(node["h"], TOKEN);
                        let raw = wire::aes_key_wrap_decrypt(
                            &wire::b64_url_decode(node["k"].as_str().unwrap()).unwrap(),
                            &MASTER,
                        )
                        .unwrap();
                        let key = keys::unpack_file_key(&wire::bytes_to_a32(&raw)).unwrap();
                        let mut plain = Vec::new();
                        for (&offset, body) in &bodies {
                            plain.extend(
                                wire::ctr_crypt_at_offset(
                                    key.aes_key.as_slice(),
                                    &key.nonce,
                                    offset,
                                    body,
                                )
                                .unwrap(),
                            );
                        }
                        assert_eq!(plain, expected, "stale bytes reused for {mode:?}");
                        let attrs = wire::decrypt_attributes(
                            &wire::b64_url_decode(node["a"].as_str().unwrap()).unwrap(),
                            key.aes_key.as_slice(),
                        )
                        .unwrap();
                        assert_eq!(attrs["n"], NAME);
                        api(json!({"f":[{"h":"AQIDBAUG"}]}))
                    }
                    _ => panic!("unexpected restart API action"),
                })
            },
            |address| {
                let mut cloud = cloud(address);
                let control = cloud.api.control.clone();
                upload(
                    &mut cloud,
                    &source,
                    "target",
                    None,
                    1,
                    &directory,
                    &vault,
                    !matches!(mode, Restart::Disabled),
                    None,
                    &RateLimiter::new(0.0).unwrap(),
                    &progress,
                    item,
                    &control,
                )
                .unwrap()
            },
        );
        assert_eq!((slots, calls.len()), (1, 4));
        assert_eq!(
            (uploaded.handle.as_str(), uploaded.size),
            ("AQIDBAUG", SIZE)
        );
        assert_eq!(
            progress.snapshot(item).unwrap().status,
            crate::terminal::progress::Status::Complete
        );
        uploaded.acknowledge().unwrap();
        assert!(!state_path.exists());
        assert_eq!(std::fs::read(&source).unwrap(), expected);
        drop(original);
    }
}

#[test]
fn confirmed_receipt_survives_disabled_resume_without_any_remote_replay() {
    let scratch = scratch();
    let source = source(scratch.path(), SIZE as usize);
    let directory = scratch.path().join("private confirmed state");
    let vault = Vault::new("synthetic receipt passphrase");
    let (path, mut state) = seed(&source, &directory, &vault);
    state.completed.insert(
        1,
        hex::decode("110e1a89f506e3e5d33167e2a932e544")
            .unwrap()
            .try_into()
            .unwrap(),
    );
    state.completion_token = Some(TOKEN.into());
    state.registration_started = true;
    state.registered_handle = Some("AQIDBAUG".into());
    state.upload_url = None;
    States::new(&path).save(&state).unwrap();
    let before = std::fs::read(&path).unwrap();
    let (uploaded, calls) = test_peer::with_peer(
        |_| panic!("confirmed receipt was replayed"),
        |address| {
            let mut cloud = cloud(address);
            let control = cloud.api.control.clone();
            let progress = Progress::new(false);
            let item = progress.add(NAME, SIZE).unwrap();
            upload(
                &mut cloud,
                &source,
                "target",
                None,
                1,
                &directory,
                &vault,
                false,
                None,
                &RateLimiter::new(0.0).unwrap(),
                &progress,
                item,
                &control,
            )
            .unwrap()
        },
    );
    assert!(calls.is_empty());
    assert_eq!(uploaded.handle, "AQIDBAUG");
    assert_eq!(std::fs::read(&path).unwrap(), before);
    drop(uploaded);
    // Source change must not turn a confirmed receipt into permission to create another node.
    let mut changed = std::fs::read(&source).unwrap();
    changed[0] ^= 0xff;
    std::fs::write(&source, changed).unwrap();
    let (error, calls) = test_peer::with_peer(
        |_| panic!("changed registered source contacted the peer"),
        |address| {
            let mut cloud = cloud(address);
            let control = cloud.api.control.clone();
            let progress = Progress::new(false);
            let item = progress.add(NAME, SIZE).unwrap();
            upload(
                &mut cloud,
                &source,
                "target",
                None,
                1,
                &directory,
                &vault,
                true,
                None,
                &RateLimiter::new(0.0).unwrap(),
                &progress,
                item,
                &control,
            )
            .err()
            .unwrap()
        },
    );
    assert!(matches!(error, Error::Corrupt(_)));
    assert!(calls.is_empty());
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn restart_never_discards_foreign_corrupt_keyless_or_uncertain_state_or_reuses_a_missing_slot() {
    use crate::storage::files::{STORE_VERSION, Store};

    let scratch = scratch();
    let source = source(scratch.path(), SIZE as usize);
    let directory = scratch.path().join("private refused state");
    let vault = Vault::new("synthetic refusal passphrase");
    let (path, state) = seed(&source, &directory, &vault);
    let mut variants = Vec::new();
    for field in [
        "kind",
        "source_hash",
        "destination",
        "sealed_upload_key",
        "key_hash",
        "upload_url",
    ] {
        let mut invalid = state.clone();
        match field {
            "kind" => invalid.kind = "download".into(),
            "source_hash" => invalid.source_hash = "a".repeat(64),
            "destination" => invalid.destination = "another-transfer.json".into(),
            "sealed_upload_key" => invalid.sealed_upload_key = None,
            "key_hash" => invalid.key_hash = "b".repeat(64),
            "upload_url" => invalid.upload_url = None,
            _ => unreachable!(),
        }
        variants.push((
            field,
            json!({"version":STORE_VERSION,"data":invalid}),
            false,
        ));
    }
    let mut uncertain = state.clone();
    uncertain.completion_token = Some(TOKEN.into());
    uncertain.registration_started = true;
    variants.push((
        "uncertain registration",
        json!({"version":STORE_VERSION,"data":uncertain}),
        true,
    ));
    variants.push((
        "future version",
        json!({"version":STORE_VERSION+1,"new_schema":{"preserve":true}}),
        false,
    ));
    variants.push((
        "invalid structure",
        json!({"version":STORE_VERSION,"data":{"missing":"fields"}}),
        false,
    ));
    let context = format!("upload:{}", path.file_stem().unwrap().to_str().unwrap());
    let material = hex::decode(MATERIAL).unwrap();
    assert_eq!(
        &*vault
            .open(
                state.sealed_upload_key.as_deref().unwrap(),
                context.as_bytes()
            )
            .unwrap(),
        &material
    );
    for (label, sealed) in [
        ("malformed key envelope", "not-base64!".to_owned()),
        (
            "empty key material",
            vault.seal(&[], context.as_bytes()).unwrap(),
        ),
        (
            "short key material",
            vault.seal(&material[..23], context.as_bytes()).unwrap(),
        ),
        (
            "long key material",
            vault.seal(&[0x5a; 25], context.as_bytes()).unwrap(),
        ),
        (
            "wrong key context",
            vault.seal(&material, b"upload:another-transfer").unwrap(),
        ),
    ] {
        let mut invalid = state.clone();
        invalid.sealed_upload_key = Some(sealed);
        variants.push((
            label,
            json!({"version":STORE_VERSION,"data":invalid}),
            false,
        ));
    }
    let source_bytes = std::fs::read(&source).unwrap();
    let (_, calls) = test_peer::with_peer(
        |_| panic!("refused upload state contacted the peer"),
        |address| {
            let mut cloud = cloud(address);
            let control = cloud.api.control.clone();
            let limiter = RateLimiter::new(0.0).unwrap();
            for (label, document, ambiguous) in variants {
                let bytes = serde_json::to_vec(&document).unwrap();
                Store::new(&path)
                    .lock()
                    .unwrap()
                    .write_bytes(&bytes)
                    .unwrap();
                let resume_modes: &[bool] = if label == "upload_url" {
                    &[true]
                } else {
                    &[false, true]
                };
                for &resume in resume_modes {
                    let progress = Progress::new(false);
                    let item = progress.add(NAME, SIZE).unwrap();
                    let error = upload(
                        &mut cloud, &source, "target", None, 1, &directory, &vault, resume, None,
                        &limiter, &progress, item, &control,
                    )
                    .err()
                    .unwrap();
                    if ambiguous {
                        assert!(
                            matches!(error, Error::AmbiguousMutation(_)),
                            "{label}: {error}"
                        );
                    } else if label == "wrong key context" {
                        assert!(matches!(error, Error::Auth(_)), "{label}: {error}");
                        assert_eq!(error.code(), "auth_failed");
                    } else {
                        if label == "future version" {
                            assert!(error.to_string().contains("format version 3"));
                        } else if matches!(
                            label,
                            "empty key material" | "short key material" | "long key material"
                        ) {
                            assert!(
                                error
                                    .to_string()
                                    .contains("Upload state key has invalid width")
                            );
                        }
                        assert!(matches!(error, Error::Corrupt(_)), "{label}: {error}");
                        assert_eq!(error.code(), "storage_corrupt");
                    }
                    assert_eq!(error.exit_code(), 1, "{label}");
                    assert_eq!(std::fs::read(&path).unwrap(), bytes, "{label}");
                    assert_eq!(std::fs::read(&source).unwrap(), source_bytes, "{label}");
                    drop(
                        Store::new(path.with_extension("lease"))
                            .with_timeout(std::time::Duration::ZERO)
                            .lock()
                            .unwrap(),
                    );
                }
            }
        },
    );
    assert!(calls.is_empty());
    let mut names = std::fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    names.sort();
    let basename = path.file_stem().unwrap().to_str().unwrap();
    assert_eq!(
        names,
        ["json", "json.lock", "lease.lock"]
            .map(|extension| std::ffi::OsString::from(format!("{basename}.{extension}")))
    );
}
