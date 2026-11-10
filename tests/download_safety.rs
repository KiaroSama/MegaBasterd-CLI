#![allow(clippy::unwrap_used)]
use std::{
    collections::BTreeMap,
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

use megabasterd_cli::{
    crypto::{chunks, keys},
    platform::secure_files::{OutputDirectory, file_identity},
    storage::transfer_state::TransferState,
    transfers::{claims::Claim, control::Control, verification::validate_completed},
};

#[test]
fn resume_rechecks_saved_chunk_bytes_before_suppressing_network_work() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/download-safety");
    std::fs::create_dir_all(&base).unwrap();
    let scratch = private_tempfile::tempdir_in(base).unwrap();
    let directory = OutputDirectory::ensure(scratch.path()).unwrap();
    let mut file = directory
        .open_file(std::ffi::OsStr::new("stage"), true)
        .unwrap();
    let plaintext = b"source-oracle independent plaintext";
    file.write_all(plaintext).unwrap();
    file.sync_all().unwrap();
    let key = keys::unpack_file_key(&[0; 8]).unwrap();
    let mac = chunks::chunk_mac(plaintext, key.aes_key.as_slice(), &key.nonce).unwrap();
    let mut completed = BTreeMap::from([(0, mac)]);
    assert_eq!(
        validate_completed(
            &mut file,
            plaintext.len() as u64,
            &key,
            &mut completed,
            &Control::new()
        )
        .unwrap(),
        plaintext.len() as u64
    );
    file.seek(SeekFrom::Start(4)).unwrap();
    file.write_all(b"!").unwrap();
    assert_eq!(
        validate_completed(
            &mut file,
            plaintext.len() as u64,
            &key,
            &mut completed,
            &Control::new()
        )
        .unwrap(),
        0
    );
    assert!(completed.is_empty());
}

#[test]
fn disk_verification_rereads_two_chunks_and_refuses_changed_or_truncated_bytes() {
    use megabasterd_cli::{crypto::wire, error::Error, transfers::verification::verify};

    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/transfers/vectors.json")).unwrap();
    let vector = &vectors["vectors"][2];
    assert_eq!(vector["size"], 131089);
    let key = keys::unpack_file_key(&wire::bytes_to_a32(
        &hex::decode(vector["raw_key"].as_str().unwrap()).unwrap(),
    ))
    .unwrap();
    let plaintext: Vec<u8> = (0..131089u32)
        .map(|index| ((13 * index + 7) % 256) as u8)
        .collect();
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/download-safety");
    std::fs::create_dir_all(&base).unwrap();
    let scratch = private_tempfile::tempdir_in(base).unwrap();
    let directory = OutputDirectory::open(scratch.path()).unwrap();
    let mut file = directory
        .open_file(std::ffi::OsStr::new("on-disk.bin"), true)
        .unwrap();
    file.write_all(&plaintext).unwrap();
    file.sync_all().unwrap();
    verify(&mut file, 131089, &key, &Control::new()).unwrap();

    file.seek(SeekFrom::Start(131080)).unwrap();
    file.write_all(&[plaintext[131080] ^ 1]).unwrap();
    file.sync_all().unwrap();
    assert!(matches!(
        verify(&mut file, 131089, &key, &Control::new()),
        Err(Error::Integrity(message))
            if message == "On-disk MEGA MAC does not match the public file key"
    ));
    file.seek(SeekFrom::Start(131080)).unwrap();
    let mut changed = [0];
    file.read_exact(&mut changed).unwrap();
    assert_eq!(changed, [plaintext[131080] ^ 1]);

    file.set_len(131088).unwrap();
    file.sync_all().unwrap();
    assert!(matches!(
        verify(&mut file, 131089, &key, &Control::new()),
        Err(Error::Integrity(message))
            if message == "Downloaded file size differs from metadata"
    ));
    assert_eq!(file.metadata().unwrap().len(), 131088);
    assert!(matches!(
        directory.open_read(std::ffi::OsStr::new("missing.bin")),
        Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound
    ));
}

#[test]
fn missing_or_wrong_width_nonce_is_refused_before_a_verification_key_can_be_constructed() {
    use megabasterd_cli::error::Error;

    let aes = [0x10; 16];
    let mac = [0x18191a1b, 0x1c1d1e1f];
    for size in [0, 1, 7, 9, 16] {
        let nonce = vec![0x11; size];
        let error = keys::pack_file_key(&aes, &nonce, &mac).unwrap_err();
        assert!(matches!(&error, Error::Invalid(_)));
        assert_eq!(error.exit_code(), 2);
        assert_eq!(
            error.to_string(),
            "Invalid input: File key requires a 16-byte AES key, 8-byte nonce and two MAC words"
        );
    }
    // Fixed source-oracle vector, not an expectation computed by the Rust implementation.
    let nonce = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];
    let packed = keys::pack_file_key(&aes, &nonce, &mac).unwrap();
    assert_eq!(
        packed,
        [
            0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617, 0x18191a1b,
            0x1c1d1e1f,
        ]
    );
    let decoded = keys::unpack_file_key(&packed).unwrap();
    assert_eq!(decoded.nonce, nonce);
    assert_eq!(decoded.aes_key.as_slice(), aes);
    assert_eq!(decoded.mac, mac);
}

#[test]
fn unrelated_destination_appearance_is_not_overwritten_at_publication() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/download-safety");
    std::fs::create_dir_all(&base).unwrap();
    let scratch = private_tempfile::tempdir_in(base).unwrap();
    let claim = Claim::acquire(&scratch.path().join("file.bin"), false, |_| Ok(false)).unwrap();
    let staging = claim.temporary_name().unwrap();
    let mut file = claim.directory.open_file(&staging, true).unwrap();
    file.write_all(b"verified replacement").unwrap();
    file.sync_all().unwrap();
    drop(file);
    std::fs::write(&claim.path, b"unrelated concurrent creation").unwrap();
    assert!(claim.publish(&staging, false).is_err());
    assert_eq!(
        std::fs::read(&claim.path).unwrap(),
        b"unrelated concurrent creation"
    );
    let mut retained = claim.directory.open_read(&staging).unwrap();
    let mut bytes = Vec::new();
    retained.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"verified replacement");
}

#[test]
fn resume_staging_identity_rejects_a_replaced_same_length_file() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/download-safety");
    std::fs::create_dir_all(&base).unwrap();
    let scratch = private_tempfile::tempdir_in(base).unwrap();
    let directory = OutputDirectory::ensure(scratch.path()).unwrap();
    let original = directory
        .open_file(std::ffi::OsStr::new("stage-a"), true)
        .unwrap();
    let replacement = directory
        .open_file(std::ffi::OsStr::new("stage-b"), true)
        .unwrap();
    original.set_len(32).unwrap();
    replacement.set_len(32).unwrap();
    assert_ne!(
        file_identity(&original).unwrap(),
        file_identity(&replacement).unwrap()
    );
    let mut state = TransferState::new(
        "download",
        "public:source",
        &scratch.path().join("final"),
        32,
        &[0; 32],
    )
    .unwrap();
    state.staging_name = Some("stage-a".into());
    state.staging_identity = Some(file_identity(&original).unwrap());
    assert!(state.validate().is_ok());
    state.staging_name = Some("../not-owned".into());
    assert!(state.validate().is_err());
}

#[path = "common/private_tempfile.rs"]
mod private_tempfile;
