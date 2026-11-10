//! Full held-file identity detects content, metadata and object changes without sampling.
#![allow(clippy::unwrap_used)]

use std::{
    ffi::OsStr,
    fs::FileTimes,
    io::{Seek, SeekFrom, Write},
    path::Path,
    time::Duration,
};

use megabasterd_cli::{
    error::Error,
    platform::secure_files::OutputDirectory,
    transfers::{control::Control, upload::source_hash},
};

fn scratch() -> tempfile::TempDir {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/upload-source-identity");
    std::fs::create_dir_all(&base).unwrap();
    tempfile::tempdir_in(base).unwrap()
}

#[test]
fn held_source_identity_detects_same_size_content_changes_with_original_mtime_restored() {
    let scratch = scratch();
    let directory = OutputDirectory::open(scratch.path()).unwrap();
    let mut file = directory.open_file(OsStr::new("source.bin"), true).unwrap();
    file.write_all(&vec![7; 1024 * 1024]).unwrap();
    file.sync_all().unwrap();
    let modified = file.metadata().unwrap().modified().unwrap();
    let control = Control::new();
    let original = source_hash(&mut file, &control).unwrap();
    assert_eq!(source_hash(&mut file, &control).unwrap(), original);
    for offset in [0, 300 * 1024, 1024 * 1024 - 1] {
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(&[8]).unwrap();
        file.sync_all().unwrap();
        file.set_times(FileTimes::new().set_modified(modified))
            .unwrap();
        assert_eq!(file.metadata().unwrap().modified().unwrap(), modified);
        let changed = source_hash(&mut file, &control).unwrap();
        let (before_identity, before_hash) = original.rsplit_once(':').unwrap();
        let (after_identity, after_hash) = changed.rsplit_once(':').unwrap();
        assert_eq!(
            before_identity, after_identity,
            "size, timestamp or native identity changed"
        );
        assert_ne!(
            before_hash, after_hash,
            "content change at {offset} was missed"
        );
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(&[7]).unwrap();
        file.sync_all().unwrap();
        file.set_times(FileTimes::new().set_modified(modified))
            .unwrap();
        assert_eq!(source_hash(&mut file, &control).unwrap(), original);
    }
    file.set_times(FileTimes::new().set_modified(modified + Duration::from_secs(2)))
        .unwrap();
    let changed = source_hash(&mut file, &control).unwrap();
    assert_ne!(changed, original, "metadata-only change was missed");
    assert_eq!(
        changed.rsplit_once(':').unwrap().1,
        original.rsplit_once(':').unwrap().1
    );

    let mut replacement = directory
        .open_file(OsStr::new("replacement.bin"), true)
        .unwrap();
    replacement.write_all(&vec![7; 1024 * 1024]).unwrap();
    replacement.sync_all().unwrap();
    replacement
        .set_times(FileTimes::new().set_modified(modified))
        .unwrap();
    let other = source_hash(&mut replacement, &control).unwrap();
    assert_ne!(
        other, original,
        "different live objects shared their source identity"
    );
    assert_eq!(
        other.rsplit_once(':').unwrap().1,
        original.rsplit_once(':').unwrap().1
    );
}

#[test]
fn source_hash_matches_the_independent_fixture_and_cancellation_remains_typed() {
    let scratch = scratch();
    let directory = OutputDirectory::open(scratch.path()).unwrap();
    let mut file = directory.open_file(OsStr::new("source.bin"), true).unwrap();
    let plaintext: Vec<u8> = (0..131089u32)
        .map(|index| ((13 * index + 7) % 256) as u8)
        .collect();
    file.write_all(&plaintext).unwrap();
    file.sync_all().unwrap();
    let identity = source_hash(&mut file, &Control::new()).unwrap();
    assert_eq!(
        identity.rsplit_once(':').unwrap().1,
        "a31213bc27f2b5e03d3e3591de6049e0832e93e1a28864a596bcfda869c93072"
    );
    let control = Control::new();
    control.cancel();
    let error = source_hash(&mut file, &control).unwrap_err();
    assert!(matches!(error, Error::Canceled));
    assert_eq!(error.exit_code(), 130);
    assert_eq!(
        std::fs::read(scratch.path().join("source.bin")).unwrap(),
        plaintext
    );
}
