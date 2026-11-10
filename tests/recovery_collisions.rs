//! Content-addressed recovery does not overwrite occupants or lose a distinct corruption episode.
#![allow(clippy::unwrap_used)]

use megabasterd_cli::{
    error::Error,
    storage::{config_store::ConfigStore, files::Store},
};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fs, path::Path};

#[test]
fn config_backup_creation_failure_is_reported_without_claiming_a_copy_or_changing_the_original() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/recovery-collisions");
    fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    let path = scratch.path().join("private/config.json");
    let original = b"{\"episode\": \"A\",,,";
    Store::new(&path)
        .lock()
        .unwrap()
        .write_bytes(original)
        .unwrap();
    let backup_name = format!(
        "config.json.corrupt-{}",
        hex::encode(Sha256::digest(original))
    );
    let obstacle = path.parent().unwrap().join(&backup_name);
    fs::create_dir(&obstacle).unwrap();
    let sentinel = obstacle.join("unrelated.bin");
    fs::write(&sentinel, b"unrelated occupant remains").unwrap();
    let inventory = || {
        fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<BTreeSet<_>>()
    };
    let before = inventory();
    let store = ConfigStore::new(&path);
    for _ in 0..2 {
        let error = store.load().err().unwrap();
        assert!(matches!(&error, Error::Corrupt(message)
            if message == "Saved file is not valid UTF-8 JSON. A private recovery copy could not be written or verified; original bytes remain untouched. Inspect or explicitly recover configuration before continuing"));
        assert!(!error.to_string().contains(&backup_name));
        assert_eq!(fs::read(&path).unwrap(), original);
        assert_eq!(inventory(), before);
    }
    let error = store.recover(false).err().unwrap();
    assert!(matches!(&error, Error::Corrupt(message)
        if message.contains("copy could not be written or verified")
            && message.contains("requires explicit --reset")));
    assert!(!error.to_string().contains(&backup_name));
    assert!(matches!(
        store.recover(true),
        Err(Error::Io(_) | Error::Protocol(_))
    ));
    // A directory occupant fails closed, not as an unrelated regular file eligible for a suffix.
    let locked = Store::new(&path).lock().unwrap();
    assert!(matches!(
        locked.preserve(),
        Err(Error::Io(_) | Error::Protocol(_))
    ));
    assert_eq!(locked.bytes().unwrap().unwrap().as_slice(), original);
    assert_eq!(inventory(), before);
    assert!(obstacle.is_dir());
    assert_eq!(fs::read(&sentinel).unwrap(), b"unrelated occupant remains");
}

#[test]
fn recovery_collision_uses_one_private_alternative_and_repeated_reads_adopt_its_exact_bytes() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/recovery-collisions");
    fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    let path = scratch.path().join("private/queue.json");
    let original = b"{ first corruption episode ,,,";
    let different = b"{ second corruption episode ,,,";
    let locked = Store::new(&path).lock().unwrap();
    locked.write_bytes(original).unwrap();
    let first = locked.preserve().unwrap();
    let occupied = path.parent().unwrap().join(&first);
    // A pre-existing private file with unrelated bytes squats the base hash name.
    Store::new(&occupied)
        .lock()
        .unwrap()
        .write_bytes(b"unrelated recovery content")
        .unwrap();
    let alternative = locked.preserve().unwrap();
    assert_ne!(first, alternative);
    assert_eq!(fs::read(&occupied).unwrap(), b"unrelated recovery content");
    assert_eq!(
        fs::read(path.parent().unwrap().join(&alternative)).unwrap(),
        original
    );
    let before_repeats = fs::read_dir(path.parent().unwrap()).unwrap().count();
    for _ in 0..3 {
        assert_eq!(locked.preserve().unwrap(), alternative);
        assert_eq!(
            fs::read_dir(path.parent().unwrap()).unwrap().count(),
            before_repeats
        );
    }
    locked.write_bytes(different).unwrap();
    let second = locked.preserve().unwrap();
    assert_ne!(second, alternative);
    assert_eq!(
        fs::read(path.parent().unwrap().join(second)).unwrap(),
        different
    );
    assert_eq!(fs::read(&path).unwrap(), different);
    assert_eq!(
        fs::read(path.parent().unwrap().join(alternative)).unwrap(),
        original
    );
    // Exhausting the bounded namespace reports failure without claiming or deleting a copy.
    let mut current = locked.preserve().unwrap();
    for attempt in 0..32 {
        fs::write(
            path.parent().unwrap().join(&current),
            b"unrelated occupied name",
        )
        .unwrap();
        if attempt != 31 {
            current = locked.preserve().unwrap();
        }
    }
    let before = fs::read_dir(path.parent().unwrap()).unwrap().count();
    let error = locked.preserve().unwrap_err();
    assert!(error.to_string().contains("names are occupied"));
    assert_eq!(fs::read(&path).unwrap(), different);
    assert_eq!(
        fs::read_dir(path.parent().unwrap()).unwrap().count(),
        before
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for entry in fs::read_dir(path.parent().unwrap()).unwrap() {
            let entry = entry.unwrap();
            assert_eq!(
                entry.metadata().unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
    assert!(!fs::read_dir(path.parent().unwrap()).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")
    }));
}
