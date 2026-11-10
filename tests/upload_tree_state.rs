#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{fs, path::Path};

use megabasterd_cli::{
    error::Error,
    storage::files::Store,
    transfers::{control::Control, upload_tree, upload_tree_state::Journal},
};
use serde_json::{Value, json};

fn scratch() -> tempfile::TempDir {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/upload-tree-state");
    fs::create_dir_all(&base).unwrap();
    tempfile::tempdir_in(base).unwrap()
}

#[test]
fn resumed_tree_reuses_confirmed_folders_and_the_same_file_operation() {
    let scratch = scratch();
    let source = scratch.path().join("source with spaces");
    fs::create_dir_all(source.join("empty child")).unwrap();
    let states = scratch.path().join("private states");
    let manifest = upload_tree::walk(&source, &Control::new()).unwrap();
    let mut journal =
        Journal::open(&states, &source, "account/target/name", None, &manifest).unwrap();
    assert!(matches!(
        Journal::open(&states, &source, "account/target/name", None, &manifest),
        Err(Error::Busy(_))
    ));
    let operation = journal.operation().to_owned();
    assert_eq!(
        journal
            .folder(Path::new(""), || Ok("root0001".into()))
            .unwrap(),
        "root0001"
    );
    assert_eq!(
        journal
            .folder(Path::new("empty child"), || Ok("child001".into()))
            .unwrap(),
        "child001"
    );
    drop(journal);
    let mut retry =
        Journal::open(&states, &source, "account/target/name", None, &manifest).unwrap();
    assert_eq!(retry.operation(), operation);
    assert_eq!(
        retry
            .folder(Path::new(""), || panic!("root must not be recreated"))
            .unwrap(),
        "root0001"
    );
    assert_eq!(
        retry
            .folder(Path::new("empty child"), || panic!(
                "child must not be recreated"
            ))
            .unwrap(),
        "child001"
    );
    retry.acknowledge().unwrap();
    let next = Journal::open(&states, &source, "account/target/name", None, &manifest).unwrap();
    assert_ne!(
        next.operation(),
        operation,
        "a completed deliberate new upload is independent"
    );
}

#[test]
fn uncertain_folder_mutation_survives_restart_without_a_second_attempt() {
    for canceled in [false, true] {
        let scratch = scratch();
        let source = scratch.path().join("source");
        fs::create_dir(&source).unwrap();
        let manifest = upload_tree::walk(&source, &Control::new()).unwrap();
        let states = scratch.path().join("states");
        let mut journal = Journal::open(&states, &source, "binding", None, &manifest).unwrap();
        let result = journal.folder(Path::new(""), || {
            if canceled {
                Err(Error::Canceled)
            } else {
                Err(Error::Timeout)
            }
        });
        if canceled {
            assert!(matches!(result, Err(Error::Canceled)));
        } else {
            assert!(matches!(result, Err(Error::AmbiguousMutation(_))));
        }
        assert!(matches!(
            journal.folder(Path::new(""), || panic!("unknown mutation replayed")),
            Err(Error::AmbiguousMutation(_))
        ));
        assert!(matches!(
            journal.acknowledge(),
            Err(Error::AmbiguousMutation(_))
        ));
        assert!(matches!(
            Journal::open(&states, &source, "binding", None, &manifest),
            Err(Error::AmbiguousMutation(_))
        ));
    }
}

#[test]
fn only_a_definitive_server_rejection_permits_folder_retry() {
    let scratch = scratch();
    let source = scratch.path().join("source");
    fs::create_dir(&source).unwrap();
    let manifest = upload_tree::walk(&source, &Control::new()).unwrap();
    let states = scratch.path().join("states");
    let mut journal = Journal::open(&states, &source, "binding", None, &manifest).unwrap();
    assert!(matches!(
        journal.folder(Path::new(""), || Err(Error::mega(-11))),
        Err(Error::Mega { code: -11, .. })
    ));
    drop(journal);
    let mut retry = Journal::open(&states, &source, "binding", None, &manifest).unwrap();
    assert_eq!(
        retry
            .folder(Path::new(""), || Ok("root0001".into()))
            .unwrap(),
        "root0001"
    );
    retry.acknowledge().unwrap();
}

#[test]
fn changed_binding_or_manifest_refuses_without_overwriting_saved_outcome() {
    let scratch = scratch();
    let source = scratch.path().join("source");
    fs::create_dir(&source).unwrap();
    let states = scratch.path().join("states");
    let manifest = upload_tree::walk(&source, &Control::new()).unwrap();
    drop(Journal::open(&states, &source, "binding", None, &manifest).unwrap());
    let path = fs::read_dir(&states)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .unwrap();
    let original = fs::read(&path).unwrap();
    assert!(matches!(
        Journal::open(
            &states,
            &source,
            "different account or target",
            None,
            &manifest
        ),
        Err(Error::Corrupt(_))
    ));
    assert_eq!(fs::read(&path).unwrap(), original);
    fs::write(source.join("new file"), b"new bytes").unwrap();
    let changed = upload_tree::walk(&source, &Control::new()).unwrap();
    assert!(matches!(
        Journal::open(&states, &source, "binding", None, &changed),
        Err(Error::Corrupt(_))
    ));
    assert_eq!(fs::read(&path).unwrap(), original);
    let locked = Store::new(&path).lock().unwrap();
    let mut future: Value = serde_json::from_slice(&original).unwrap();
    future["version"] = json!(999);
    let future = serde_json::to_vec(&future).unwrap();
    locked.write_bytes(&future).unwrap();
    drop(locked);
    assert!(matches!(
        Journal::open(&states, &source, "binding", None, &manifest),
        Err(Error::Corrupt(_))
    ));
    assert_eq!(fs::read(&path).unwrap(), future);
}

#[test]
fn completed_file_accounting_survives_restart_and_completion_retains_a_tombstone() {
    let scratch = scratch();
    let source = scratch.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("file.bin"), b"bytes").unwrap();
    let states = scratch.path().join("states");
    let manifest = upload_tree::walk(&source, &Control::new()).unwrap();
    let mut journal = Journal::open(&states, &source, "binding", None, &manifest).unwrap();
    journal
        .folder(Path::new(""), || Ok("root0001".into()))
        .unwrap();
    journal
        .file_finished(Path::new("file.bin"), "file0001")
        .unwrap();
    drop(journal);
    let mut retry = Journal::open(&states, &source, "binding", None, &manifest).unwrap();
    retry
        .file_finished(Path::new("file.bin"), "file0001")
        .unwrap();
    assert!(matches!(
        retry.file_finished(Path::new("file.bin"), "file0002"),
        Err(Error::Corrupt(_))
    ));
    assert!(matches!(
        retry.file_finished(Path::new("missing.bin"), "file0001"),
        Err(Error::Invalid(_))
    ));
    retry.acknowledge().unwrap();
    let tombstone = fs::read_dir(&states)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|path| path.extension().is_some_and(|ext| ext == "json"))
        .unwrap();
    let saved: Value = serde_json::from_slice(&fs::read(tombstone).unwrap()).unwrap();
    assert_eq!(
        saved["data"]["completed"], true,
        "completion must retain a durable tombstone, not unlink recovery evidence"
    );
    assert_eq!(saved["data"]["finalized_files"]["file.bin"], "file0001");
}

#[test]
fn unknown_paths_or_missing_parents_never_invoke_the_remote_adapter() {
    let scratch = scratch();
    let source = scratch.path().join("source");
    fs::create_dir_all(source.join("child/grandchild")).unwrap();
    let manifest = upload_tree::walk(&source, &Control::new()).unwrap();
    let mut journal = Journal::open(
        &scratch.path().join("states"),
        &source,
        "binding",
        None,
        &manifest,
    )
    .unwrap();
    for path in ["../outside", "unknown", "child", "child/grandchild"] {
        assert!(
            journal
                .folder(Path::new(path), || panic!(
                    "invalid folder must not contact API"
                ))
                .is_err()
        );
    }
    assert!(
        journal.acknowledge().is_err(),
        "incomplete parent set cannot be acknowledged"
    );
}
