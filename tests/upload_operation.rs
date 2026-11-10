#![allow(clippy::unwrap_used)]

use std::path::Path;

use megabasterd_cli::{error::Error, transfers::upload_operation};

#[test]
fn queued_operation_pins_account_and_target_across_retries_without_conflating_new_jobs() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/upload-operation");
    std::fs::create_dir_all(&root).unwrap();
    let scratch = tempfile::tempdir_in(root).unwrap();
    let source = scratch.path().join("file with spaces.bin");
    let first = upload_operation::bind(
        scratch.path(),
        Some("job-one"),
        &source,
        "account-one:target-one:original-name",
    )
    .unwrap();
    assert!(first.is_some());
    assert!(matches!(
        upload_operation::bind(
            scratch.path(),
            Some("job-one"),
            &source,
            "account-one:target-one:original-name"
        ),
        Err(Error::Busy(_))
    ));
    drop(first);
    let before: Vec<_> = std::fs::read_dir(scratch.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|e| e == "binding"))
        .map(|path| (path.clone(), std::fs::read(path).unwrap()))
        .collect();
    assert_eq!(before.len(), 1);
    for changed in [
        "account-two:target-one:original-name",
        "account-one:target-two:original-name",
        "account-one:target-one:different-name",
    ] {
        assert!(matches!(
            upload_operation::bind(scratch.path(), Some("job-one"), &source, changed),
            Err(Error::Corrupt(_))
        ));
        assert_eq!(std::fs::read(&before[0].0).unwrap(), before[0].1);
    }
    assert!(
        upload_operation::bind(
            scratch.path(),
            Some("job-one"),
            &source,
            "account-one:target-one:original-name"
        )
        .unwrap()
        .is_some()
    );
    assert!(
        upload_operation::bind(
            scratch.path(),
            Some("job-two"),
            &source,
            "account-two:target-two:new-name"
        )
        .unwrap()
        .is_some()
    );
    assert!(
        upload_operation::bind(scratch.path(), None, &source, "manual-new-upload")
            .unwrap()
            .is_none()
    );
}

#[test]
fn invalid_operation_identifiers_do_not_create_binding_files() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/upload-operation-invalid");
    std::fs::create_dir_all(&root).unwrap();
    let scratch = tempfile::tempdir_in(root).unwrap();
    for operation in ["", "job\ncontrol"] {
        assert!(
            upload_operation::bind(
                scratch.path(),
                Some(operation),
                Path::new("source"),
                "binding"
            )
            .is_err()
        );
    }
    assert_eq!(std::fs::read_dir(scratch.path()).unwrap().count(), 0);
}
