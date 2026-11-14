#![allow(clippy::unwrap_used, clippy::expect_used)]

use megabasterd_cli::{
    platform::secure_files::OutputDirectory,
    transfers::{control::Control, upload_tree},
};
use std::fs;

#[test]
fn bounded_manifest_preserves_empty_directories_exact_names_and_sizes() {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/upload-tree");
    fs::create_dir_all(&base).unwrap();
    let scratch = private_tempfile::tempdir_in(&base).unwrap();
    let root = scratch.path().join("root with spaces");
    fs::create_dir_all(root.join("empty")).unwrap();
    fs::create_dir_all(root.join("sub")).unwrap();
    fs::write(root.join("sub/file  name.bin"), b"source bytes").unwrap();
    let manifest = upload_tree::walk(&root, &Control::new()).unwrap();
    assert_eq!(manifest.bytes, 12);
    assert_eq!(manifest.skipped, 0);
    assert_eq!(manifest.entries.len(), 3);
    assert!(
        manifest
            .entries
            .iter()
            .any(|entry| entry.directory && entry.relative == std::path::Path::new("empty"))
    );
    assert!(manifest.entries.iter().any(|entry| !entry.directory
        && entry.relative == std::path::Path::new("sub/file  name.bin")
        && entry.size == 12));
    let directory = OutputDirectory::open(&root).unwrap();
    assert!(directory.entries(1).is_err());
    assert_eq!(directory.entries(8).unwrap().len(), 2);
}

#[test]
fn manifest_never_follows_a_symlinked_file_or_directory() {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/upload-tree");
    fs::create_dir_all(&base).unwrap();
    let scratch = private_tempfile::tempdir_in(&base).unwrap();
    let root = scratch.path().join("source");
    let external = scratch.path().join("outside");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&external).unwrap();
    fs::write(external.join("private.bin"), b"not selected").unwrap();
    fs::write(root.join("real.txt"), b"real").unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&external, root.join("redirect")).unwrap();
        std::os::unix::fs::symlink(external.join("private.bin"), root.join("file.bin")).unwrap();
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::symlink_dir(&external, root.join("redirect"))
            .expect("Windows fixture requires symbolic-link privilege or Developer Mode");
        std::os::windows::fs::symlink_file(external.join("private.bin"), root.join("file.bin"))
            .expect("Windows fixture requires symbolic-link privilege or Developer Mode");
    }
    let manifest = upload_tree::walk(&root, &Control::new()).unwrap();
    assert_eq!(manifest.skipped, 2);
    assert_eq!(manifest.bytes, 4);
    assert_eq!(manifest.entries.len(), 1);
    assert_eq!(
        manifest.entries[0].relative,
        std::path::Path::new("real.txt")
    );
    assert!(!manifest.entries[0].directory);
    assert_eq!(manifest.entries[0].size, 4);
    assert_eq!(
        fs::read(external.join("private.bin")).unwrap(),
        b"not selected"
    );
}

#[path = "common/private_tempfile.rs"]
mod private_tempfile;
