// SPDX-License-Identifier: GPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
use megabasterd_cli::platform::secure_files::{
    DirectorySync, OutputDirectory, PrivateDirectory, file_identity,
};
use std::{
    ffi::OsStr,
    fs,
    io::{Read, Write},
    path::PathBuf,
};

fn fixture() -> (private_tempfile::TempDir, PrivateDirectory, PathBuf) {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(".ci-work")
        .join("private-file-tests");
    fs::create_dir_all(&base).unwrap();
    let scratch = private_tempfile::Builder::new()
        .prefix("native-")
        .tempdir_in(base)
        .unwrap();
    let private = scratch.path().join("private space");
    let directory = PrivateDirectory::ensure(&private).unwrap();
    (scratch, directory, private)
}

#[test]
fn private_file_is_created_exclusively_and_existing_contents_are_not_truncated() {
    let (_scratch, directory, _) = fixture();
    let name = OsStr::new("credentials.fixture");
    let mut file = directory.open_private(name, true).unwrap();
    file.write_all(b"synthetic non-secret fixture").unwrap();
    file.sync_all().unwrap();
    drop(file);
    assert!(directory.open_private(name, true).is_err());
    let mut reopened = directory.open_private(name, false).unwrap();
    let mut text = String::new();
    reopened.read_to_string(&mut text).unwrap();
    assert_eq!(text, "synthetic non-secret fixture");
    let another = directory.open_private(name, false).unwrap();
    assert_eq!(
        file_identity(&reopened).unwrap(),
        file_identity(&another).unwrap()
    );
    let different = directory
        .open_private(OsStr::new("different"), true)
        .unwrap();
    assert_ne!(
        file_identity(&reopened).unwrap(),
        file_identity(&different).unwrap()
    );
    drop(another);
    drop(different);
    drop(reopened);
    for invalid in [
        "",
        "..",
        ".",
        "../escape",
        "sub/file",
        "stream:secret",
        "x\\y",
    ] {
        assert!(directory.open_private(OsStr::new(invalid), true).is_err());
    }
}

#[test]
fn replacement_and_owned_cleanup_use_the_retained_private_anchor() {
    let (_scratch, directory, private) = fixture();
    for (name, contents) in [
        ("old", b"old data".as_slice()),
        ("stage", b"new data".as_slice()),
    ] {
        let mut file = directory.open_private(OsStr::new(name), true).unwrap();
        file.write_all(contents).unwrap();
        file.sync_all().unwrap();
    }
    directory
        .replace(OsStr::new("stage"), OsStr::new("old"))
        .unwrap();
    let mut text = String::new();
    directory
        .open_private(OsStr::new("old"), false)
        .unwrap()
        .read_to_string(&mut text)
        .unwrap();
    assert_eq!(text, "new data");
    assert!(!private.join("stage").exists());
    assert!(
        directory
            .replace(OsStr::new("old"), OsStr::new("old"))
            .is_err()
    );
    let sync = directory.sync().unwrap();
    #[cfg(windows)]
    assert_eq!(sync, DirectorySync::Unsupported);
    #[cfg(unix)]
    assert!(matches!(
        sync,
        DirectorySync::Synced | DirectorySync::Unsupported
    ));
    directory.remove(OsStr::new("old")).unwrap();
    assert!(!private.join("old").exists());
}

#[cfg(unix)]
#[test]
fn unix_private_modes_are_verified_and_unsafe_existing_objects_are_preserved() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let (_scratch, directory, private) = fixture();
    assert_eq!(fs::metadata(&private).unwrap().mode() & 0o7777, 0o700);
    let file = directory
        .open_private(OsStr::new("owner-file"), true)
        .unwrap();
    assert_eq!(file.metadata().unwrap().mode() & 0o7777, 0o600);
    // SAFETY: geteuid has no pointer or allocation preconditions.
    assert_eq!(file.metadata().unwrap().uid(), unsafe { libc::geteuid() });
    drop(file);
    fs::write(private.join("broad"), b"preserve this fixture").unwrap();
    fs::set_permissions(private.join("broad"), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(directory.open_private(OsStr::new("broad"), false).is_err());
    assert!(directory.remove(OsStr::new("broad")).is_err());
    assert!(
        directory
            .replace(OsStr::new("owner-file"), OsStr::new("broad"))
            .is_err()
    );
    assert_eq!(
        fs::read(private.join("broad")).unwrap(),
        b"preserve this fixture"
    );
    fs::hard_link(private.join("owner-file"), private.join("hardlink")).unwrap();
    assert!(
        directory
            .open_private(OsStr::new("owner-file"), false)
            .is_err()
    );
    assert!(directory.remove(OsStr::new("hardlink")).is_err());
    let shared = private.parent().unwrap().join("shared");
    fs::create_dir(&shared).unwrap();
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(PrivateDirectory::ensure(&shared).is_err());
    assert_eq!(fs::metadata(&shared).unwrap().mode() & 0o7777, 0o755);
}

#[cfg(unix)]
#[test]
fn unix_rejects_symlink_components_and_operations_remain_anchored_after_rename() {
    use std::os::unix::fs::symlink;
    let (scratch, directory, private) = fixture();
    let outside = scratch.path().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("valuable"), b"preserve").unwrap();
    symlink(&outside, private.join("directory-link")).unwrap();
    assert!(PrivateDirectory::ensure(&private.join("directory-link").join("new")).is_err());
    assert!(!outside.join("new").exists());
    symlink(outside.join("valuable"), private.join("file-link")).unwrap();
    assert!(
        directory
            .open_private(OsStr::new("file-link"), false)
            .is_err()
    );
    assert!(directory.remove(OsStr::new("file-link")).is_err());
    assert_eq!(fs::read(outside.join("valuable")).unwrap(), b"preserve");
    let moved = scratch.path().join("moved");
    fs::rename(&private, &moved).unwrap();
    symlink(&outside, &private).unwrap();
    let mut file = directory
        .open_private(OsStr::new("anchored"), true)
        .unwrap();
    file.write_all(b"same directory descriptor").unwrap();
    drop(file);
    assert_eq!(
        fs::read(moved.join("anchored")).unwrap(),
        b"same directory descriptor"
    );
    assert!(!outside.join("anchored").exists());
    directory.remove(OsStr::new("anchored")).unwrap();
}

#[cfg(windows)]
#[test]
fn windows_hardlinks_and_held_directory_replacement_are_refused() {
    let (scratch, directory, private) = fixture();
    let file = directory
        .open_private(OsStr::new("original"), true)
        .unwrap();
    drop(file);
    fs::hard_link(private.join("original"), private.join("alias")).unwrap();
    assert!(
        directory
            .open_private(OsStr::new("original"), false)
            .is_err()
    );
    assert!(directory.remove(OsStr::new("alias")).is_err());
    assert!(fs::rename(&private, scratch.path().join("moved")).is_err());
    drop(directory);
    assert!(fs::rename(&private, scratch.path().join("moved")).is_ok());
}

#[cfg(windows)]
#[test]
fn windows_explicit_foreign_acl_is_rejected_without_repairing_or_truncating() {
    use std::{
        os::windows::{
            ffi::OsStrExt,
            io::{FromRawHandle, OwnedHandle},
        },
        ptr,
    };
    use windows_sys::Win32::{
        Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE, LocalFree},
        Security::{
            Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
            SECURITY_ATTRIBUTES,
        },
        Storage::FileSystem::{
            CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE,
        },
    };
    let (_scratch, directory, private) = fixture();
    let path = private.join("unsafe-acl");
    let name: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // Synthetic ACL intentionally grants Everyone access; no credential or operator data.
    let sddl: Vec<u16> = "D:P(A;;FA;;;WD)".encode_utf16().chain(Some(0)).collect();
    let mut descriptor = ptr::null_mut();
    // SAFETY: valid terminated SDDL and output descriptor pointer.
    assert_ne!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                ptr::null_mut(),
            )
        },
        0
    );
    let attrs = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    // SAFETY: terminated path, valid descriptor during creation, exclusive non-truncating create.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &attrs,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };
    // SAFETY: descriptor was allocated by the converter and is no longer needed after creation.
    unsafe {
        LocalFree(descriptor);
    }
    assert_ne!(handle, INVALID_HANDLE_VALUE);
    // SAFETY: successful native create transfers one owned handle to File.
    let mut file = std::fs::File::from(unsafe { OwnedHandle::from_raw_handle(handle) });
    file.write_all(b"preserved unsafe fixture").unwrap();
    drop(file);
    assert!(
        directory
            .open_private(OsStr::new("unsafe-acl"), false)
            .is_err()
    );
    assert!(directory.remove(OsStr::new("unsafe-acl")).is_err());
    assert_eq!(fs::read(&path).unwrap(), b"preserved unsafe fixture");
}

#[test]
fn owned_cleanup_preserves_a_different_object_and_removes_only_the_expected_identity() {
    let (scratch, private_anchor, _) = fixture();
    let output = scratch.path().join("owned cleanup");
    let directory = OutputDirectory::ensure(&output).unwrap();
    let mut original = directory.open_file(OsStr::new("original"), true).unwrap();
    original.write_all(b"original owned fixture").unwrap();
    let expected = file_identity(&original).unwrap();
    let mut replacement = directory
        .open_file(OsStr::new("replacement"), true)
        .unwrap();
    replacement
        .write_all(b"preserve replacement fixture")
        .unwrap();
    let actual = file_identity(&replacement).unwrap();
    assert_ne!(expected, actual);
    drop(replacement);
    // Original handle remains live, preventing its ID from being recycled.
    assert!(
        directory
            .remove_owned(OsStr::new("replacement"), &expected)
            .is_err()
    );
    assert_eq!(
        fs::read(output.join("replacement")).unwrap(),
        b"preserve replacement fixture"
    );
    assert!(
        directory
            .remove_owned(OsStr::new("replacement"), "")
            .is_err()
    );
    directory
        .remove_owned(OsStr::new("replacement"), &actual)
        .unwrap();
    assert!(!output.join("replacement").exists());
    assert_eq!(
        fs::read(output.join("original")).unwrap(),
        b"original owned fixture"
    );
    drop(original);
    drop(directory);
    drop(private_anchor);
}

#[test]
fn no_overwrite_publication_preserves_a_destination_that_appeared_after_claim() {
    let (scratch, private_anchor, _) = fixture();
    let output = scratch.path().join("race output");
    let directory = OutputDirectory::ensure(&output).unwrap();
    let mut stage = directory.open_file(OsStr::new("stage"), true).unwrap();
    stage.write_all(b"verified staging bytes").unwrap();
    drop(stage);
    // Models a competing destination created after the caller's claim/existence decision.
    let mut competitor = directory.open_file(OsStr::new("final"), true).unwrap();
    competitor.write_all(b"keep competing bytes").unwrap();
    drop(competitor);
    assert!(
        directory
            .publish(OsStr::new("stage"), OsStr::new("final"), false)
            .is_err()
    );
    assert_eq!(
        fs::read(output.join("stage")).unwrap(),
        b"verified staging bytes"
    );
    assert_eq!(
        fs::read(output.join("final")).unwrap(),
        b"keep competing bytes"
    );
    directory
        .publish(OsStr::new("stage"), OsStr::new("new-final"), false)
        .unwrap();
    assert_eq!(
        fs::read(output.join("new-final")).unwrap(),
        b"verified staging bytes"
    );
    assert!(!output.join("stage").exists());
    #[cfg(windows)]
    assert!(
        directory
            .publish(OsStr::new("new-final"), OsStr::new("NEW-FINAL"), true)
            .is_err()
    );
    assert!(
        directory
            .publish(OsStr::new("final"), OsStr::new("final"), false)
            .is_err()
    );
    drop(directory);
    drop(private_anchor);
}

#[test]
fn ordinary_output_directory_and_readonly_source_do_not_require_private_permissions() {
    let (scratch, private_anchor, _) = fixture();
    let output = scratch.path().join("ordinary output");
    fs::create_dir(&output).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&output, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let anchor = OutputDirectory::open(&output).unwrap();
    let mut file = anchor.open_file(OsStr::new("source"), true).unwrap();
    file.write_all(b"read only source").unwrap();
    drop(file);
    let mut existing = anchor.open_file(OsStr::new("source"), false).unwrap();
    let mut original = String::new();
    existing.read_to_string(&mut original).unwrap();
    assert_eq!(original, "read only source");
    drop(existing);
    fs::write(output.join("inherited"), b"ordinary existing input").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(output.join("inherited"), fs::Permissions::from_mode(0o644)).unwrap();
    }
    let mut ordinary = anchor.open_read(OsStr::new("inherited")).unwrap();
    let mut original = String::new();
    ordinary.read_to_string(&mut original).unwrap();
    assert_eq!(original, "ordinary existing input");
    drop(ordinary);
    let mut permissions = fs::metadata(output.join("source")).unwrap().permissions();
    permissions.set_readonly(true);
    fs::set_permissions(output.join("source"), permissions).unwrap();
    let mut read = anchor.open_read(OsStr::new("source")).unwrap();
    let mut contents = String::new();
    read.read_to_string(&mut contents).unwrap();
    assert_eq!(contents, "read only source");
    drop(read);
    assert!(anchor.open_file(OsStr::new("source"), true).is_err());
    let mut stage = anchor.open_file(OsStr::new("stage"), true).unwrap();
    stage.write_all(b"new output").unwrap();
    drop(stage);
    anchor
        .replace(OsStr::new("stage"), OsStr::new("finished"))
        .unwrap();
    assert_eq!(fs::read(output.join("finished")).unwrap(), b"new output");
    fs::hard_link(output.join("finished"), output.join("alias")).unwrap();
    assert!(anchor.open_read(OsStr::new("alias")).is_err());
    assert!(anchor.remove(OsStr::new("alias")).is_err());
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(fs::metadata(&output).unwrap().mode() & 0o7777, 0o755);
    }
    drop(anchor);
    drop(private_anchor);
    #[cfg(windows)]
    {
        let mut permissions = fs::metadata(output.join("source")).unwrap().permissions();
        permissions.set_readonly(false);
        fs::set_permissions(output.join("source"), permissions).unwrap();
    }
}

#[test]
fn output_anchor_accepts_real_children_and_refuses_parent_or_sibling_paths() {
    let (scratch, private_anchor, _) = fixture();
    let output = scratch.path().join("out");
    fs::create_dir_all(output.join("a")).unwrap();
    for (name, contents) in [
        ("evil.txt", b"outside file".as_slice()),
        ("out-evil/valuable", b"sibling prefix".as_slice()),
        ("output-evil/valuable", b"longer sibling prefix".as_slice()),
    ] {
        let path = scratch.path().join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }
    let directory = OutputDirectory::open(&output).unwrap();
    let same_root = OutputDirectory::open(&output).unwrap();
    let child = directory.child(OsStr::new("a")).unwrap();
    let mut file = child.open_file(OsStr::new("b.txt"), true).unwrap();
    file.write_all(b"contained bytes").unwrap();
    drop(file);
    let mut actual = Vec::new();
    same_root
        .child(OsStr::new("a"))
        .unwrap()
        .open_read(OsStr::new("b.txt"))
        .unwrap()
        .read_to_end(&mut actual)
        .unwrap();
    assert_eq!(actual, b"contained bytes");
    for invalid in [
        "../evil.txt",
        "../out-evil",
        "../output-evil",
        "..",
        "sub/../../evil.txt",
    ] {
        for error in [
            directory.child(OsStr::new(invalid)).err().unwrap(),
            directory.open_read(OsStr::new(invalid)).err().unwrap(),
            directory
                .open_file(OsStr::new(invalid), true)
                .err()
                .unwrap(),
        ] {
            assert!(matches!(&error, megabasterd_cli::error::Error::Invalid(_)));
            assert_eq!(error.code(), "invalid_input");
            assert_eq!(error.exit_code(), 2);
            assert!(error.to_string().contains("one normal path component"));
        }
    }
    assert_eq!(
        fs::read(scratch.path().join("evil.txt")).unwrap(),
        b"outside file"
    );
    assert_eq!(
        fs::read(scratch.path().join("out-evil/valuable")).unwrap(),
        b"sibling prefix"
    );
    assert_eq!(
        fs::read(scratch.path().join("output-evil/valuable")).unwrap(),
        b"longer sibling prefix"
    );
    assert_eq!(fs::read_dir(&output).unwrap().count(), 1);
    assert_eq!(fs::read_dir(output.join("a")).unwrap().count(), 1);
    assert_eq!(fs::read_dir(scratch.path()).unwrap().count(), 5);
    drop(child);
    drop(same_root);
    drop(directory);
    drop(private_anchor);
}

#[test]
fn output_aliases_are_refused_without_following_targets_or_redirecting_the_anchor() {
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
    #[cfg(windows)]
    use std::os::windows::fs::{symlink_dir, symlink_file};

    let (scratch, private_anchor, _) = fixture();
    #[cfg(unix)]
    assert!(OutputDirectory::open(std::path::Path::new("/")).is_ok());
    let output = scratch.path().join("output");
    let directory = OutputDirectory::ensure(&output).unwrap();
    let outside = scratch.path().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("valuable"), b"do not follow").unwrap();
    #[cfg(unix)]
    symlink(&outside, output.join("dir-alias")).unwrap();
    #[cfg(windows)]
    symlink_dir(&outside, output.join("dir-alias"))
        .expect("Windows reparse fixture requires symbolic-link privilege or Developer Mode");
    assert!(OutputDirectory::ensure(&output.join("dir-alias").join("child")).is_err());
    assert!(directory.child(OsStr::new("dir-alias")).is_err());
    assert!(!outside.join("child").exists());
    #[cfg(unix)]
    symlink(outside.join("valuable"), output.join("file-alias")).unwrap();
    #[cfg(windows)]
    symlink_file(outside.join("valuable"), output.join("file-alias"))
        .expect("Windows reparse fixture requires symbolic-link privilege or Developer Mode");
    assert!(directory.open_read(OsStr::new("file-alias")).is_err());
    assert!(
        directory
            .open_file(OsStr::new("file-alias"), false)
            .is_err()
    );
    assert!(directory.remove(OsStr::new("file-alias")).is_err());
    #[cfg(unix)]
    {
        let moved = scratch.path().join("moved");
        fs::rename(&output, &moved).unwrap();
        symlink(&outside, &output).unwrap();
        let mut stage = directory.open_file(OsStr::new("stage"), true).unwrap();
        stage.write_all(b"anchored publication").unwrap();
        drop(stage);
        directory
            .publish(OsStr::new("stage"), OsStr::new("final"), false)
            .unwrap();
        assert_eq!(
            fs::read(moved.join("final")).unwrap(),
            b"anchored publication"
        );
        assert!(!outside.join("final").exists());
    }
    assert_eq!(
        fs::read(outside.join("valuable")).unwrap(),
        b"do not follow"
    );
    drop(directory);
    drop(private_anchor);
}

#[path = "common/private_tempfile.rs"]
mod private_tempfile;
