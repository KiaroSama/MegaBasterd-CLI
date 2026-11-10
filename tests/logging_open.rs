#![allow(clippy::unwrap_used)]

use megabasterd_cli::platform::secure_files::{OutputDirectory, PrivateDirectory, file_identity};
use std::{
    ffi::OsStr,
    fs,
    io::{Read, Write},
};

#[cfg(windows)]
#[path = "common/windows_log_acl.rs"]
mod windows_log_acl;

fn scratch() -> tempfile::TempDir {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/logging-open");
    fs::create_dir_all(&base).unwrap();
    tempfile::tempdir_in(base).unwrap()
}

#[test]
fn native_creation_keeps_the_file_private_even_when_its_parent_grants_another_principal_access() {
    let scratch = scratch();
    let path = scratch.path().join("inheriting parent");
    drop(PrivateDirectory::ensure(&path).unwrap());
    #[cfg(unix)]
    struct RestorePermissions(std::path::PathBuf);
    #[cfg(unix)]
    impl Drop for RestorePermissions {
        fn drop(&mut self) {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
        }
    }
    #[cfg(unix)]
    let _restore = {
        use std::os::unix::fs::PermissionsExt;
        let restore = RestorePermissions(path.clone());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).unwrap();
        restore
    };
    #[cfg(windows)]
    let parent_acl = {
        windows_log_acl::snapshot(&path).assert_owner_only();
        let acl = windows_log_acl::grant_local_service_read(&path, true);
        fs::write(
            path.join("inherited-control.txt"),
            b"nonsecret inheritance control",
        )
        .unwrap();
        assert!(
            windows_log_acl::snapshot(&path.join("inherited-control.txt"))
                .grants_local_service_read()
        );
        acl
    };
    let directory = OutputDirectory::open(&path).unwrap();
    let name = OsStr::new("cli.log");
    let mut file = directory.open_file(name, true).unwrap();
    let identity = file_identity(&file).unwrap();
    assert_eq!(file.metadata().unwrap().len(), 0);
    #[cfg(windows)]
    windows_log_acl::snapshot(&path.join(name)).assert_owner_only();
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let metadata = file.metadata().unwrap();
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        // SAFETY: geteuid has no memory or lifetime preconditions.
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
    }
    file.write_all(b"private from creation\n").unwrap();
    file.sync_all().unwrap();
    assert!(directory.open_file(name, true).is_err());
    assert_eq!(file_identity(&file).unwrap(), identity);
    assert_eq!(
        fs::read(path.join(name)).unwrap(),
        b"private from creation\n"
    );
    #[cfg(windows)]
    {
        windows_log_acl::snapshot(&path.join(name)).assert_owner_only();
        assert_eq!(windows_log_acl::snapshot(&path), parent_acl);
        assert_eq!(fs::read_dir(&path).unwrap().count(), 2);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
            0o777
        );
        assert_eq!(fs::read_dir(&path).unwrap().count(), 1);
    }
}

#[test]
fn shared_private_open_is_exclusive_verified_and_writes_the_same_retained_regular_handle() {
    let scratch = scratch();
    let path = scratch.path().join("private");
    let directory = PrivateDirectory::ensure(&path).unwrap();
    let name = OsStr::new("cli.log");
    let mut file = directory.open_private(name, true).unwrap();
    directory.verify_private(&file).unwrap();
    let identity = file_identity(&file).unwrap();
    #[cfg(windows)]
    let original_acl = {
        let acl = windows_log_acl::snapshot(&path.join(name));
        acl.assert_owner_only();
        acl
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let metadata = file.metadata().unwrap();
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        // SAFETY: geteuid has no memory or lifetime preconditions.
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
    }
    file.write_all(b"first-line\n").unwrap();
    file.flush().unwrap();
    assert!(directory.open_private(name, true).is_err());
    file.write_all(b"second-line\n").unwrap();
    file.sync_all().unwrap();
    directory.verify_private(&file).unwrap();
    #[cfg(windows)]
    assert_eq!(windows_log_acl::snapshot(&path.join(name)), original_acl);
    let mut same = directory.open_private(name, false).unwrap();
    assert_eq!(file_identity(&same).unwrap(), identity);
    let mut bytes = Vec::new();
    same.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"first-line\nsecond-line\n");
    drop(same);
    drop(file);
    assert_eq!(
        fs::read(path.join(name)).unwrap(),
        b"first-line\nsecond-line\n"
    );
    let entries = fs::read_dir(&path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    assert_eq!(entries, [name.to_owned()]);
}

#[test]
fn each_of_five_appends_keeps_owner_private_access_identity_and_the_original_first_line() {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    let scratch = scratch();
    let path = scratch.path().join("private");
    let directory = PrivateDirectory::ensure(&path).unwrap();
    let name = OsStr::new("launcher.log");
    let log = path.join(name);
    let mut file = directory.open_private(name, true).unwrap();
    directory.verify_private(&file).unwrap();
    let identity = file_identity(&file).unwrap();
    #[cfg(windows)]
    let original_acl = windows_log_acl::snapshot(&log);
    file.write_all(b"first\n").unwrap();
    file.flush().unwrap();
    directory.verify_private(&file).unwrap();
    #[cfg(unix)]
    assert_eq!(
        fs::metadata(&log).unwrap().permissions().mode() & 0o7777,
        0o600
    );
    #[cfg(windows)]
    assert_eq!(windows_log_acl::snapshot(&log), original_acl);
    for index in 0..5 {
        directory.verify_private(&file).unwrap();
        writeln!(file, "line {index}").unwrap();
        file.flush().unwrap();
        directory.verify_private(&file).unwrap();
        assert_eq!(file_identity(&file).unwrap(), identity);
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&log).unwrap().permissions().mode() & 0o7777,
            0o600
        );
        #[cfg(windows)]
        assert_eq!(windows_log_acl::snapshot(&log), original_acl);
    }
    directory.verify_private(&file).unwrap();
    drop(file);
    assert_eq!(
        fs::read(&log).unwrap(),
        b"first\nline 0\nline 1\nline 2\nline 3\nline 4\n"
    );
}

#[test]
fn a_preexisting_unsafe_log_is_refused_without_content_identity_or_permission_repair() {
    let scratch = scratch();
    let path = scratch.path().join("private");
    let directory = PrivateDirectory::ensure(&path).unwrap();
    let name = OsStr::new("planted.log");
    let log = path.join(name);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        fs::write(&log, b"planted\n").unwrap();
        fs::set_permissions(&log, fs::Permissions::from_mode(0o666)).unwrap();
        let before = fs::symlink_metadata(&log).unwrap();
        assert!(directory.open_private(name, false).is_err());
        assert!(directory.open_private(name, true).is_err());
        assert_eq!(fs::read(&log).unwrap(), b"planted\n");
        let after = fs::symlink_metadata(&log).unwrap();
        assert_eq!(before.ino(), after.ino());
        assert_eq!(after.permissions().mode() & 0o7777, 0o666);
    }
    #[cfg(windows)]
    {
        let mut original = directory.open_private(name, true).unwrap();
        original.write_all(b"planted\n").unwrap();
        original.sync_all().unwrap();
        let identity = file_identity(&original).unwrap();
        drop(original);
        let unsafe_acl = windows_log_acl::grant_local_service_read(&log, false);
        let refusal = directory.open_private(name, false).unwrap_err();
        assert!(matches!(
            refusal,
            megabasterd_cli::error::Error::Protocol(ref message)
                if message == "Private native object grants another principal access"
        ));
        assert!(directory.open_private(name, true).is_err());
        let retained = fs::File::open(&log).unwrap();
        assert_eq!(file_identity(&retained).unwrap(), identity);
        assert_eq!(fs::read(&log).unwrap(), b"planted\n");
        assert!(!fs::symlink_metadata(&log).unwrap().file_type().is_symlink());
        assert_eq!(windows_log_acl::snapshot(&log), unsafe_acl);
        assert_eq!(fs::read_dir(&path).unwrap().count(), 1);
    }
}

#[test]
fn shared_private_open_refuses_a_planted_symlink_and_keeps_the_victim_and_alias() {
    let scratch = scratch();
    let path = scratch.path().join("private");
    let directory = PrivateDirectory::ensure(&path).unwrap();
    let victim = scratch.path().join("victim");
    fs::write(&victim, b"victim contents\n").unwrap();
    let alias = path.join("cli.log");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&victim, &alias).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&victim, &alias).unwrap_or_else(|error| {
        panic!("Windows fixture requires symlink privilege or Developer Mode: {error}")
    });
    for create_new in [true, false] {
        assert!(
            directory
                .open_private(OsStr::new("cli.log"), create_new)
                .is_err()
        );
    }
    assert!(
        fs::symlink_metadata(&alias)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read(victim).unwrap(), b"victim contents\n");
}

#[test]
fn shared_private_open_refuses_directories_and_fifos_without_blocking_or_replacing_them() {
    let scratch = scratch();
    let path = scratch.path().join("private");
    let directory = PrivateDirectory::ensure(&path).unwrap();
    fs::create_dir(path.join("directory")).unwrap();
    #[cfg(unix)]
    let names = {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};
        let fifo = CString::new(path.join("fifo").as_os_str().as_bytes()).unwrap();
        // SAFETY: terminated fixture path and private mode; creates no process or external service.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        ["directory", "fifo"]
    };
    #[cfg(windows)]
    let names = ["directory"];
    for name in names {
        for create_new in [true, false] {
            assert!(
                directory
                    .open_private(OsStr::new(name), create_new)
                    .is_err()
            );
        }
        assert!(!fs::symlink_metadata(path.join(name)).unwrap().is_file());
    }
}
