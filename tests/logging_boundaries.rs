#![allow(clippy::unwrap_used)]

use megabasterd_cli::terminal::{logging::Logger, output::Output};
use serde_json::json;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);
impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut output = self.0.lock().unwrap();
        if bytes.len() > 4096usize.saturating_sub(output.len()) {
            return Err(io::Error::other("Fixture output bound"));
        }
        output.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn scratch() -> private_tempfile::TempDir {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/logging-boundaries");
    std::fs::create_dir_all(&base).unwrap();
    private_tempfile::tempdir_in(base).unwrap()
}

#[cfg(windows)]
#[path = "common/windows_log_acl.rs"]
mod windows_log_acl;

#[test]
fn held_log_handle_permission_drift_is_refused_before_the_next_byte_and_warns_only_once() {
    let scratch = scratch();
    let logs = scratch.path().join("private");
    let logger = Arc::new(Logger::configured(&logs, 0, 0).unwrap());
    let path = logs.join(logger.name());
    logger
        .write("INFO", "CONTROL", "safe initial record", &json!({}))
        .unwrap();
    let before = std::fs::read(&path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o666
        );
    }
    #[cfg(windows)]
    let unsafe_acl = windows_log_acl::grant_local_service_read(&path, false);
    let refusal = logger
        .write(
            "ERROR",
            "DRIFT",
            "must not write private payload",
            &json!({}),
        )
        .unwrap_err();
    #[cfg(windows)]
    assert!(matches!(
        refusal,
        megabasterd_cli::error::Error::Protocol(ref message)
            if message == "Private native object grants another principal access"
    ));
    #[cfg(not(windows))]
    let _ = refusal;
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(
        logger
            .write("ERROR", "DRIFT", "must stay disabled", &json!({}))
            .is_err()
    );
    let stderr = Capture::default();
    let output = Output::with_writers(false, false, Vec::new(), stderr.clone());
    for _ in 0..5 {
        output.logging_warning(&logger).unwrap();
    }
    let warning = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
    assert_eq!(warning, "[WARNING] Private runtime log write failed.\n");
    #[cfg(windows)]
    assert_eq!(windows_log_acl::snapshot(&path), unsafe_acl);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o666,
            "production must refuse, never silently repair this fixture"
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

#[test]
fn an_extra_hardlink_is_refused_on_the_retained_log_handle_without_reopening_either_name() {
    let scratch = scratch();
    let logs = scratch.path().join("private");
    let logger = Logger::configured(&logs, 0, 0).unwrap();
    let path = logs.join(logger.name());
    let before = std::fs::read(&path).unwrap();
    let alias = logs.join("alias");
    std::fs::hard_link(&path, &alias).unwrap();
    assert!(
        logger
            .write("ERROR", "LINK", "do not append", &json!({}))
            .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(std::fs::read(&alias).unwrap(), before);
    assert!(alias.exists() && path.exists());
}

#[test]
fn a_planted_rotation_symlink_preserves_victim_alias_and_primary_and_disables_the_writer() {
    let scratch = scratch();
    let logs = scratch.path().join("private");
    let logger = Logger::configured(&logs, 512, 2).unwrap();
    let path = logs.join(logger.name());
    let before = std::fs::read(&path).unwrap();
    let victim = scratch.path().join("victim");
    std::fs::write(&victim, b"preserve victim bytes\n").unwrap();
    let alias = logs.join(format!("{}.1", logger.name().to_string_lossy()));
    #[cfg(unix)]
    std::os::unix::fs::symlink(&victim, &alias).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&victim, &alias).unwrap_or_else(|error| {
        panic!("Windows fixture requires symlink privilege or Developer Mode: {error}")
    });
    for message in ["x".repeat(600), "must remain disabled".to_owned()] {
        assert!(
            logger
                .write("ERROR", "ROTATE", &message, &json!({}))
                .is_err()
        );
    }
    assert_eq!(std::fs::read(&victim).unwrap(), b"preserve victim bytes\n");
    assert!(
        std::fs::symlink_metadata(&alias)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn primary_name_replacement_after_a_good_write_never_authorizes_a_different_object() {
    use megabasterd_cli::platform::secure_files::file_identity;
    use std::io::Read;

    let variants: &[&str] = if cfg!(windows) {
        &["deny-delete"]
    } else {
        &["file", "symlink", "directory"]
    };
    for variant in variants {
        let scratch = scratch();
        let logs = scratch.path().join("user@example.com-SENTINEL-PATH");
        let logger = Arc::new(Logger::configured(&logs, 0, 0).unwrap());
        let path = logs.join(logger.name());
        logger
            .write("INFO", "CONTROL", "FIRST-LINE", &json!({}))
            .unwrap();
        let before = std::fs::read(&path).unwrap();
        assert!(std::str::from_utf8(&before).unwrap().contains("FIRST-LINE"));
        let mut retained = std::fs::File::open(&path).unwrap();
        let identity = file_identity(&retained).unwrap();
        let stdout = Capture::default();
        let stderr = Capture::default();
        let output = Output::with_writers(false, false, stdout.clone(), stderr.clone());
        output.attach_logger(logger.clone()).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let victim = scratch.path().join("victim");
            std::fs::write(&victim, b"victim content\n").unwrap();
            std::fs::remove_file(&path).unwrap();
            match *variant {
                "file" => {
                    std::fs::write(&path, b"PLANTED").unwrap();
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))
                        .unwrap();
                }
                "symlink" => std::os::unix::fs::symlink(&victim, &path).unwrap(),
                "directory" => {
                    std::fs::create_dir(&path).unwrap();
                    std::fs::write(path.join("keep.txt"), b"keep").unwrap();
                }
                _ => unreachable!(),
            }
            for message in ["SECOND-LINE", "must stay disabled"] {
                assert!(
                    logger
                        .write("ERROR", "REPLACEMENT", message, &json!({}))
                        .is_err()
                );
            }
            assert!(logger.finish(1).is_err());
            for _ in 0..2 {
                output.message("WARNING", "still alive").unwrap();
                output.logging_warning(&logger).unwrap();
            }
            assert_eq!(
                String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap(),
                "[WARNING] Private runtime log write failed.\n[WARNING] still alive\n[WARNING] still alive\n"
            );
            let mut old_bytes = Vec::new();
            retained.read_to_end(&mut old_bytes).unwrap();
            assert_eq!(
                old_bytes, before,
                "unlinked retained object received a later byte"
            );
            assert_eq!(std::fs::read(&victim).unwrap(), b"victim content\n");
            match *variant {
                "file" => {
                    assert_eq!(std::fs::read(&path).unwrap(), b"PLANTED");
                    assert_eq!(
                        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                        0o666
                    );
                }
                "symlink" => assert_eq!(std::fs::read_link(&path).unwrap(), victim),
                "directory" => {
                    assert!(path.is_dir());
                    assert_eq!(std::fs::read(path.join("keep.txt")).unwrap(), b"keep");
                    assert_eq!(std::fs::read_dir(&path).unwrap().count(), 1);
                }
                _ => unreachable!(),
            }
            assert_eq!(std::fs::read_dir(&logs).unwrap().count(), 1);
        }
        #[cfg(windows)]
        {
            let _ = variant;
            let moved = logs.join("moved.log");
            for error in [
                std::fs::rename(&path, &moved).unwrap_err(),
                std::fs::remove_file(&path).unwrap_err(),
            ] {
                assert_eq!(
                    error.raw_os_error(),
                    Some(32),
                    "replacement must fail with ERROR_SHARING_VIOLATION"
                );
            }
            assert!(!moved.exists());
            assert_eq!(std::fs::read(&path).unwrap(), before);
            logger
                .write("INFO", "CONTROL", "SECOND-LINE", &json!({}))
                .unwrap();
            output.message("INFO", "still alive").unwrap();
            logger.finish(0).unwrap();
            assert_eq!(file_identity(&retained).unwrap(), identity);
            assert_eq!(
                file_identity(&std::fs::File::open(&path).unwrap()).unwrap(),
                identity
            );
            let mut bytes = Vec::new();
            retained.read_to_end(&mut bytes).unwrap();
            assert!(bytes.starts_with(&before));
            assert!(std::str::from_utf8(&bytes).unwrap().contains("SECOND-LINE"));
            assert_eq!(
                String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap(),
                "[INFO] still alive\n"
            );
            assert_eq!(std::fs::read_dir(&logs).unwrap().count(), 1);
        }
        #[cfg(not(windows))]
        let _ = identity;
        assert!(stdout.0.lock().unwrap().is_empty());
    }
}

#[test]
fn a_real_backup_open_refusal_disables_logging_without_disclosing_paths_or_mutating_files() {
    use megabasterd_cli::platform::secure_files::{PrivateDirectory, file_identity};
    use std::ffi::OsString;

    let scratch = scratch();
    let logs = scratch.path().join("SENTINEL-PW-9921-user@example.com");
    let logger = Arc::new(Logger::configured(&logs, 512, 2).unwrap());
    let primary = logs.join(logger.name());
    let primary_bytes = std::fs::read(&primary).unwrap();
    let primary_identity = file_identity(&std::fs::File::open(&primary).unwrap()).unwrap();
    let backup_name = OsString::from(format!("{}.1", logger.name().to_string_lossy()));
    let backup = logs.join(&backup_name);
    let directory = PrivateDirectory::open(&logs).unwrap();
    let mut saved = directory.open_private(&backup_name, true).unwrap();
    let backup_identity = file_identity(&saved).unwrap();
    let backup_bytes = b"preserve private backup\n";
    saved.write_all(backup_bytes).unwrap();
    saved.sync_all().unwrap();
    drop(saved);
    #[cfg(unix)]
    struct RestoreMode(std::path::PathBuf);
    #[cfg(unix)]
    impl Drop for RestoreMode {
        fn drop(&mut self) {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o600));
        }
    }
    #[cfg(unix)]
    let restore = {
        use std::os::unix::fs::PermissionsExt;
        let restore = RestoreMode(backup.clone());
        std::fs::set_permissions(&backup, std::fs::Permissions::from_mode(0o666)).unwrap();
        restore
    };
    #[cfg(windows)]
    let mut blocker = {
        use std::os::windows::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&backup)
            .unwrap()
    };
    let refusal = logger
        .write("ERROR", "ROTATE", &"x".repeat(600), &json!({}))
        .unwrap_err();
    #[cfg(windows)]
    assert!(matches!(
        refusal,
        megabasterd_cli::error::Error::Io(ref error) if error.raw_os_error() == Some(32)
    ));
    #[cfg(unix)]
    assert!(matches!(
        refusal,
        megabasterd_cli::error::Error::Protocol(ref message)
            if message == "Native object is not an owner-private regular file or directory"
    ));
    let stdout = Capture::default();
    let stderr = Capture::default();
    let output = Output::with_writers(false, false, stdout.clone(), stderr.clone());
    output.attach_logger(logger.clone()).unwrap();
    output.message("INFO", "still alive").unwrap();
    #[cfg(windows)]
    {
        use std::io::Read;
        let mut bytes = Vec::new();
        blocker.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, backup_bytes);
        assert_eq!(file_identity(&blocker).unwrap(), backup_identity);
        drop(blocker);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
            0o666,
            "the writer must refuse, not repair the unsafe backup"
        );
        drop(restore);
    }
    assert!(
        logger
            .write("INFO", "AFTER", "do not resume", &json!({}))
            .is_err()
    );
    output.message("INFO", "still alive").unwrap();
    assert!(logger.finish(1).is_err());
    output.logging_warning(&logger).unwrap();
    assert_eq!(
        String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap(),
        "[WARNING] Private runtime log write failed.\n[INFO] still alive\n[INFO] still alive\n"
    );
    assert!(stdout.0.lock().unwrap().is_empty());
    assert_eq!(std::fs::read(&primary).unwrap(), primary_bytes);
    assert_eq!(std::fs::read(&backup).unwrap(), backup_bytes);
    assert_eq!(
        file_identity(&std::fs::File::open(&primary).unwrap()).unwrap(),
        primary_identity
    );
    assert_eq!(
        file_identity(&std::fs::File::open(&backup).unwrap()).unwrap(),
        backup_identity
    );
    assert_eq!(std::fs::read_dir(&logs).unwrap().count(), 2);
    for path in [&primary, &backup] {
        let bytes = std::fs::read(path).unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        for private in [
            "SENTINEL-PW-9921",
            "user@example.com",
            logs.to_str().unwrap(),
        ] {
            assert!(!text.contains(private));
        }
    }
}

#[test]
fn a_regular_rotation_control_still_succeeds_after_private_handle_verification() {
    #[cfg(unix)]
    const CHILD: &str = "MB_PRIVATE_LOG_UMASK_CHILD";
    #[cfg(unix)]
    if std::env::var_os(CHILD).as_deref() != Some(std::ffi::OsStr::new("1")) {
        use megabasterd_cli::{platform::process, transfers::control::Control};
        use std::{process::Command, time::Duration};
        let scratch = scratch();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.current_dir(scratch.path()).env_clear();
        for key in [
            "LLVM_PROFILE_FILE",
            "PATH",
            "LD_LIBRARY_PATH",
            "DYLD_LIBRARY_PATH",
        ] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        for key in ["HOME", "TMP", "TEMP", "TMPDIR"] {
            command.env(key, scratch.path());
        }
        command
            .env(CHILD, "1")
            .env("HOOKMAKER_MAX_TEST_WORKERS", "1")
            .args([
                "--exact",
                "a_regular_rotation_control_still_succeeds_after_private_handle_verification",
                "--test-threads=1",
            ]);
        let result = process::run_command(
            command,
            Duration::from_secs(5),
            16 * 1024,
            16 * 1024,
            &Control::new(),
            None,
        )
        .unwrap();
        assert_eq!(result.status.code(), Some(0));
        assert!(result.stderr.is_empty());
        let report = String::from_utf8(result.stdout).unwrap();
        for required in ["1 passed", "0 failed", "0 ignored"] {
            assert!(report.contains(required), "{report}");
        }
        return;
    }
    #[cfg(unix)]
    {
        let arguments = std::env::args().collect::<Vec<_>>();
        assert!(arguments.windows(2).any(|pair| {
            pair[0] == "--exact"
                && pair[1]
                    == "a_regular_rotation_control_still_succeeds_after_private_handle_verification"
        }));
        assert!(
            arguments
                .iter()
                .any(|argument| argument == "--test-threads=1")
        );
    }
    #[cfg(unix)]
    struct RestoreUmask(libc::mode_t);
    #[cfg(unix)]
    impl Drop for RestoreUmask {
        fn drop(&mut self) {
            // SAFETY: restore only this isolated single-test child's prior process mask.
            unsafe { libc::umask(self.0) };
        }
    }
    #[cfg(unix)]
    // SAFETY: only the bounded exact-test child reaches this process-wide mutation.
    let _mask = RestoreUmask(unsafe { libc::umask(0) });

    let scratch = scratch();
    let logs = scratch.path().join("private");
    let logger = Logger::configured(&logs, 512, 2).unwrap();
    let name = logger.name().to_owned();
    let primary = logs.join(&name);
    let startup = std::fs::read_to_string(&primary).unwrap();
    assert_eq!(startup.lines().count(), 1);
    assert!(startup.contains("[INFO] [RUNTIME]") && startup.contains("Started"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&primary).unwrap().permissions().mode() & 0o7777,
            0o600
        );
    }
    #[cfg(windows)]
    windows_log_acl::snapshot(&primary).assert_owner_only();
    logger
        .write("INFO", "ROTATE", &"x".repeat(600), &json!({}))
        .unwrap();
    logger.finish(0).unwrap();
    let backup = logs.join(format!("{}.1", name.to_string_lossy()));
    assert!(backup.is_file());
    let directory = megabasterd_cli::platform::secure_files::PrivateDirectory::open(&logs).unwrap();
    let entries = std::fs::read_dir(&logs)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    assert_eq!(entries.len(), 3, "both real rotated segments must exist");
    let mut combined = String::new();
    for suffix in ["", ".1", ".2"] {
        let path = logs.join(format!("{}{suffix}", name.to_string_lossy()));
        assert!(entries.contains(&path));
        assert!(std::fs::symlink_metadata(&path).unwrap().is_file());
        let file = directory
            .open_private(path.file_name().unwrap(), false)
            .unwrap();
        directory.verify_private(&file).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                file.metadata().unwrap().permissions().mode() & 0o7777,
                0o600
            );
        }
        #[cfg(windows)]
        windows_log_acl::snapshot(&path).assert_owner_only();
        let contents = std::fs::read_to_string(path).unwrap();
        assert!(!contents.is_empty());
        combined.push_str(&contents);
    }
    assert!(combined.contains(&"x".repeat(600)));
    assert!(combined.contains(&startup));
    assert!(
        std::fs::read_to_string(logs.join(name))
            .unwrap()
            .contains("Finished")
    );
}

#[path = "common/private_tempfile.rs"]
mod private_tempfile;
