//! Actual OS write and security-query refusals seal the private logger.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::{platform::secure_files::OutputDirectory, terminal::output::Output};
use std::{io, sync::Arc};

#[cfg(windows)]
#[allow(dead_code)] // This fixture uses only the shared independent ACL observer.
#[path = "../../tests/common/windows_log_acl.rs"]
mod windows_log_acl;

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut output = self.0.lock().unwrap();
        if bytes.len() > 4096usize.saturating_sub(output.len()) {
            return Err(io::Error::other(
                "Logging fixture capture exceeded its bound",
            ));
        }
        output.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_real_read_only_sink_write_failure_seals_logging_without_mutation_or_disclosure() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/logging-write");
    std::fs::create_dir_all(&base).unwrap();
    let scratch = crate::test_support::tempdir_in(base).unwrap();
    let logs = scratch.path().join("user@example.com-SENTINEL-PW-7781");
    let logger = Arc::new(Logger::configured(&logs, 0, 0).unwrap());
    let path = logs.join(logger.name());
    let original = std::fs::read(&path).unwrap();
    assert!(std::str::from_utf8(&original).unwrap().contains("Started"));
    let read_only = OutputDirectory::open(&logs)
        .unwrap()
        .open_read(logger.name())
        .unwrap();
    logger.directory.verify_private(&read_only).unwrap();
    let identity = crate::platform::secure_files::file_identity(&read_only).unwrap();
    {
        let mut active = logger.active.lock().unwrap();
        let writable = active.file.take().unwrap();
        assert_eq!(
            crate::platform::secure_files::file_identity(&writable).unwrap(),
            identity
        );
        drop(writable);
        active.file = Some(read_only);
    }
    let error = logger
        .write(
            "ERROR",
            "WRITE",
            "must not reach the file",
            &serde_json::json!({}),
        )
        .unwrap_err();
    assert!(matches!(error, Error::Io(_)));
    assert!(logger.active.lock().unwrap().file.is_none());
    let stdout = Capture::default();
    let stderr = Capture::default();
    let output = Output::with_writers(false, false, stdout.clone(), stderr.clone());
    output.attach_logger(logger.clone()).unwrap();
    for _ in 0..2 {
        output.message("INFO", "still alive").unwrap();
    }
    assert!(logger.finish(1).is_err());
    output.logging_warning(&logger).unwrap();
    assert!(stdout.0.lock().unwrap().is_empty());
    assert_eq!(
        String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap(),
        "[WARNING] Private runtime log write failed.\n[INFO] still alive\n[INFO] still alive\n"
    );
    assert_eq!(std::fs::read(&path).unwrap(), original);
    let retained = logger.directory.open_private(logger.name(), false).unwrap();
    assert_eq!(
        crate::platform::secure_files::file_identity(&retained).unwrap(),
        identity
    );
    assert_eq!(std::fs::read_dir(&logs).unwrap().count(), 1);
    let written = std::str::from_utf8(&original).unwrap();
    for private in [
        "user@example.com",
        "SENTINEL-PW-7781",
        logs.to_str().unwrap(),
    ] {
        assert!(!written.contains(private));
    }
}

#[cfg(windows)]
fn without_security_access(original: &File) -> File {
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use windows_sys::Win32::{
        Foundation::{DuplicateHandle, ERROR_ACCESS_DENIED, LocalFree},
        Security::{
            Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
            DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        },
        Storage::FileSystem::{FILE_GENERIC_READ, FILE_GENERIC_WRITE, READ_CONTROL},
        System::Threading::GetCurrentProcess,
    };

    let mut reduced = std::ptr::null_mut();
    // SAFETY: live current-process file; success transfers one non-inheritable duplicate.
    assert_ne!(
        unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                original.as_raw_handle(),
                GetCurrentProcess(),
                &mut reduced,
                (FILE_GENERIC_READ | FILE_GENERIC_WRITE) & !READ_CONTROL,
                0,
                0,
            )
        },
        0
    );
    // SAFETY: the successful duplicate is uniquely owned, not the retained original.
    let reduced = unsafe { File::from_raw_handle(reduced) };
    assert_eq!(
        crate::platform::secure_files::file_identity(&reduced).unwrap(),
        crate::platform::secure_files::file_identity(original).unwrap(),
    );
    let mut owner = std::ptr::null_mut();
    let mut dacl = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    // SAFETY: retained duplicate and valid outputs; it intentionally lacks READ_CONTROL.
    let status = unsafe {
        GetSecurityInfo(
            reduced.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    let empty = descriptor.is_null();
    if !empty {
        // SAFETY: any returned descriptor is LocalAlloc-owned, even on unexpected success.
        unsafe { LocalFree(descriptor) };
    }
    assert_eq!(status, ERROR_ACCESS_DENIED);
    assert!(empty && owner.is_null() && dacl.is_null());
    reduced
}

#[cfg(windows)]
#[test]
fn a_real_security_query_failure_seals_logging_before_writing_without_an_insecure_fallback() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/logging-write");
    std::fs::create_dir_all(&base).unwrap();
    let scratch = crate::test_support::tempdir_in(base).unwrap();
    let logs = scratch.path().join("user@example.com-SENTINEL-PW-7781");
    let logger = Arc::new(Logger::configured(&logs, 0, 0).unwrap());
    let path = logs.join(logger.name());
    let before = std::fs::read(&path).unwrap();
    let acl = windows_log_acl::snapshot(&path);
    acl.assert_owner_only();
    let original = {
        let mut active = logger.active.lock().unwrap();
        let original = active.file.take().unwrap();
        logger.directory.verify_private(&original).unwrap();
        active.file = Some(without_security_access(&original));
        original
    };
    let identity = crate::platform::secure_files::file_identity(&original).unwrap();
    assert!(std::str::from_utf8(&before).unwrap().contains("Started"));
    let error = logger
        .write(
            "ERROR",
            "VERIFY",
            "must not reach disk",
            &serde_json::json!({}),
        )
        .unwrap_err();
    assert!(
        matches!(error, Error::Protocol(ref message) if message == "Cannot read native owner or ACL")
    );
    assert!(logger.active.lock().unwrap().file.is_none());
    assert!(
        logger
            .write(
                "INFO",
                "VERIFY",
                "must remain disabled",
                &serde_json::json!({})
            )
            .is_err()
    );
    assert!(logger.finish(1).is_err());
    let stdout = Capture::default();
    let stderr = Capture::default();
    let output = Output::with_writers(false, false, stdout.clone(), stderr.clone());
    output.attach_logger(logger.clone()).unwrap();
    for _ in 0..2 {
        output.message("INFO", "still alive").unwrap();
        output.logging_warning(&logger).unwrap();
    }
    assert!(stdout.0.lock().unwrap().is_empty());
    assert_eq!(
        String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap(),
        "[WARNING] Private runtime log write failed.\n[INFO] still alive\n[INFO] still alive\n",
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(windows_log_acl::snapshot(&path), acl);
    assert_eq!(
        crate::platform::secure_files::file_identity(&original).unwrap(),
        identity
    );
    assert_eq!(std::fs::read_dir(&logs).unwrap().count(), 1);
    drop(output);
    drop(logger);
    drop(original);
    let fresh = Logger::configured(&logs, 0, 0).unwrap();
    let fresh_path = logs.join(fresh.name());
    assert_ne!(fresh_path, path);
    fresh
        .write("INFO", "CONTROL", "safe fresh run", &serde_json::json!({}))
        .unwrap();
    fresh.finish(0).unwrap();
    assert!(
        std::fs::read_to_string(&fresh_path)
            .unwrap()
            .contains("safe fresh run")
    );
    windows_log_acl::snapshot(&fresh_path).assert_owner_only();
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(windows_log_acl::snapshot(&path), acl);
    assert_eq!(std::fs::read_dir(&logs).unwrap().count(), 2);
}

#[cfg(windows)]
#[test]
fn an_initial_security_query_failure_leaves_the_created_log_empty_and_console_usable() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/logging-write");
    std::fs::create_dir_all(&base).unwrap();
    let scratch = crate::test_support::tempdir_in(base).unwrap();
    let logs = scratch.path().join("user@example.com-SENTINEL-PW-7781");
    let mut attempts = 0;
    let mut created = None;
    let error = Logger::configured_with_opener(&logs, 0, 0, "config", |directory, name| {
        attempts += 1;
        let original = directory.open_private(name, true)?;
        let reduced = without_security_access(&original);
        let identity = crate::platform::secure_files::file_identity(&original)?;
        let acl = windows_log_acl::snapshot(&logs.join(name));
        acl.assert_owner_only();
        created = Some((name.to_owned(), original, identity, acl));
        directory.verify_private(&reduced)?;
        Ok(reduced)
    })
    .err()
    .unwrap();
    assert!(
        matches!(error, Error::Protocol(ref message) if message == "Cannot read native owner or ACL")
    );
    assert_eq!(
        attempts, 1,
        "security failures must not retry another opener"
    );
    let (name, retained, identity, acl) = created.unwrap();
    let path = logs.join(&name);
    assert_eq!(std::fs::read(&path).unwrap(), b"");
    assert_eq!(
        crate::platform::secure_files::file_identity(&retained).unwrap(),
        identity
    );
    assert_eq!(windows_log_acl::snapshot(&path), acl);
    assert_eq!(std::fs::read_dir(&logs).unwrap().count(), 1);
    let stdout = Capture::default();
    let stderr = Capture::default();
    let output = Output::with_writers(false, false, stdout.clone(), stderr.clone());
    output.logging_init_warning().unwrap();
    output.message("INFO", "still alive").unwrap();
    assert!(stdout.0.lock().unwrap().is_empty());
    assert_eq!(
        String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap(),
        concat!(
            "[WARNING] Private file logging could not be initialized; only console diagnostics are available.\n",
            "[INFO] still alive\n",
        )
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"");
    assert_eq!(windows_log_acl::snapshot(&path), acl);
    drop(retained);
    let fresh = Logger::configured(&logs, 0, 0).unwrap();
    let fresh_path = logs.join(fresh.name());
    assert_ne!(fresh_path, path);
    fresh.finish(0).unwrap();
    let text = std::fs::read_to_string(&fresh_path).unwrap();
    assert!(text.contains("Started") && text.contains("Finished"));
    windows_log_acl::snapshot(&fresh_path).assert_owner_only();
    assert_eq!(std::fs::read(&path).unwrap(), b"");
    assert_eq!(std::fs::read_dir(&logs).unwrap().count(), 2);
}
