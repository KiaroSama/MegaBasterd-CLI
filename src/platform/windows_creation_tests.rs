//! Native creation must verify the descriptor before returning a writable file.
#![allow(clippy::unwrap_used)]

use std::{
    cell::RefCell,
    io::Write,
    sync::{Arc, Mutex},
};

use super::*;
use crate::terminal::{logging::Logger, output::Output};

#[path = "../../tests/common/windows_log_acl.rs"]
mod windows_log_acl;

struct CreationOverride {
    directory: PathBuf,
    descriptor: Vec<u16>,
}

thread_local! {
    static CREATION: RefCell<Option<CreationOverride>> = const { RefCell::new(None) };
}

pub(super) fn descriptor_for_creation(
    directory: &Path,
    create_new: bool,
    original: LocalAllocation,
) -> Result<LocalAllocation> {
    let replacement = CREATION.with(|slot| {
        let mut slot = slot.borrow_mut();
        if create_new
            && slot
                .as_ref()
                .is_some_and(|value| value.directory == directory)
        {
            slot.take().map(|value| value.descriptor)
        } else {
            None
        }
    });
    replacement.map_or(Ok(original), |sddl| descriptor_from_sddl(&sddl))
}

fn with_descriptor<T>(directory: &Path, descriptor: Vec<u16>, run: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            CREATION.with(|slot| {
                slot.borrow_mut().take();
            });
        }
    }
    CREATION.with(|slot| {
        let mut slot = slot.borrow_mut();
        assert!(slot.is_none());
        *slot = Some(CreationOverride {
            directory: directory.to_owned(),
            descriptor,
        });
    });
    let _reset = Reset;
    run()
}

fn broad_descriptor() -> Vec<u16> {
    let token = token_user().unwrap();
    let sid = sid_from_token(&token).unwrap();
    let mut raw = ptr::null_mut();
    // SAFETY: validated token SID remains live until conversion finishes.
    assert_ne!(unsafe { ConvertSidToStringSidW(sid, &mut raw) }, 0);
    let _allocation = LocalAllocation(raw.cast());
    let length = (0..256)
        // SAFETY: the converted SID is terminated and shorter than 256 UTF-16 units.
        .find(|&index| unsafe { *raw.add(index) } == 0)
        .unwrap();
    // SAFETY: the inspected prefix lies within the retained converted SID allocation.
    let owner = String::from_utf16(unsafe { std::slice::from_raw_parts(raw, length) }).unwrap();
    format!("O:{owner}G:{owner}D:P(A;;FA;;;{owner})(A;;FR;;;S-1-5-19)")
        .encode_utf16()
        .chain(Some(0))
        .collect()
}

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut output = self.0.lock().unwrap();
        if bytes.len() > 4096usize.saturating_sub(output.len()) {
            return Err(io::Error::other(
                "Creation fixture capture exceeded its bound",
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
fn an_unsafe_descriptor_at_creation_is_refused_empty_and_console_diagnostics_remain_available() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/logging-creation");
    std::fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    let logs = scratch.path().join("user@example.com-SENTINEL-CREATE");
    let directory = crate::platform::secure_files::PrivateDirectory::ensure(&logs).unwrap();
    let stdout = Capture::default();
    let stderr = Capture::default();
    let output = Output::with_writers(false, false, stdout.clone(), stderr.clone());
    with_descriptor(&logs, broad_descriptor(), || {
        let error = Logger::configured(&logs, 0, 0).err().unwrap();
        assert!(matches!(error, Error::Protocol(message)
            if message == "Private native object grants another principal access"));
        assert!(CREATION.with(|slot| slot.borrow().is_none()));
        let entries = std::fs::read_dir(&logs)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 1);
        let refused = &entries[0];
        assert_eq!(std::fs::read(refused).unwrap(), b"");
        let unsafe_acl = windows_log_acl::snapshot(refused);
        assert!(unsafe_acl.grants_local_service_read());
        let identity = file_identity(&File::open(refused).unwrap()).unwrap();
        output.logging_init_warning().unwrap();
        output.message("WARNING", "still alive").unwrap();
        assert!(stdout.0.lock().unwrap().is_empty());
        assert_eq!(
            String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap(),
            concat!(
                "[WARNING] Private file logging could not be initialized; only console diagnostics are available.\n",
                "[WARNING] still alive\n",
            )
        );
        assert_eq!(std::fs::read(refused).unwrap(), b"");
        assert_eq!(
            file_identity(&File::open(refused).unwrap()).unwrap(),
            identity
        );
        let logger = Logger::configured(&logs, 0, 0).unwrap();
        let safe = logs.join(logger.name());
        assert_ne!(&safe, refused);
        windows_log_acl::snapshot(&safe).assert_owner_only();
        logger.finish(0).unwrap();
        assert!(std::fs::read_to_string(&safe).unwrap().contains("Finished"));
        assert_eq!(std::fs::read(refused).unwrap(), b"");
        assert_eq!(std::fs::read_dir(&logs).unwrap().count(), 2);
        // An independent setter/observer confirms the bad-at-create descriptor's exact grants.
        assert_eq!(
            windows_log_acl::grant_local_service_read(&safe, false),
            unsafe_acl
        );
    });
    assert!(CREATION.with(|slot| slot.borrow().is_none()));
    drop(directory);
}

#[test]
fn creation_override_is_directory_scoped_single_use_and_restored_after_unwind() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/logging-creation");
    std::fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    let first = scratch.path().join("first");
    let second = scratch.path().join("second");
    let directory = crate::platform::secure_files::PrivateDirectory::ensure(&first).unwrap();
    drop(crate::platform::secure_files::PrivateDirectory::ensure(&second).unwrap());
    let name = OsStr::new("existing.log");
    drop(directory.open_private(name, true).unwrap());
    let outcome = std::panic::catch_unwind(|| {
        with_descriptor::<()>(&first, broad_descriptor(), || {
            drop(directory.open_private(name, false).unwrap());
            assert!(CREATION.with(|slot| slot.borrow().is_some()));
            let logger = Logger::configured(&second, 0, 0).unwrap();
            windows_log_acl::snapshot(&second.join(logger.name())).assert_owner_only();
            logger.finish(0).unwrap();
            assert!(CREATION.with(|slot| slot.borrow().is_some()));
            std::panic::resume_unwind(Box::new(()));
        })
    });
    assert!(outcome.is_err());
    assert!(CREATION.with(|slot| slot.borrow().is_none()));
    let logger = Logger::configured(&first, 0, 0).unwrap();
    windows_log_acl::snapshot(&first.join(logger.name())).assert_owner_only();
    logger.finish(0).unwrap();
}

#[test]
fn context_startup_survives_a_log_created_with_an_unsafe_descriptor_without_writing_to_it() {
    use crate::{
        cli::context::Context,
        storage::{files::Store, paths::Paths},
    };

    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/logging-creation");
    std::fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    let paths = Paths {
        root: scratch.path().to_owned(),
        user: scratch.path().join("private user"),
        logs: scratch.path().join("user@example.com-SENTINEL-CONTEXT"),
        output: scratch.path().join("output"),
    };
    drop(crate::platform::secure_files::PrivateDirectory::ensure(&paths.logs).unwrap());
    Store::new(paths.config())
        .lock()
        .unwrap()
        .save(&serde_json::json!({"max_workers":3,"log_to_file":true}))
        .unwrap();
    let original_config = std::fs::read(paths.config()).unwrap();
    let stdout = Capture::default();
    let stderr = Capture::default();
    with_descriptor(&paths.logs, broad_descriptor(), || {
        let context = Context::start_with_output(
            paths.clone(),
            Output::with_writers(false, false, stdout.clone(), stderr.clone()),
            Some(true),
            "config",
        )
        .unwrap();
        assert!(CREATION.with(|slot| slot.borrow().is_none()));
        assert!(context.logger.is_none() && context.config_error.is_none());
        assert_eq!(context.config.max_workers, 3);
        let entries = std::fs::read_dir(&paths.logs)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 1);
        let refused = &entries[0];
        assert_eq!(std::fs::read(refused).unwrap(), b"");
        let acl = windows_log_acl::snapshot(refused);
        assert!(acl.grants_local_service_read());
        let identity = file_identity(&File::open(refused).unwrap()).unwrap();
        context.output.message("INFO", "still alive").unwrap();
        context.finish(0);
        drop(context);
        assert!(stdout.0.lock().unwrap().is_empty());
        assert_eq!(
            String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap(),
            concat!(
                "[WARNING] Private file logging could not be initialized; only console diagnostics are available.\n",
                "[INFO] still alive\n",
            )
        );
        assert_eq!(std::fs::read(refused).unwrap(), b"");
        assert_eq!(
            file_identity(&File::open(refused).unwrap()).unwrap(),
            identity
        );
        assert_eq!(windows_log_acl::snapshot(refused), acl);
        assert_eq!(std::fs::read_dir(&paths.logs).unwrap().count(), 1);
        assert_eq!(std::fs::read(paths.config()).unwrap(), original_config);
        assert!(!paths.output.exists());
    });
    assert!(CREATION.with(|slot| slot.borrow().is_none()));
}
