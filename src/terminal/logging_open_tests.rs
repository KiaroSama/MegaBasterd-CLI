//! Initial private-open errors cannot fall through to an ordinary file opener.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::terminal::output::Output;
use std::{io, sync::Arc};

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut output = self.0.lock().unwrap();
        if bytes.len() > 4096usize.saturating_sub(output.len()) {
            return Err(io::Error::other(
                "Initial logging capture exceeded its bound",
            ));
        }
        output.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn scratch() -> tempfile::TempDir {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/logging-initial-open");
    std::fs::create_dir_all(&base).unwrap();
    tempfile::tempdir_in(base).unwrap()
}

#[test]
fn initial_private_open_failure_returns_without_retrying_or_changing_existing_files() {
    for verification_failure in [false, true] {
        let scratch = scratch();
        let logs = scratch.path().join("user@example.com-SENTINEL-OPEN");
        let directory = PrivateDirectory::ensure(&logs).unwrap();
        let sentinel = logs.join("preserve.log");
        let mut file = directory
            .open_private(OsStr::new("preserve.log"), true)
            .unwrap();
        file.write_all(b"original private bytes\n").unwrap();
        file.sync_all().unwrap();
        let identity = crate::platform::secure_files::file_identity(&file).unwrap();
        let mut attempts = 0;
        let error = Logger::configured_with_opener(&logs, 0, 0, "config", |_, name| {
            attempts += 1;
            assert!(name.to_str().unwrap().starts_with("mb_"));
            if verification_failure {
                Err(Error::protocol("Controlled private verification refusal"))
            } else {
                Err(
                    io::Error::new(io::ErrorKind::PermissionDenied, "controlled open refusal")
                        .into(),
                )
            }
        })
        .err()
        .unwrap();
        if verification_failure {
            assert!(matches!(error, Error::Protocol(message)
                if message == "Controlled private verification refusal"));
        } else {
            assert!(matches!(error, Error::Io(error)
                if error.kind() == io::ErrorKind::PermissionDenied));
        }
        assert_eq!(attempts, 1);
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
        assert_eq!(
            std::fs::read(&sentinel).unwrap(),
            b"original private bytes\n"
        );
        assert_eq!(
            crate::platform::secure_files::file_identity(&file).unwrap(),
            identity
        );
        let names = std::fs::read_dir(&logs)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(names, [OsString::from("preserve.log")]);
        directory.verify_private(&file).unwrap();
    }
}

#[test]
fn only_an_existing_name_advances_the_initial_private_creation_attempt() {
    let scratch = scratch();
    let logs = scratch.path().join("private logs");
    let mut attempts = 0;
    let mut occupied = None;
    let logger = Logger::configured_with_opener(&logs, 0, 0, "config", |directory, name| {
        attempts += 1;
        if attempts == 1 {
            let mut file = directory.open_private(name, true)?;
            file.write_all(b"occupied log must remain unchanged\n")?;
            file.sync_all()?;
            occupied = Some((
                name.to_owned(),
                crate::platform::secure_files::file_identity(&file)?,
            ));
            drop(file);
        }
        directory.open_private(name, true)
    })
    .unwrap();
    assert_eq!(attempts, 2);
    let (name, identity) = occupied.unwrap();
    assert_ne!(logger.name(), name.as_os_str());
    assert!(logger.name().to_str().unwrap().ends_with("_1.log"));
    let directory = PrivateDirectory::open(&logs).unwrap();
    let file = directory.open_private(&name, false).unwrap();
    assert_eq!(
        crate::platform::secure_files::file_identity(&file).unwrap(),
        identity
    );
    assert_eq!(
        std::fs::read(logs.join(&name)).unwrap(),
        b"occupied log must remain unchanged\n"
    );
    logger.finish(0).unwrap();
    let control = std::fs::read_to_string(logs.join(logger.name())).unwrap();
    assert!(control.contains("Started") && control.contains("Finished"));
    assert!(control.contains("cmd=config"));
    assert_eq!(std::fs::read_dir(&logs).unwrap().count(), 2);
}
