#![allow(clippy::unwrap_used)]

use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use megabasterd_cli::terminal::{logging::Logger, output::Output, redaction::log_text};
use serde_json::json;

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);
impl Capture {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}
impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut output = self.0.lock().unwrap();
        if bytes.len() > 32_768usize.saturating_sub(output.len()) {
            return Err(io::Error::other(
                "Logging fixture output exceeded its bound",
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
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/logging-privacy");
    std::fs::create_dir_all(&base).unwrap();
    tempfile::tempdir_in(base).unwrap()
}

const LEAKS: &[(&str, &[&str])] = &[
    (
        "Authorization: Digest username=\"u\", nonce=\"SENTINELNONCE\", response=\"SENTINELRESP\"",
        &["SENTINELNONCE", "SENTINELRESP"],
    ),
    (
        "Proxy-Authorization: Basic SENTINELBASIC",
        &["SENTINELBASIC"],
    ),
    ("sent Bearer SENTINELBEARER upstream", &["SENTINELBEARER"]),
    ("the password is SENTINELPW", &["SENTINELPW"]),
    ("password: SENTINELPW2", &["SENTINELPW2"]),
    ("SID was SENTINELSID", &["SENTINELSID"]),
    ("session id: SENTINELSESSION", &["SENTINELSESSION"]),
    ("MFA code 123456", &["123456"]),
    ("api key: SENTINELAPIKEY", &["SENTINELAPIKEY"]),
    ("vault passphrase = SENTINELVAULT", &["SENTINELVAULT"]),
    (
        "download L --share-password \"SENTINELSHARE private tail\" -o out",
        &["SENTINELSHARE", "private tail"],
    ),
    (
        "download L --share-password 'SENTINELSHARE private tail' -o out",
        &["SENTINELSHARE", "private tail"],
    ),
    (
        "download L --elc-api-key \"SENTINELELC private tail\" -o out",
        &["SENTINELELC", "private tail"],
    ),
    (
        "download L --elc-api-key 'SENTINELELC private tail' -o out",
        &["SENTINELELC", "private tail"],
    ),
    (
        "using http://user:SENTINELPROXYPW@proxy.example:8080",
        &["SENTINELPROXYPW"],
    ),
];

#[test]
fn every_exact_central_secret_shape_is_masked_in_the_real_log_and_shared_sanitizer() {
    let scratch = scratch();
    let logs = scratch.path().join("private logs with spaces");
    let logger = Logger::configured(&logs, 0, 0).unwrap();
    let path = logs.join(logger.name());
    for (index, (message, secrets)) in LEAKS.iter().enumerate() {
        let cleaned = log_text(message);
        for &secret in *secrets {
            assert!(!cleaned.contains(secret), "sanitizer case {index}");
        }
        assert_eq!(log_text(&cleaned), cleaned);
        logger
            .write("INFO", "CENTRAL", message, &json!({"case": index}))
            .unwrap();
    }
    logger.finish(0).unwrap();
    let written = std::fs::read_to_string(path).unwrap();
    assert_eq!(written.matches("[INFO] [CENTRAL]").count(), LEAKS.len());
    for (_, secrets) in LEAKS {
        for &secret in *secrets {
            assert!(!written.contains(secret));
        }
    }
    assert_eq!(
        log_text("Downloaded chunk 4 of 12 in 1.20s"),
        "Downloaded chunk 4 of 12 in 1.20s"
    );
    let link = log_text("fetching https://mega.nz/file/ABCD1234#SECRETKEYVALUE now");
    assert!(!link.contains("SECRETKEYVALUE"));
    assert!(link.contains("<redacted-url>"));
    assert!(!log_text("logged in as user@example.com").contains("user@example.com"));
    let combined = log_text("password: SENTINELPW and SID was SENTINELSID");
    assert!(!combined.contains("SENTINELPW") && !combined.contains("SENTINELSID"));
    assert_eq!(log_text(&combined), combined);
}

#[test]
fn diagnostics_and_error_chains_use_stderr_only_and_keep_sanitized_failure_context_in_the_log() {
    let scratch = scratch();
    let logs = scratch.path().join("private");
    let logger = Arc::new(Logger::configured(&logs, 0, 0).unwrap());
    let path = logs.join(logger.name());
    let stdout = Capture::default();
    let stderr = Capture::default();
    let output = Output::with_writers(true, false, stdout.clone(), stderr.clone());
    output.attach_logger(logger.clone()).unwrap();
    output.diagnostic("WARNING", "MARKERWORD").unwrap();
    let failure = concat!(
        "transfer failed\nTraceback: RuntimeError: proxy auth failed for ",
        "http://alice:hunter2@1.2.3.4:8080 (password: swordfish)\n",
        "ValueError: bad login for carol@example.com; password: SENTINELTRACEBACK"
    );
    output.message("ERROR", failure).unwrap();
    logger.finish(1).unwrap();
    assert!(stdout.text().is_empty());
    let console = stderr.text();
    assert!(console.contains("MARKERWORD"));
    let written = std::fs::read_to_string(path).unwrap();
    for text in [&console, &written] {
        for secret in ["hunter2", "swordfish", "SENTINELTRACEBACK"] {
            assert!(!text.contains(secret));
        }
        for context in [
            "transfer failed",
            "Traceback",
            "RuntimeError",
            "proxy auth failed",
        ] {
            assert!(text.contains(context));
        }
    }
    assert!(!written.contains("carol@example.com"));
    assert!(written.contains("ValueError: bad login"));
    assert_eq!(written.matches("MARKERWORD").count(), 1);
}

#[test]
fn a_caught_filesystem_failure_keeps_its_real_cause_but_redacts_email_in_the_private_log() {
    use megabasterd_cli::error::{Error, Result as NativeResult};
    use std::{
        error::Error as _,
        fmt,
        fs::File,
        path::{Path, PathBuf},
    };

    #[derive(Debug)]
    struct OpenFailure {
        path: PathBuf,
        cause: io::Error,
    }
    impl fmt::Display for OpenFailure {
        fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                output,
                "file open failed ({:?}) for {}: {}",
                self.cause.kind(),
                self.path.display(),
                self.cause
            )
        }
    }
    impl std::error::Error for OpenFailure {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.cause)
        }
    }
    fn open(path: &Path) -> NativeResult<File> {
        Ok(File::open(path).map_err(|cause| {
            io::Error::new(
                cause.kind(),
                OpenFailure {
                    path: path.to_owned(),
                    cause,
                },
            )
        })?)
    }

    for machine in [false, true] {
        let scratch = scratch();
        let missing = scratch.path().join("carol@example.com");
        assert!(!missing.exists());
        let error = open(&missing).unwrap_err();
        let Error::Io(caught) = &error else {
            panic!("Filesystem failure did not use the existing I/O error conversion");
        };
        assert_eq!(caught.kind(), io::ErrorKind::NotFound);
        let source = caught
            .get_ref()
            .unwrap()
            .downcast_ref::<OpenFailure>()
            .unwrap();
        assert_eq!(source.path, missing);
        assert_eq!(source.cause.kind(), io::ErrorKind::NotFound);
        assert!(source.cause.raw_os_error().is_some());
        assert!(source.source().unwrap().is::<io::Error>());
        let native_cause = source.cause.to_string();
        assert!(!native_cause.is_empty());
        let diagnostic = error.to_string();
        assert!(
            diagnostic.contains("carol@example.com"),
            "Email redaction control was absent from the caught failure"
        );

        let logs = scratch.path().join("private");
        let logger = Arc::new(Logger::configured(&logs, 0, 0).unwrap());
        let path = logs.join(logger.name());
        let stdout = Capture::default();
        let stderr = Capture::default();
        let output = Output::with_writers(machine, false, stdout.clone(), stderr.clone());
        output.attach_logger(logger.clone()).unwrap();
        output.error(&error).unwrap();
        logger.finish(error.exit_code()).unwrap();

        let console = stderr.text();
        assert_eq!(console, format!("[ERROR] {diagnostic}\n"));
        if machine {
            let text = stdout.text();
            assert_eq!(text.lines().count(), 1);
            let record: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(record["event"], "result");
            assert_eq!(record["status"], "failed");
            assert_eq!(record["error_code"], "local_file_missing");
            assert_eq!(record["error"], diagnostic);
        } else {
            assert!(stdout.text().is_empty());
        }
        let written = std::fs::read_to_string(&path).unwrap();
        assert_eq!(written.matches("[ERROR] [OUTPUT]").count(), 1);
        assert!(!written.contains("carol@example.com"));
        assert!(written.contains("<redacted-email>"));
        for contents in [&console, &written] {
            for retained in [
                "I/O operation failed",
                "file open failed",
                "NotFound",
                &native_cause,
            ] {
                assert!(
                    contents.contains(retained),
                    "Caught failure context was dropped"
                );
            }
            assert!(!contents.contains("Traceback") && !contents.contains("RuntimeError"));
        }
        assert!(!missing.exists());
        assert_eq!(std::fs::read_dir(&logs).unwrap().count(), 1);
    }
}

#[test]
fn a_disabled_log_warns_once_without_recursion_path_disclosure_or_loss_of_console_output() {
    let scratch = scratch();
    let logs = scratch.path().join("SENTINEL-PW-4471-user@example.com");
    let logger = Arc::new(Logger::configured(&logs, 512, 2).unwrap());
    let path = logs.join(logger.name());
    let blocked = logs.join(format!("{}.1", logger.name().to_string_lossy()));
    let stdout = Capture::default();
    let stderr = Capture::default();
    let output = Output::with_writers(false, false, stdout.clone(), stderr.clone());
    output.attach_logger(logger.clone()).unwrap();
    const CREDENTIAL: &str = "--password SENTINEL-PW-8842";
    output
        .message("WARNING", &format!("still alive first {CREDENTIAL}"))
        .unwrap();
    let before = std::fs::read(&path).unwrap();
    assert!(
        String::from_utf8(before.clone())
            .unwrap()
            .contains("still alive first")
    );
    assert!(!stderr.text().contains("Private runtime log write failed."));
    std::fs::create_dir(&blocked).unwrap();
    output
        .message(
            "WARNING",
            &format!("still alive second {CREDENTIAL} {}", "x".repeat(600)),
        )
        .unwrap();
    for _ in 0..3 {
        output
            .message("WARNING", &format!("still alive later {CREDENTIAL}"))
            .unwrap();
    }
    assert!(logger.finish(1).is_err());
    output.logging_warning(&logger).unwrap();
    let text = stderr.text();
    assert_eq!(text.matches("Private runtime log write failed.").count(), 1);
    assert_eq!(text.matches("still alive").count(), 5);
    for secret in ["SENTINEL-PW-8842", "SENTINEL-PW-4471", "user@example.com"] {
        assert!(!text.contains(secret));
    }
    assert!(stdout.text().is_empty());
    assert!(blocked.is_dir());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let artifacts: Vec<_> = std::fs::read_dir(&logs)
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(artifacts.len(), 2);
    let mut files = 0;
    for artifact in artifacts {
        let kind = artifact.file_type().unwrap();
        assert!(!kind.is_symlink());
        if kind.is_file() {
            files += 1;
            assert!(artifact.metadata().unwrap().len() <= 4096);
            let contents = std::fs::read_to_string(artifact.path()).unwrap();
            for secret in ["SENTINEL-PW-8842", "SENTINEL-PW-4471", "user@example.com"] {
                assert!(!contents.contains(secret));
            }
            assert!(contents.contains("still alive first"));
            assert!(!contents.contains("still alive second"));
        } else {
            assert!(kind.is_dir());
            assert_eq!(artifact.path(), blocked);
            assert_eq!(std::fs::read_dir(artifact.path()).unwrap().count(), 0);
        }
    }
    assert_eq!(files, 1);
}

#[test]
fn nested_structured_secrets_are_masked_without_dropping_safe_siblings_in_output_or_logs() {
    let original = json!({"a":{"b":[{"password":"pw1","note":"keep"}]}});
    let expected = json!({"a":{"b":[{"password":"<redacted>","note":"keep"}]}});
    let stdout = Capture::default();
    let stderr = Capture::default();
    let output = Output::with_writers(true, false, stdout.clone(), stderr.clone());
    output.record(&original).unwrap();
    let machine = stdout.text();
    assert_eq!(machine.lines().count(), 1);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&machine).unwrap(),
        expected
    );
    assert!(stderr.text().is_empty());

    let scratch = scratch();
    let logs = scratch.path().join("private");
    let logger = Logger::configured(&logs, 0, 0).unwrap();
    logger
        .write("INFO", "NESTED", "nested payload", &original)
        .unwrap();
    logger.finish(0).unwrap();
    let written = std::fs::read_to_string(logs.join(logger.name())).unwrap();
    let lines = written.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 3);
    assert!(lines[0].contains("Started") && lines[2].contains("Finished"));
    assert!(lines[1].contains("[INFO] [NESTED]") && lines[1].contains("cmd=unknown"));
    let fields = lines[1].split_once("nested payload ").unwrap().1;
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(fields).unwrap(),
        expected
    );
    assert_eq!(original["a"]["b"][0]["password"], "pw1");
    for artifact in [&machine, &written] {
        assert!(!artifact.contains("pw1"));
        assert!(artifact.contains("keep") && artifact.contains("<redacted>"));
    }
    assert_eq!(std::fs::read_dir(&logs).unwrap().count(), 1);
}

#[test]
fn finish_flushes_syncs_and_closes_the_same_handle_and_refuses_later_writes() {
    let scratch = scratch();
    let logs = scratch.path().join("private");
    let logger = Logger::configured(&logs, 0, 0).unwrap();
    let path = logs.join(logger.name());
    logger
        .write("INFO", "CLOSE", "last owned record", &json!({}))
        .unwrap();
    logger.finish(7).unwrap();
    let before = std::fs::read(&path).unwrap();
    assert!(
        logger
            .write("INFO", "CLOSE", "must not reopen", &json!({}))
            .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let renamed = logs.join("closed.log");
    std::fs::rename(&path, &renamed).unwrap();
    let text = std::fs::read_to_string(renamed).unwrap();
    assert!(text.contains("last owned record") && text.contains("\"exit_code\":7"));
    assert!(!text.contains("must not reopen"));
}
