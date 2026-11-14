#![allow(clippy::unwrap_used)]

use super::*;
use crate::{
    error::Error,
    platform::process,
    terminal::{logging::Logger, output::Output},
    transfers::control::Control,
};
use std::{
    fs,
    path::Path,
    process::Command,
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);
impl std::io::Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let mut output = self.0.lock().unwrap();
        if bytes.len() > (16 * 1024usize).saturating_sub(output.len()) {
            return Err(std::io::Error::other(
                "Panic fixture output exceeds its bound",
            ));
        }
        output.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

const CHILD: &str = "MB_PANIC_CAPTURE_CHILD";
const TEST: &str = "terminal::panic_report::tests::actual_panics_keep_sanitized_origin_and_trace_only_in_the_private_log";

#[test]
fn actual_panics_keep_sanitized_origin_and_trace_only_in_the_private_log() {
    if let Some(directory) = std::env::var_os(CHILD) {
        install();
        let directory = std::path::PathBuf::from(directory);
        let logger = Arc::new(Logger::configured(&directory, 0, 0).unwrap());
        let path = directory.join(logger.name());
        let stdout = Capture::default();
        let stderr = Capture::default();
        let output = Output::with_writers(true, true, stdout.clone(), stderr.clone());
        output.attach_logger(logger.clone()).unwrap();
        assert_eq!(catch(|| 7).unwrap(), 7);
        for mode in ["text", "opaque", "oversized"] {
            let failure = catch(|| match mode {
                "text" => panic!("transfer failed: proxy auth failed for http://alice:hunter2@1.2.3.4:8080 (password: swordfish); password: SENTINELTRACEBACK"),
                "opaque" => panic::panic_any(41u8),
                _ => panic::panic_any(format!("password: {}", "SENTINEL_OVERSIZED".repeat(300))),
            }).unwrap_err();
            for secret in [
                "hunter2",
                "swordfish",
                "SENTINELTRACEBACK",
                "SENTINEL_OVERSIZED",
            ] {
                assert!(!failure.contains(secret));
            }
            assert!(failure.starts_with("Unexpected native panic: "));
            assert!(failure.contains("panic_report_tests.rs:"));
            assert!(failure.contains("Backtrace status=Captured:"));
            let trace = failure.split_once("Backtrace status=Captured:").unwrap().1;
            assert!(!trace.trim().is_empty() && trace.contains("0:"));
            assert!(
                !failure.contains("unsupported backtrace")
                    && !failure.contains("disabled backtrace")
            );
            if mode == "text" {
                assert!(
                    failure.contains("transfer failed") && failure.contains("proxy auth failed")
                );
                assert!(failure.contains("<redacted>"));
            } else if mode == "opaque" {
                assert!(failure.contains("Non-string panic payload"));
            } else {
                assert!(failure.contains("text exceeds the capture bound"));
            }
            record(&failure, Some(&logger), &output);
            output.error(&Error::Unexpected).unwrap();
        }
        // A locally handled panic must not survive into the next escaping panic.
        assert_eq!(
            catch(|| {
                let _ = panic::catch_unwind(|| panic!("already handled locally"));
                11
            })
            .unwrap(),
            11
        );
        let nested = catch(|| {
            assert!(
                catch(|| panic!("inner diagnostic"))
                    .unwrap_err()
                    .contains("inner diagnostic")
            );
            panic!("outer diagnostic");
        })
        .unwrap_err();
        assert!(nested.contains("outer diagnostic") && !nested.contains("inner diagnostic"));
        let fresh = catch(|| panic!("fresh diagnostic")).unwrap_err();
        assert!(fresh.contains("fresh diagnostic") && !fresh.contains("already handled locally"));
        logger.finish(1).unwrap();
        let bytes = fs::read_to_string(path).unwrap();
        assert_eq!(bytes.matches("Unexpected native panic:").count(), 3);
        assert_eq!(bytes.matches("Backtrace status=Captured:").count(), 3);
        assert!(bytes.contains("transfer failed") && bytes.contains("proxy auth failed"));
        assert!(bytes.contains("panic_report_tests.rs:"));
        let machine = String::from_utf8(stdout.0.lock().unwrap().clone()).unwrap();
        let console = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
        assert_eq!(machine.lines().count(), 3);
        assert_eq!(console.lines().count(), 3);
        for line in machine.lines() {
            let value: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(value["error_code"], "error");
            assert_eq!(value["status"], "failed");
            assert_eq!(value["error"], Error::Unexpected.to_string());
        }
        assert_eq!(
            console,
            format!("[ERROR] {}\n", Error::Unexpected).repeat(3)
        );
        for secret in [
            "hunter2",
            "swordfish",
            "SENTINELTRACEBACK",
            "SENTINEL_OVERSIZED",
        ] {
            assert!(!machine.contains(secret) && !console.contains(secret));
            assert!(!bytes.contains(secret));
        }
        assert!(CAPTURE.with(|capture| capture.borrow().is_none()));
        let mut limit = BoundedText(Zeroizing::new(String::new()));
        assert!(fmt::Write::write_str(&mut limit, &"x".repeat(MAX_TRACE + 1)).is_err());
        assert!(limit.0.is_empty());
        return;
    }
    let main = include_str!("../main.rs");
    assert!(main.contains("megabasterd_cli::terminal::panic_report::install();"));
    let cli = include_str!("../cli/mod.rs");
    assert!(cli.contains("panic_report::catch(|| dispatch(context, command))"));
    assert!(cli.contains("panic_report::record("));
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/panic-capture");
    fs::create_dir_all(&base).unwrap();
    let scratch = crate::test_support::tempdir_in(base).unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.env_clear().current_dir(scratch.path());
    for key in [
        "LLVM_PROFILE_FILE",
        "PATH",
        "SystemRoot",
        "WINDIR",
        "PATHEXT",
        "LD_LIBRARY_PATH",
        "DYLD_LIBRARY_PATH",
    ] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    for key in [
        "HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "TMP",
        "TEMP",
        "TMPDIR",
    ] {
        command.env(key, scratch.path());
    }
    command
        .env(CHILD, scratch.path().join("private logs with spaces"))
        .env("HOOKMAKER_MAX_TEST_WORKERS", "1")
        .args(["--exact", TEST, "--test-threads=1"]);
    let result = process::run_command(
        command,
        Duration::from_secs(10),
        16 * 1024,
        16 * 1024,
        &Control::new(),
        None,
    )
    .unwrap();
    assert_eq!(result.status.code(), Some(0));
    assert!(result.stderr.is_empty());
    let stdout = String::from_utf8(result.stdout).unwrap();
    assert!(
        stdout.contains("1 passed") && stdout.contains("0 failed") && stdout.contains("0 ignored")
    );
    for secret in [
        "hunter2",
        "swordfish",
        "SENTINELTRACEBACK",
        "SENTINEL_OVERSIZED",
    ] {
        assert!(!stdout.contains(secret));
    }
}
