#![allow(clippy::unwrap_used)]

use megabasterd_cli::terminal::logging::Logger;
use serde_json::json;

fn scratch() -> tempfile::TempDir {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/logging");
    std::fs::create_dir_all(&base).unwrap();
    tempfile::tempdir_in(base).unwrap()
}

#[test]
fn runtime_logs_rotate_only_the_current_run_with_private_utf8_and_retention() {
    let scratch = scratch();
    let logs = scratch.path().join("private logs with spaces");
    let logger = Logger::configured(&logs, 512, 2).unwrap();
    let name = logger.name().to_string_lossy().into_owned();
    assert!(name.starts_with("mb_"));
    assert!(name.ends_with("_UTC.log"));
    let previous = logs.join("older-run.log");
    std::fs::write(&previous, b"preserve previous operational log").unwrap();
    for number in 0..8 {
        logger
            .write(
                "INFO",
                "CONTRACT",
                &format!("record{number} {}", "x".repeat(220)),
                &json!({"password":"synthetic-secret","name":"نام  دو فاصله"}),
            )
            .unwrap();
    }
    logger.finish(7).unwrap();
    drop(logger);
    assert_eq!(
        std::fs::read(previous).unwrap(),
        b"preserve previous operational log"
    );
    assert!(!logs.join(format!("{name}.3")).exists());
    let mut combined = String::new();
    for suffix in ["", ".1", ".2"] {
        let path = logs.join(format!("{name}{suffix}"));
        let bytes = std::fs::read(&path).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.lines().all(|line| line.contains(" UTC] [INFO] [")));
        assert!(!text.contains("synthetic-secret"));
        assert!(text.contains("نام  دو فاصله") || text.contains("Finished"));
        combined.push_str(&text);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
    assert!(combined.contains("record7"));
    assert!(!combined.contains("record0"));
    assert!(combined.contains("\"exit_code\":7"));
}

#[test]
fn zero_limits_disable_rotation_and_each_run_keeps_a_distinct_filename() {
    let scratch = scratch();
    let logs = scratch.path().join("private");
    for (max_bytes, backups) in [(0, 2), (1, 0)] {
        let first = Logger::configured(&logs, max_bytes, backups).unwrap();
        let second = Logger::configured(&logs, max_bytes, backups).unwrap();
        assert_ne!(first.name(), second.name());
        let name = first.name().to_owned();
        std::thread::scope(|scope| {
            for index in 0..2 {
                let logger = &first;
                scope.spawn(move || {
                    for count in 0..4 {
                        logger
                            .write(
                                "DEBUG",
                                "WORKER",
                                "progress",
                                &json!({"worker":index,"count":count}),
                            )
                            .unwrap();
                    }
                });
            }
        });
        first.finish(0).unwrap();
        second.finish(0).unwrap();
        drop(first);
        drop(second);
        let text = std::fs::read_to_string(logs.join(&name)).unwrap();
        assert_eq!(text.matches("[DEBUG] [WORKER]").count(), 8);
        assert!(!logs.join(format!("{}.1", name.to_string_lossy())).exists());
    }
}

#[test]
fn filtered_console_diagnostics_still_reach_the_shared_file_log_once() {
    use megabasterd_cli::terminal::output::Output;
    let scratch = scratch();
    let logs = scratch.path().join("private");
    let logger = std::sync::Arc::new(Logger::configured(&logs, 0, 0).unwrap());
    let name = logger.name().to_owned();
    let output = Output::new(false, true);
    output.attach_logger(logger.clone()).unwrap();
    output.diagnostic("DEBUG", "filtered-debug-record").unwrap();
    output.message("INFO", "quiet-command-record").unwrap();
    output
        .message("WARNING", "password=synthetic-secret")
        .unwrap();
    output
        .message("INFO", "Refreshing account bob@example.net")
        .unwrap();
    logger.write("ERROR", "CONTRACT", "ValueError: bad login for carol@example.com", &json!({
        "account":"alice.smith@example.com", "nested":{"user":"me@example.org","k":"synthetic-wrapped-key"},
        "source":"https://mega.nz/file/ABC#SYNTHETICKEY"
    })).unwrap();
    assert!(output.attach_logger(logger.clone()).is_err());
    logger.finish(7).unwrap();
    drop(output);
    drop(logger);
    let text = std::fs::read_to_string(logs.join(name)).unwrap();
    assert_eq!(text.matches("filtered-debug-record").count(), 1);
    assert_eq!(text.matches("quiet-command-record").count(), 1);
    assert!(!text.contains("synthetic-secret"));
    assert!(text.contains("[WARNING] [OUTPUT]"));
    for private in [
        "bob@example.net",
        "carol@example.com",
        "alice.smith@example.com",
        "me@example.org",
        "synthetic-wrapped-key",
        "SYNTHETICKEY",
    ] {
        assert!(!text.contains(private));
    }
    assert!(text.contains("<redacted-email>") && text.contains("<redacted-url>"));
    assert!(text.contains("ValueError: bad login"));
    assert!(text.contains("\"exit_code\":7"));
}

#[test]
fn unsafe_rotation_target_disables_file_writes_without_overwriting_it() {
    let scratch = scratch();
    let logs = scratch.path().join("private");
    let logger = Logger::configured(&logs, 512, 2).unwrap();
    let blocked = logs.join(format!("{}.1", logger.name().to_string_lossy()));
    std::fs::create_dir(&blocked).unwrap();
    let sentinel = blocked.join("keep.txt");
    std::fs::write(&sentinel, b"keep\n").unwrap();
    let primary = logs.join(logger.name());
    let before = std::fs::read(&primary).unwrap();
    assert!(
        logger
            .write("ERROR", "CONTRACT", &"x".repeat(600), &json!({}))
            .is_err()
    );
    assert!(blocked.is_dir());
    assert!(
        logger
            .write("ERROR", "CONTRACT", "must stay disabled", &json!({}))
            .is_err()
    );
    assert!(logger.finish(1).is_err());
    assert_eq!(std::fs::read(&primary).unwrap(), before);
    assert_eq!(std::fs::read(&sentinel).unwrap(), b"keep\n");
    assert_eq!(std::fs::read_dir(&blocked).unwrap().count(), 1);
    assert_eq!(std::fs::read_dir(&logs).unwrap().count(), 2);
    assert!(
        !std::fs::read_to_string(primary)
            .unwrap()
            .contains("must stay disabled")
    );
}
