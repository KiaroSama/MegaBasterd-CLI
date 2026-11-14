#![allow(clippy::unwrap_used)]

use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use megabasterd_cli::{error::Error, terminal::output::Output};
use serde_json::{Value, json};

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut output = self.0.lock().unwrap();
        if bytes.len() > (128 * 1024usize).saturating_sub(output.len()) {
            return Err(io::Error::other("Fixture output bound exceeded"));
        }
        output.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn concurrent_json_records_are_atomic_sanitized_and_keep_explicit_public_links() {
    let capture = Capture::default();
    let output = Output::with_writer(true, true, capture.clone());
    std::thread::scope(|scope| {
        for worker in 0..2 {
            let output = &output;
            scope.spawn(move || {
                for index in 0..30 {
                    let number = worker * 30 + index;
                    output
                        .record(&json!({"event":"result","n":number,
                        "status":if number % 2 == 0 {"success"} else {"failed"},
                        "blob":"x".repeat(500), "name":"نام  دو فاصله",
                        "detail":if number % 2 == 0 {"f".repeat(100)} else {"boom ".repeat(100)},
                        "error":"failed https://mega.nz/file/ABC#SYNTHETICKEY",
                        "details":{"api_key":"synthetic-secret","sid":"synthetic-session",
                            "accounts":{"host.example":{"user":"u","api_key":"TOPSECRET"}},
                            "links":["https://mega.nz/file/X#NESTEDKEY"]},
                        "vault_passphrase":"pw",
                        "query":"GET /x?password=hunter2&token=abc123 failed",
                        "wrapper":"mega://elc/token#KEYMATERIAL",
                        "share_link":"https://mega.nz/file/H#PUBLICKEY"}))
                        .unwrap();
                }
            });
        }
    });
    let bytes = capture.0.lock().unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    assert!(text.ends_with('\n'));
    assert!(!text.contains("SYNTHETICKEY"));
    for secret in [
        "synthetic-secret",
        "synthetic-session",
        "TOPSECRET",
        "NESTEDKEY",
        "KEYMATERIAL",
        "hunter2",
        "abc123",
    ] {
        assert!(!text.contains(secret));
    }
    let records: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records.len(), 60);
    let mut seen: Vec<u64> = records
        .iter()
        .map(|record| record["n"].as_u64().unwrap())
        .collect();
    seen.sort_unstable();
    assert_eq!(seen, (0..60).collect::<Vec<_>>());
    for record in records {
        assert_eq!(
            record["status"],
            if record["n"].as_u64().unwrap() % 2 == 0 {
                "success"
            } else {
                "failed"
            }
        );
        assert_eq!(record["blob"].as_str().unwrap().len(), 500);
        assert_eq!(
            record["detail"],
            if record["n"].as_u64().unwrap() % 2 == 0 {
                "f".repeat(100)
            } else {
                "boom ".repeat(100)
            }
        );
        assert_eq!(record["name"], "نام  دو فاصله");
        assert_eq!(record["details"]["api_key"], "<redacted>");
        assert_eq!(record["details"]["sid"], "<redacted>");
        assert_eq!(
            record["details"]["accounts"]["host.example"]["api_key"],
            "<redacted>"
        );
        assert_eq!(record["details"]["accounts"]["host.example"]["user"], "u");
        assert_eq!(
            record["details"]["links"][0],
            "https://mega.nz/file/X#<key>"
        );
        assert_eq!(record["vault_passphrase"], "<redacted>");
        assert!(
            record["query"]
                .as_str()
                .unwrap()
                .contains("password=<redacted>")
        );
        assert_eq!(record["wrapper"], "mega://elc/token#<key>");
        assert!(record["error"].as_str().unwrap().ends_with("#<key>"));
        assert_eq!(record["share_link"], "https://mega.nz/file/H#PUBLICKEY");
    }
}

#[test]
fn failed_human_sink_cannot_suppress_machine_failure_and_the_reverse_still_reports() {
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Controlled closed pipe",
            ))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let machine = Capture::default();
    let output = Output::with_writers(true, false, machine.clone(), Broken);
    assert!(
        output
            .error(&Error::transfer(Error::protocol("CDN framing rejected")))
            .is_err()
    );
    let bytes = machine.0.lock().unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    let records: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["status"], "failed");
    assert_eq!(records[0]["error_code"], "transfer_failed");
    assert!(!text.contains("[ERROR]"));
    let human = Capture::default();
    let output = Output::with_writers(true, false, Broken, human.clone());
    assert!(
        output
            .error(&Error::invalid("controlled usage failure"))
            .is_err()
    );
    let bytes = human.0.lock().unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    assert!(text.contains("[ERROR] Invalid input: controlled usage failure"));
    assert!(!text.contains("\"event\""));
}

#[test]
fn disabled_records_do_not_write_and_serialization_failures_are_not_success() {
    let capture = Capture::default();
    Output::with_writer(false, false, capture.clone())
        .record(&json!({"status":"success"}))
        .unwrap();
    assert!(capture.0.lock().unwrap().is_empty());

    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Controlled closed pipe",
            ))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let error = Output::with_writer(true, false, Broken)
        .record(&json!({"event":"result"}))
        .unwrap_err();
    assert_eq!(error.exit_code(), 1);
    assert!(matches!(error, Error::Json(_) | Error::Io(_)));
}

#[test]
fn original_digest_and_nested_exception_records_are_scrubbed_by_the_actual_machine_writer() {
    let capture = Capture::default();
    let output = Output::with_writers(true, false, capture.clone(), Vec::new());
    let digest = concat!(
        "Authorization: Digest username=\"alice\", realm=\"mega\", ",
        "nonce=\"dcd98b7102dd2f0e10a3\", uri=\"/api\", ",
        "response=\"6629fae49393a05397450978507c4ef1\", ",
        "opaque=\"5ccc069c403ebaf9f0171e9517f40e41\", qop=auth, ",
        "nc=00000001, cnonce=\"0a4f113b8fa5\""
    );
    output
        .record(&json!({"event":"result","status":"failed","error":digest,
            "detail":{"cause":["password: nested-fake"]}}))
        .unwrap();
    let bytes = capture.0.lock().unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    assert_eq!(text.lines().count(), 1);
    let record: Value = serde_json::from_str(text).unwrap();
    assert_eq!(record["status"], "failed");
    assert_eq!(record["error"], "Authorization: <redacted>");
    assert_eq!(record["detail"]["cause"][0], "password: <redacted>");
    for secret in [
        "dcd98b7102dd2f0e10a3",
        "6629fae49393a05397450978507c4ef1",
        "5ccc069c403ebaf9f0171e9517f40e41",
        "0a4f113b8fa5",
        "nested-fake",
    ] {
        assert!(!text.contains(secret));
    }
}

#[test]
fn error_boundary_masks_secret_bearing_diagnostics_on_both_channels() {
    let machine = Capture::default();
    let human = Capture::default();
    let output = Output::with_writers(true, false, machine.clone(), human.clone());
    output
        .error(&Error::invalid(
            "request failed for https://mega.nz/file/ABCD1234#SYNTHETICKEY; password: fake-value",
        ))
        .unwrap();
    let bytes = machine.0.lock().unwrap();
    let machine = std::str::from_utf8(&bytes).unwrap();
    assert_eq!(machine.lines().count(), 1);
    let record: Value = serde_json::from_str(machine).unwrap();
    assert_eq!(record["status"], "failed");
    assert_eq!(record["error_code"], "invalid_input");
    assert_eq!(
        record["error"],
        "Invalid input: request failed for https://mega.nz/file/ABCD1234#<key> password: <redacted>"
    );
    let bytes = human.0.lock().unwrap();
    let human = std::str::from_utf8(&bytes).unwrap();
    assert_eq!(
        human,
        "[ERROR] Invalid input: request failed for https://mega.nz/file/ABCD1234#<key> password: <redacted>\n"
    );
    for surface in [machine, human] {
        assert!(!surface.contains("SYNTHETICKEY") && !surface.contains("fake-value"));
    }
}
