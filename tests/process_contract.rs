#![allow(clippy::unwrap_used)]
use std::{ffi::OsString, io::Write, path::Path, time::Duration};

use megabasterd_cli::{platform::process, transfers::control::Control};

fn child_mode(name: &str) -> bool {
    let args: Vec<_> = std::env::args().collect();
    args.windows(2)
        .any(|pair| pair[0] == "--exact" && pair[1] == name)
}

#[test]
fn child_fixture_close() {
    if child_mode("child_fixture_close") {
        print!("fixture output");
        std::io::stdout().flush().unwrap();
    }
}

#[test]
fn child_fixture_flood() {
    if child_mode("child_fixture_flood") {
        let bytes = vec![b'x'; 8192];
        for _ in 0..256 {
            std::io::stdout().write_all(&bytes).unwrap();
        }
    }
}

#[test]
fn child_fixture_wait() {
    if child_mode("child_fixture_wait") {
        let (_sender, receiver) = std::sync::mpsc::channel::<()>();
        let _ = receiver.recv_timeout(Duration::from_secs(3));
    }
}

fn arguments(mode: &str) -> Vec<OsString> {
    vec![
        "--exact".into(),
        format!("child_fixture_{mode}").into(),
        "--nocapture".into(),
    ]
}

#[test]
fn missing_child_is_reported_without_a_process_or_unbounded_wait() {
    let error = process::run(
        Path::new("missing-native-fixture-program"),
        &[],
        Duration::from_millis(300),
        1024,
        1024,
        &Control::new(),
    )
    .unwrap_err();
    assert_eq!(error.code(), "missing_tool");
}

#[test]
fn executable_returns_real_exit_and_enforces_capture_deadline() {
    let current = std::env::current_exe().unwrap();
    let output = process::run(
        &current,
        &arguments("close"),
        Duration::from_secs(3),
        8192,
        8192,
        &Control::new(),
    )
    .unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("fixture output")
    );
    let flood = process::run(
        &current,
        &arguments("flood"),
        Duration::from_secs(3),
        1024,
        8192,
        &Control::new(),
    );
    assert!(flood.is_err());
    let waiting = process::run(
        &current,
        &arguments("wait"),
        Duration::from_millis(100),
        8192,
        8192,
        &Control::new(),
    )
    .unwrap_err();
    assert_eq!(waiting.code(), "timeout");
}
