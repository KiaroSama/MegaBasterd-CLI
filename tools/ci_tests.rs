use super::*;
use std::time::Duration;

#[test]
fn release_source_packaging_refuses_dirty_inputs_and_leaves_no_root_diagnostic() {
    let driver = include_str!("ci.rs");
    assert!(!driver.contains(concat!("--allow", "-dirty")));
    let workflow = include_str!("../.github/workflows/ci.yml");
    assert!(!workflow.contains("tee rust-version.txt"));
    assert!(workflow.contains("rustc -vV\n"));
}

#[test]
fn bounded_child_fixture() {
    match std::env::var("MB_CI_FIXTURE_MODE").as_deref() {
        Ok("success") => {
            println!("bounded fixture stdout");
            eprintln!("bounded fixture stderr");
        }
        Ok("failure") => std::process::exit(7),
        Ok("wait") => {
            let (_sender, receiver) = std::sync::mpsc::channel::<()>();
            let _ = receiver.recv_timeout(Duration::from_secs(5));
        }
        _ => (),
    }
}

#[test]
fn harness_owner_preserves_streams_exit_and_rejects_expired_children() {
    let command = |mode: &str| {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "tests::bounded_child_fixture", "--nocapture"])
            .env("MB_CI_FIXTURE_MODE", mode);
        command
    };
    let success = test_output(command("success"), Duration::from_secs(5)).unwrap();
    assert!(success.status.success());
    assert!(
        String::from_utf8(success.stdout)
            .unwrap()
            .contains("bounded fixture stdout")
    );
    assert!(
        String::from_utf8(success.stderr)
            .unwrap()
            .contains("bounded fixture stderr")
    );
    let failure = test_output(command("failure"), Duration::from_secs(5)).unwrap();
    assert_eq!(failure.status.code(), Some(7));
    let expired = test_output(command("wait"), Duration::from_millis(100)).unwrap_err();
    assert_eq!(
        expired
            .downcast_ref::<megabasterd_cli::error::Error>()
            .unwrap()
            .code(),
        "timeout"
    );
}
