//! Direct command results survive diagnostics and private-log finalization unchanged.
#![allow(clippy::unwrap_used)]

use std::{cell::Cell, path::Path, sync::Arc};

use clap::Parser;
use serde_json::json;

use super::{args::Cli, auto_account_peer_tests::Capture, context::Context};
use crate::{
    error::Error,
    terminal::{logging::Logger, output::Output},
};

#[test]
fn direct_dispatch_preserves_the_returned_status_and_finalizes_the_same_log_once() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/command-execution");
    std::fs::create_dir_all(&base).unwrap();
    for (label, expected) in [
        ("success", 0),
        ("returned", 7),
        ("invalid", 2),
        ("io", 1),
        ("canceled", 130),
    ] {
        let scratch = tempfile::tempdir_in(&base).unwrap();
        let mut context = Context::test_context(scratch.path());
        let stdout = Capture::default();
        let stderr = Capture::default();
        context.output = Output::with_writers(false, false, stdout.clone(), stderr.clone());
        let logger =
            Arc::new(Logger::configured_for_command(&context.paths.logs, 0, 0, "config").unwrap());
        let path = context.paths.logs.join(logger.name());
        context.output.attach_logger(logger.clone()).unwrap();
        context.logger = Some(logger.clone());
        let command = Cli::try_parse_from(["mb", "config", "show"])
            .unwrap()
            .command
            .unwrap();
        let calls = Cell::new(0);
        let returned =
            super::execute_in_context(&mut context, command, 0, false, |context, command| {
                calls.set(calls.get() + 1);
                assert!(matches!(
                    &command,
                    super::Command::Config(super::args::Config::Show)
                ));
                assert_eq!(super::dispatch(context, command).unwrap(), 0);
                context
                    .output
                    .message("INFO", "Command-result fixture.")
                    .unwrap();
                match label {
                    "success" | "returned" => Ok(expected),
                    "invalid" => Err(Error::invalid("Controlled usage refusal")),
                    "io" => Err(std::io::Error::other("Controlled operational refusal").into()),
                    "canceled" => Err(Error::Canceled),
                    _ => unreachable!(),
                }
            });
        assert_eq!(calls.get(), 1);
        assert_eq!(returned, expected, "{label}");
        let printed = String::from_utf8(stdout.0.lock().unwrap().clone()).unwrap();
        assert!(printed.starts_with("Key | Value\n") && printed.contains("max_workers"));
        assert!(!printed.contains("Command-result fixture") && !printed.contains("[ERROR]"));
        let diagnostic = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
        assert!(diagnostic.starts_with("[INFO] Command-result fixture.\n"));
        if matches!(label, "success" | "returned") {
            assert_eq!(diagnostic, "[INFO] Command-result fixture.\n");
        } else {
            assert_eq!(diagnostic.matches("[ERROR]").count(), 1);
            assert!(diagnostic.contains(match label {
                "invalid" => "Controlled usage refusal",
                "io" => "Controlled operational refusal",
                "canceled" => "The operation was canceled.",
                _ => unreachable!(),
            }));
        }
        let bytes = std::fs::read(&path).unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert_eq!(text.matches("[RUNTIME]").count(), 2);
        assert_eq!(text.matches("Command started").count(), 1);
        assert_eq!(text.matches("Finished").count(), 1);
        assert!(text.contains(&format!("\"exit_code\":{expected}")));
        assert!(text.lines().all(|line| line.contains("cmd=config")));
        assert_eq!(
            text.lines().count(),
            if matches!(label, "success" | "returned") {
                4
            } else {
                5
            }
        );
        assert!(
            logger
                .write("INFO", "CLI", "must stay closed", &json!({}))
                .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert_eq!(std::fs::read_dir(&context.paths.logs).unwrap().count(), 1);
        assert!(!context.paths.config().exists() && !context.paths.accounts().exists());
        assert!(!context.paths.output.exists());
    }
}
