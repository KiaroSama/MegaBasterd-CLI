//! Real startup keeps commands usable when private file logging cannot be initialized.
#![allow(clippy::unwrap_used)]

use std::{fs, path::Path};

use clap::Parser;
use serde_json::{Value, json};

use super::{Context, Output, Paths};
use crate::{
    cli::{args::Cli, auto_account_peer_tests::Capture, dispatch},
    storage::files::Store,
};

#[test]
fn startup_uses_the_real_config_and_keeps_commands_usable_after_initial_logging_refusal() {
    let wrapper = include_str!("context.rs")
        .split_once("pub(crate) fn start_for_command(")
        .unwrap()
        .1
        .split_once("pub(crate) fn start_with_output(")
        .unwrap()
        .0;
    assert!(wrapper.contains("Paths::discover()?"));
    assert!(wrapper.contains("Output::new(json, quiet)"));
    assert!(wrapper.contains("Self::start_with_output("));
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/context-startup");
    fs::create_dir_all(&base).unwrap();
    for quiet in [false, true] {
        for logging in [None, Some(true), Some(false)] {
            let scratch = tempfile::tempdir_in(&base).unwrap();
            let paths = Paths {
                root: scratch.path().to_owned(),
                user: scratch.path().join("private user"),
                logs: scratch.path().join("user@example.com-SENTINEL-LOG-TARGET"),
                output: scratch.path().join("output"),
            };
            let blocked = logging == Some(true);
            if blocked {
                fs::write(&paths.logs, b"preserve non-directory log target").unwrap();
            }
            let config_path = paths.config();
            Store::new(&config_path)
                .lock()
                .unwrap()
                .save(&json!({"max_workers":3,"log_to_file":true}))
                .unwrap();
            let before = fs::read(&config_path).unwrap();
            let stdout = Capture::default();
            let stderr = Capture::default();
            let mut context = Context::start_with_output(
                paths.clone(),
                Output::with_writers(false, quiet, stdout.clone(), stderr.clone()),
                logging,
                "config",
            )
            .unwrap();
            assert_eq!(context.config.max_workers, 3);
            assert!(context.config_error.is_none());
            assert_eq!(context.output.quiet, quiet);
            assert!(!context.output.diagnostic_enabled("INFO"));
            assert_eq!(context.logger.is_some(), logging.is_none());
            let command = Cli::try_parse_from(["mb", "config", "get", "max_workers"])
                .unwrap()
                .command
                .unwrap();
            assert_eq!(dispatch(&mut context, command).unwrap(), 0);
            context.finish(0);
            assert_eq!(&*stdout.0.lock().unwrap(), b"3\n");
            assert_eq!(
                &*stderr.0.lock().unwrap(),
                if blocked {
                    b"[WARNING] Private file logging could not be initialized; only console diagnostics are available.\n".as_slice()
                } else {
                    b"".as_slice()
                }
            );
            assert_eq!(fs::read(&config_path).unwrap(), before);
            assert!(!paths.output.exists());
            if blocked {
                assert_eq!(
                    fs::read(&paths.logs).unwrap(),
                    b"preserve non-directory log target"
                );
            } else if let Some(logger) = &context.logger {
                let entries = fs::read_dir(&paths.logs)
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .collect::<Vec<_>>();
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0], paths.logs.join(logger.name()));
                let written = fs::read_to_string(&entries[0]).unwrap();
                assert_eq!(written.lines().count(), 2);
                assert!(written.contains("Started") && written.contains("Finished"));
                assert!(written.contains("cmd=config") && written.contains("\"exit_code\":0"));
                assert!(!written.contains("user@example.com"));
                assert!(!written.contains("SENTINEL-LOG-TARGET"));
                assert!(
                    logger
                        .write("INFO", "LATE", "refuse", &Value::Null)
                        .is_err()
                );
                assert_eq!(fs::read_to_string(&entries[0]).unwrap(), written);
                let directory =
                    crate::platform::secure_files::PrivateDirectory::open(&paths.logs).unwrap();
                let file = directory.open_private(logger.name(), false).unwrap();
                directory.verify_private(&file).unwrap();
            } else {
                assert!(!paths.logs.exists());
            }
            assert_eq!(
                fs::read_dir(scratch.path()).unwrap().count(),
                if logging == Some(false) { 1 } else { 2 }
            );
        }
    }
}
