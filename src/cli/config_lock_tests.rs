//! Parsed config mutations report real lock contention without success text or partial writes.
#![allow(clippy::unwrap_used)]

use std::{
    fs,
    io::{self, Cursor, Write},
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use clap::Parser;

use super::{
    args::{Cli, Command},
    config,
    context::Context,
};
use crate::{
    error::Error,
    storage::files::Store,
    terminal::{output::Output, prompts},
};

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut output = self.0.lock().unwrap();
        if bytes.len() > (16 * 1024usize).saturating_sub(output.len()) {
            return Err(io::Error::other(
                "Config lock fixture output bound exceeded",
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
fn parsed_config_mutations_report_busy_after_required_confirmation_without_changing_saved_bytes() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/config-lock-cli");
    fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    let mut context = Context::test_context(scratch.path());
    context.config_store.set("max_workers", "7").unwrap();
    context
        .config_store
        .set("connect_proxy_password", "synthetic-lock-secret")
        .unwrap();
    context.config = context.config_store.load().unwrap().0;
    context.config_store = context.config_store.with_test_lock_timeout(Duration::ZERO);
    let owner = Store::new(context.paths.config()).lock().unwrap();
    let before = fs::read(context.paths.config()).unwrap();
    for words in [
        vec!["set", "max_workers", "4"],
        vec!["set", "log_backups", "3"],
        vec!["unset", "default_account"],
        vec!["migrate"],
        vec!["reset"],
        vec!["recover"],
        vec!["recover", "--reset"],
    ] {
        let stdout = Capture::default();
        let stderr = Capture::default();
        context.output = Output::with_writers(false, false, stdout.clone(), stderr.clone());
        let cli =
            Cli::try_parse_from(["mb", "config"].into_iter().chain(words.iter().copied())).unwrap();
        let Some(Command::Config(command)) = cli.command else {
            panic!("Config fixture did not parse a config command");
        };
        let expected_question = match words.as_slice() {
            ["reset"] => Some("Reset configuration to defaults?"),
            ["recover", "--reset"] => {
                Some("Preserve the damaged configuration and reset to defaults?")
            }
            _ => None,
        };
        let mut confirmations = 0;
        let mut input = Cursor::new(b"y\n");
        let mut prompt = Vec::new();
        let error = config::dispatch_with_confirmation(&context, command, |question, default| {
            assert_eq!(Some(question), expected_question);
            assert!(!default);
            confirmations += 1;
            prompts::confirmed_with_io(question, default, &mut input, &mut prompt)
        })
        .unwrap_err();
        assert_eq!(confirmations, usize::from(expected_question.is_some()));
        assert_eq!(
            input.position(),
            if expected_question.is_some() { 2 } else { 0 }
        );
        assert!(matches!(error, Error::Busy(_)), "{words:?}");
        assert_eq!(error.exit_code(), 1);
        assert_eq!(error.code(), "resource_busy");
        context.report_error(&error);
        assert!(stdout.0.lock().unwrap().is_empty());
        let diagnostic = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
        assert!(diagnostic.contains("[ERROR]"));
        assert!(diagnostic.contains("retry when the other operation finishes"));
        for forbidden in [
            "synthetic-lock-secret",
            "Traceback",
            "panicked at",
            "Configuration setting saved.",
            "Configuration setting unset.",
            "reset to defaults.",
            "defaults restored.",
            "normalized;",
            "no recovery needed.",
        ] {
            assert!(
                !diagnostic.contains(forbidden),
                "Unsafe or false-success lock diagnostic"
            );
        }
        assert_eq!(fs::read(context.paths.config()).unwrap(), before);
        let mut names: Vec<_> = fs::read_dir(context.paths.config().parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        names.sort();
        assert_eq!(
            names,
            ["config.json", "config.json.lock"].map(std::ffi::OsString::from)
        );
        assert!(!context.paths.logs.exists());
        assert!(!context.paths.output.exists());
        assert!(!context.paths.user.join("Data").exists());
    }
    drop(owner);
    let command = Cli::try_parse_from(["mb", "config", "set", "max_workers", "9"])
        .unwrap()
        .command
        .unwrap();
    assert_eq!(super::dispatch(&mut context, command).unwrap(), 0);
    let (settings, warnings) = context.config_store.load().unwrap();
    assert_eq!(settings.max_workers, 9);
    assert_eq!(
        settings.connect_proxy_password.as_deref(),
        Some("synthetic-lock-secret")
    );
    assert!(warnings.is_empty());
}
