#![allow(clippy::unwrap_used)]

use std::{collections::VecDeque, ffi::OsString, path::Path};

use clap::{CommandFactory, Parser};
use zeroize::Zeroizing;

use super::{ACCOUNTS, MAIN, QUEUE, SETTINGS, TOOLS, run_with};
use crate::{
    cli::{args::Cli, auto_account_peer_tests::Capture},
    terminal::output::Output,
};

fn flow(lines: &[&str], status: i32) -> (Vec<Vec<OsString>>, String) {
    let mut lines: VecDeque<_> = lines.iter().map(|line| (*line).to_owned()).collect();
    let stdout = Capture::default();
    let stderr = Capture::default();
    let output = Output::with_writers(false, false, stdout.clone(), stderr.clone());
    let mut calls = Vec::new();
    run_with(
        &output,
        Path::new("output"),
        |_, _| Ok(lines.pop_front().map(Zeroizing::new)),
        |arguments| {
            Cli::try_parse_from(arguments.clone()).unwrap();
            calls.push(arguments);
            status
        },
    )
    .unwrap();
    assert!(lines.is_empty(), "menu left expected input unread");
    assert!(stdout.0.lock().unwrap().is_empty());
    let rendered = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
    (calls, rendered)
}

#[test]
fn menu_lifecycle_keeps_private_logs_and_forwards_root_flags_without_recording_arguments() {
    use std::sync::Arc;

    use crate::{cli::context::Context, terminal::logging::Logger};

    let entry = include_str!("mod.rs");
    assert!(entry.contains("if cli.command.is_none() {\n        return menu::run(cli);\n    }"));
    let menu = include_str!("menu.rs");
    let startup = menu
        .split_once("pub fn run(")
        .unwrap()
        .1
        .split_once("fn run_in_context(")
        .unwrap()
        .0;
    assert!(startup.contains("Context::start_for_command(false, false, logging, \"menu\")"));
    assert!(startup.contains("run_in_context(\n        &context,\n        &cli,"));
    assert!(startup.contains("Some(false)") && startup.contains("Some(true)"));
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/menu-flow");
    std::fs::create_dir_all(&base).unwrap();
    for logging in [false, true] {
        let scratch = crate::test_support::tempdir_in(&base).unwrap();
        let mut context = Context::test_context(scratch.path());
        let stdout = Capture::default();
        let stderr = Capture::default();
        context.output = Output::with_writers(false, false, stdout.clone(), stderr.clone());
        let log_path = if logging {
            let logger = Arc::new(
                Logger::configured_for_command(&context.paths.logs, 0, 0, "menu").unwrap(),
            );
            let path = context.paths.logs.join(logger.name());
            context.output.attach_logger(logger.clone()).unwrap();
            context.logger = Some(logger);
            Some(path)
        } else {
            None
        };
        let cli = Cli::try_parse_from([
            "mb",
            "-vv",
            "-q",
            if logging {
                "--log-file"
            } else {
                "--no-log-file"
            },
        ])
        .unwrap();
        let override_command = if logging {
            "-v --no-log-file config show"
        } else {
            "-v --log-file config show"
        };
        let mut answers = VecDeque::from([
            "99",
            "8",
            "info https://mega.nz/file/ID#KEY --password SENTINELMENU",
            "8",
            override_command,
            "exit",
        ]);
        let mut calls = 0;
        let result = super::run_in_context(
            &context,
            &cli,
            |_, secret| {
                assert!(!secret);
                Ok(answers
                    .pop_front()
                    .map(|value| Zeroizing::new(value.to_owned())))
            },
            |arguments| {
                calls += 1;
                let mut expected = vec![
                    "mb",
                    "-q",
                    "-vv",
                    if logging {
                        "--log-file"
                    } else {
                        "--no-log-file"
                    },
                ];
                expected.extend(if calls == 1 {
                    vec![
                        "info",
                        "https://mega.nz/file/ID#KEY",
                        "--password",
                        "SENTINELMENU",
                    ]
                } else {
                    vec![
                        "-v",
                        if logging {
                            "--no-log-file"
                        } else {
                            "--log-file"
                        },
                        "config",
                        "show",
                    ]
                });
                assert_eq!(
                    arguments,
                    expected.into_iter().map(OsString::from).collect::<Vec<_>>()
                );
                let parsed = Cli::try_parse_from(arguments).unwrap();
                assert!(parsed.quiet);
                assert_eq!(parsed.verbose, if calls == 1 { 2 } else { 3 });
                let enabled = if calls == 1 { logging } else { !logging };
                assert_eq!(parsed.log_file, enabled);
                assert_eq!(parsed.no_log_file, !enabled);
                7
            },
        );
        result.unwrap();
        assert_eq!(calls, 2);
        assert!(answers.is_empty());
        assert!(stdout.0.lock().unwrap().is_empty());
        let rendered = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
        assert!(rendered.contains("Main menu") && rendered.contains("exit code 7"));
        assert!(!rendered.contains("SENTINELMENU") && !rendered.contains("ID#KEY"));
        if let Some(path) = log_path {
            let text = std::fs::read_to_string(&path).unwrap();
            for retained in [
                "cmd=menu",
                "[MENU]",
                "Menu started",
                "Invalid selection",
                "exit code 7",
                "Finished",
                "\"exit_code\":0",
            ] {
                assert!(
                    text.contains(retained),
                    "missing menu log context: {retained}"
                );
            }
            for secret in ["SENTINELMENU", "ID#KEY", "https://mega.nz"] {
                assert!(!text.contains(secret));
            }
            let directory =
                crate::platform::secure_files::PrivateDirectory::open(&context.paths.logs).unwrap();
            let file = directory
                .open_private(path.file_name().unwrap(), false)
                .unwrap();
            directory.verify_private(&file).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    file.metadata().unwrap().permissions().mode() & 0o7777,
                    0o600
                );
            }
            assert!(
                context
                    .logger
                    .as_ref()
                    .unwrap()
                    .write("INFO", "MENU", "after finish", &serde_json::json!({}))
                    .is_err()
            );
            assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
            assert_eq!(std::fs::read_dir(&context.paths.logs).unwrap().count(), 1);
        } else {
            assert!(!context.paths.logs.exists());
        }
        assert!(!context.paths.config().exists() && !context.paths.accounts().exists());
        assert!(!context.paths.output.exists());
    }
}

#[test]
fn menu_eof_errors_and_unwinds_finalize_once_and_seal_the_same_log() {
    use crate::{cli::context::Context, error::Error, terminal::logging::Logger};
    use std::sync::Arc;

    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/menu-flow");
    std::fs::create_dir_all(&base).unwrap();
    for mode in [
        "eof",
        "error",
        "canceled",
        "reader_unwind",
        "dispatch_unwind",
    ] {
        let scratch = crate::test_support::tempdir_in(&base).unwrap();
        let mut context = Context::test_context(scratch.path());
        let stdout = Capture::default();
        let stderr = Capture::default();
        context.output = Output::with_writers(false, false, stdout.clone(), stderr.clone());
        let logger =
            Arc::new(Logger::configured_for_command(&context.paths.logs, 0, 0, "menu").unwrap());
        let path = context.paths.logs.join(logger.name());
        context.output.attach_logger(logger.clone()).unwrap();
        context.logger = Some(logger.clone());
        let cli = Cli::try_parse_from(["mb", "-v"]).unwrap();
        let mut reads = 0;
        let mut dispatches = 0;
        let result = super::run_in_context(
            &context,
            &cli,
            |_, _| {
                reads += 1;
                assert!(reads <= 2);
                match mode {
                    "eof" => Ok(None),
                    "error" => Err(Error::invalid("menu reader failed")),
                    "canceled" => Err(Error::Canceled),
                    "reader_unwind" => std::panic::resume_unwind(Box::new("SENTINELMENUUNWIND")),
                    _ => Ok(Some(Zeroizing::new(
                        if reads == 1 { "8" } else { "config show" }.to_owned(),
                    ))),
                }
            },
            |_| {
                dispatches += 1;
                std::panic::resume_unwind(Box::new("SENTINELMENUDISPATCH"))
            },
        );
        let code = match mode {
            "eof" => {
                result.unwrap();
                0
            }
            "error" => {
                let error = result.unwrap_err();
                assert!(
                    matches!(&error, Error::Invalid(message) if message == "menu reader failed")
                );
                assert_eq!(error.exit_code(), 2);
                2
            }
            "canceled" => {
                let error = result.unwrap_err();
                assert!(matches!(error, Error::Canceled));
                assert_eq!(error.exit_code(), 130);
                130
            }
            _ => {
                let error = result.unwrap_err();
                assert!(matches!(error, Error::Unexpected));
                assert_eq!(error.exit_code(), 1);
                1
            }
        };
        assert_eq!(dispatches, usize::from(mode == "dispatch_unwind"));
        assert_eq!(reads, if mode == "dispatch_unwind" { 2 } else { 1 });
        assert!(context.output.diagnostic_enabled("INFO"));
        assert!(!context.output.diagnostic_enabled("DEBUG"));
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.matches("Finished").count(), 1);
        assert!(text.contains(&format!("\"exit_code\":{code}")));
        assert_eq!(
            text.matches("[PANIC]").count(),
            usize::from(mode.ends_with("unwind"))
        );
        let console = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
        for secret in ["SENTINELMENUUNWIND", "SENTINELMENUDISPATCH"] {
            assert!(!text.contains(secret) && !console.contains(secret));
        }
        assert!(stdout.0.lock().unwrap().is_empty());
        assert!(
            logger
                .write("INFO", "MENU", "after finish", &serde_json::json!({}))
                .is_err()
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
        assert_eq!(std::fs::read_dir(&context.paths.logs).unwrap().count(), 1);
    }
}

#[test]
fn canceled_menu_input_never_dispatches_a_late_answer_and_preserves_other_read_errors() {
    use crate::{error::Error, transfers::control::Control};

    let control = Control::new();
    control.cancel();
    assert!(matches!(
        super::read_with_control(&control, "Selection:", false, |_, _| {
            panic!("canceled menu read reached input")
        }),
        Err(Error::Canceled)
    ));
    let control = Control::new();
    assert!(matches!(
        super::read_with_control(&control, "Selection:", false, |_, _| {
            control.cancel();
            Ok(Some(Zeroizing::new("config reset".into())))
        }),
        Err(Error::Canceled)
    ));
    for kind in [
        std::io::ErrorKind::Interrupted,
        std::io::ErrorKind::UnexpectedEof,
        std::io::ErrorKind::BrokenPipe,
    ] {
        let control = Control::new();
        let result = super::read_with_control(&control, "Secret:", true, |question, secret| {
            assert!(secret && question == "Secret:");
            Err(Error::Io(std::io::Error::new(
                kind,
                "controlled read failure",
            )))
        });
        if kind == std::io::ErrorKind::UnexpectedEof {
            assert!(result.unwrap().is_none());
            assert!(!control.is_canceled());
            continue;
        }
        let error = result.unwrap_err();
        if kind == std::io::ErrorKind::Interrupted {
            assert!(matches!(error, Error::Canceled));
            assert!(control.is_canceled());
        } else {
            assert!(matches!(error, Error::Io(error) if error.kind() == kind));
            assert!(!control.is_canceled());
        }
    }
    let control = Control::new();
    assert!(
        super::read_with_control(&control, "Selection:", false, |_, _| Ok(None))
            .unwrap()
            .is_none()
    );
    #[cfg(windows)]
    assert!(matches!(
        super::read_with_control(&control, "Selection:", false, |_, _| {
            Err(Error::Io(std::io::Error::from_raw_os_error(995)))
        }),
        Err(Error::Canceled)
    ));
}

#[test]
fn every_menu_entry_has_a_label_and_resolves_to_a_real_command_prefix() {
    assert!(!MAIN.is_empty());
    assert!(MAIN.iter().all(|label| !label.trim().is_empty()));
    let mut schema = Cli::command();
    schema.build();
    for group in [ACCOUNTS, QUEUE, TOOLS, SETTINGS] {
        assert!(!group.is_empty());
        for entry in group {
            assert!(!entry.label.trim().is_empty());
            assert!(!entry.command.is_empty());
            let mut command = &schema;
            for (index, word) in entry.command.iter().enumerate() {
                assert!(!word.is_empty());
                if let Some(subcommand) = command.find_subcommand(word) {
                    command = subcommand;
                } else {
                    assert_eq!(&entry.command[..index], ["config", "set"]);
                    assert_eq!(index + 1, entry.command.len());
                    assert!(command.get_arguments().any(|argument| {
                        argument.get_id() == "key" && argument.get_index() == Some(1)
                    }));
                }
            }
            if !entry.arguments {
                Cli::try_parse_from(std::iter::once("mb").chain(entry.command.iter().copied()))
                    .unwrap();
            }
        }
    }
}

#[test]
fn main_info_and_advanced_choices_preserve_source_indices_and_actual_dispatch() {
    assert_eq!(MAIN[0], "Download MEGA link/file");
    assert_eq!(MAIN[1], "Show link info");
    assert_eq!(MAIN[2], "Upload file/folder");
    assert!(MAIN.contains(&"Settings"));
    assert_eq!(MAIN[7], "Advanced CLI command");
    let (calls, rendered) = flow(&["2", "LINK", "", "8", "config get max_workers", "exit"], 3);
    assert_eq!(
        calls,
        [
            vec!["mb", "info", "LINK"],
            vec!["mb", "config", "get", "max_workers"],
        ]
        .map(|words| words.into_iter().map(OsString::from).collect::<Vec<_>>())
    );
    assert_eq!(
        rendered
            .matches("Command finished with exit code 3.")
            .count(),
        2
    );
    assert!(!rendered.contains("[SUCCESS]") && !rendered.contains("[OK]"));
}

#[test]
fn menu_invalid_back_eof_and_nested_exit_never_dispatch_an_unselected_command() {
    for lines in [
        vec!["99", "4", "99", "0", "exit"],
        vec!["4", "exit"],
        vec!["4"],
        vec!["8", "", "exit"],
        vec!["8", "0", "exit"],
    ] {
        let (calls, _) = flow(&lines, 0);
        assert!(calls.is_empty());
    }
    for lines in [
        vec!["4", "2", "0", "exit"],
        vec!["0", "4", "2", "0", "exit"],
    ] {
        let (calls, rendered) = flow(&lines, 0);
        assert_eq!(
            calls,
            [vec![OsString::from("mb"), "account".into(), "list".into()]]
        );
        assert_eq!(
            rendered.matches("[WARNING] Invalid selection.\n").count(),
            usize::from(lines[0] == "0")
        );
    }
}

#[test]
fn every_account_verb_is_reached_through_the_real_menu_including_the_add_wizard() {
    let (calls, _) = flow(
        &[
            "4",
            "1",
            "someone@example.invalid",
            "main",
            "y",
            "y",
            "vault-pass",
            "2",
            "3",
            "",
            "4",
            "someone@example.invalid",
            "5",
            "someone@example.invalid",
            "6",
            "",
            "7",
            "0",
            "exit",
        ],
        0,
    );
    let verbs: Vec<_> = calls
        .iter()
        .map(|words| {
            assert_eq!(words[1], "account");
            words[2].to_str().unwrap()
        })
        .collect();
    assert_eq!(
        verbs,
        [
            "add",
            "list",
            "logout",
            "remove",
            "default",
            "info",
            "refresh-all"
        ]
    );
    assert_eq!(
        calls[0],
        [
            "mb",
            "account",
            "add",
            "someone@example.invalid",
            "--label",
            "main",
            "--default",
            "--vault-passphrase",
            "vault-pass",
        ]
        .map(OsString::from)
    );
    assert_eq!(calls[2], ["mb", "account", "logout"].map(OsString::from));
}

#[test]
fn original_group_entries_and_settings_shortcuts_keep_their_source_positions() {
    assert_eq!(ACCOUNTS[5].command, ["account", "info"]);
    assert_eq!(ACCOUNTS[6].command, ["account", "refresh-all"]);
    assert_eq!(QUEUE[0].command, ["queue", "add-download"]);
    assert_eq!(QUEUE[1].command, ["queue", "add-upload"]);
    assert_eq!(QUEUE[2].command, ["queue", "list"]);
    assert_eq!(TOOLS[4].command, ["crypter", "resolve"]);
    assert_eq!(TOOLS[8].command, ["stream"]);
    for (index, words) in [
        (1, vec!["config", "set", "download_path"]),
        (2, vec!["config", "set", "max_workers"]),
        (3, vec!["config", "set", "speed_limit_kbps"]),
        (4, vec!["config", "set", "elc_accounts"]),
    ] {
        assert_eq!(SETTINGS[index].command, words);
    }
    let (calls, _) = flow(&["7", "2", "", "3", "", "4", "0", "0", "exit"], 0);
    assert_eq!(
        calls,
        [
            vec!["mb", "config", "set", "download_path", "output"],
            vec!["mb", "config", "set", "max_workers", "8"],
            vec!["mb", "config", "set", "speed_limit_kbps", "0"],
        ]
        .map(|words| words.into_iter().map(OsString::from).collect::<Vec<_>>())
    );
}
