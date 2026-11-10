use std::{ffi::OsString, io::IsTerminal, path::Path};

use zeroize::Zeroizing;

#[cfg(test)]
#[path = "menu_account_tests.rs"]
mod account_tests;
#[cfg(test)]
#[path = "menu_flow_tests.rs"]
mod flow_tests;

use super::menu_wizard::{self, Outcome, Wizard};
use crate::error::Result;
use crate::terminal::output::Output;

#[path = "menu_entries.rs"]
mod entries;
use entries::{ACCOUNTS, Entry, MAIN, QUEUE, SETTINGS, TOOLS};

fn choose_with(
    output: &Output,
    title: &str,
    labels: &[&str],
    back: bool,
    mut read: impl FnMut(&str) -> Result<Option<String>>,
) -> Result<Option<usize>> {
    output.menu(title, labels)?;
    let question = if back {
        "Selection [1] {back=0, quit=exit}:"
    } else {
        "Selection [1] {quit=exit}:"
    };
    loop {
        let Some(answer) = read(question)? else {
            return Ok(None);
        };
        match answer.trim().to_ascii_lowercase().as_str() {
            "q" | "quit" | "exit" => return Ok(None),
            "0" if back => return Ok(Some(0)),
            "" => return Ok(Some(1)),
            value => {
                let choice = value.chars().try_fold(0usize, |number, character| {
                    let digit = crate::transfers::selection::decimal(character)?;
                    number.checked_mul(10)?.checked_add(digit as usize)
                });
                if let Some(choice) = choice.filter(|choice| (1..=labels.len()).contains(choice)) {
                    return Ok(Some(choice));
                }
                output.message("WARNING", "Invalid selection.")?;
            }
        }
    }
}

pub fn run(cli: super::args::Cli) -> i32 {
    if !std::io::stdin().is_terminal() {
        let _ = Output::new(false, cli.quiet).message(
            "ERROR",
            "No command provided. Use mb --help in noninteractive mode.",
        );
        return 2;
    }
    let logging = if cli.no_log_file {
        Some(false)
    } else if cli.log_file {
        Some(true)
    } else {
        None
    };
    // Menu choices must remain visible even when child commands use quiet diagnostics.
    let context = match super::context::Context::start_for_command(false, false, logging, "menu") {
        Ok(context) => context,
        Err(error) => {
            let _ = Output::new(false, false).error(&error);
            return error.exit_code();
        }
    };
    let _signal = match super::signals::activate(&context.control) {
        Ok(signal) => signal,
        Err(error) => {
            context.report_error(&error);
            context.finish(error.exit_code());
            return error.exit_code();
        }
    };
    let result = run_in_context(
        &context,
        &cli,
        |question, secret| {
            read_with_control(&context.control, question, secret, |question, secret| {
                crate::terminal::prompt_input::read(question, secret, &context.control)
            })
        },
        super::run,
    );
    result.map_or_else(|error| error.exit_code(), |()| 0)
}

fn read_with_control(
    control: &crate::transfers::control::Control,
    question: &str,
    secret: bool,
    read: impl FnOnce(&str, bool) -> Result<Option<Zeroizing<String>>>,
) -> Result<Option<Zeroizing<String>>> {
    control.checkpoint()?;
    let answer = read(question, secret);
    control.checkpoint()?;
    match answer {
        Err(crate::error::Error::Io(error))
            if error.kind() == std::io::ErrorKind::Interrupted
                || (cfg!(windows) && error.raw_os_error() == Some(995)) =>
        {
            control.cancel();
            Err(crate::error::Error::Canceled)
        }
        Err(crate::error::Error::Io(error))
            if error.kind() == std::io::ErrorKind::UnexpectedEof =>
        {
            Ok(None)
        }
        answer => answer,
    }
}

fn run_in_context(
    context: &super::context::Context,
    cli: &super::args::Cli,
    read: impl FnMut(&str, bool) -> Result<Option<Zeroizing<String>>>,
    mut dispatch: impl FnMut(Vec<OsString>) -> i32,
) -> Result<()> {
    let result = crate::terminal::panic_report::catch(|| {
        context.output.set_diagnostic_level(if cli.quiet {
            "ERROR"
        } else if cli.verbose >= 2 {
            "DEBUG"
        } else if cli.verbose == 1 {
            "INFO"
        } else {
            &context.config.log_level
        })?;
        context.event("MENU", "Menu started", &serde_json::json!({}));
        run_with(&context.output, &context.paths.output, read, |arguments| {
            let mut forwarded = vec![OsString::from("mb")];
            if cli.quiet {
                forwarded.push("-q".into());
            }
            if cli.verbose > 0 {
                forwarded.push(format!("-{}", "v".repeat(usize::from(cli.verbose))).into());
            }
            if cli.no_log_file {
                forwarded.push("--no-log-file".into());
            } else if cli.log_file {
                forwarded.push("--log-file".into());
            }
            forwarded.extend(arguments.into_iter().skip(1));
            dispatch(forwarded)
        })
    })
    .unwrap_or_else(|diagnostic| {
        crate::terminal::panic_report::record(
            &diagnostic,
            context.logger.as_deref(),
            &context.output,
        );
        Err(crate::error::Error::Unexpected)
    });
    let code = match &result {
        Ok(()) => 0,
        Err(error) => {
            context.report_error(error);
            error.exit_code()
        }
    };
    context.finish(code);
    result
}

fn run_with(
    output: &Output,
    output_directory: &Path,
    mut read: impl FnMut(&str, bool) -> Result<Option<Zeroizing<String>>>,
    mut dispatch: impl FnMut(Vec<OsString>) -> i32,
) -> Result<()> {
    loop {
        let Some(choice) = choose_with(
            output,
            "MegaBasterd-CLI Main menu",
            MAIN,
            false,
            |question| read(question, false).map(|answer| answer.map(|answer| answer.to_string())),
        )?
        else {
            return Ok(());
        };
        let (title, group) = match choice {
            1..=3 | 8 => {
                let wizard = match choice {
                    1 => Wizard::Download,
                    2 => Wizard::Info,
                    3 => Wizard::Upload,
                    _ => Wizard::Advanced,
                };
                if !wizard_action(output, wizard, output_directory, &mut read, &mut dispatch)? {
                    return Ok(());
                }
                continue;
            }
            4 => ("Account and Cloud", ACCOUNTS),
            5 => ("Queue and Proxy", QUEUE),
            6 => ("Tools", TOOLS),
            7 => ("Settings", SETTINGS),
            _ => continue,
        };
        loop {
            let labels: Vec<_> = group.iter().map(|entry| entry.label).collect();
            let Some(choice) = choose_with(output, title, &labels, true, |question| {
                read(question, false).map(|answer| answer.map(|answer| answer.to_string()))
            })?
            else {
                return Ok(());
            };
            if choice == 0 {
                break;
            }
            let entry = &group[choice - 1];
            let wizard = match entry.command {
                ["account", "add"] => Some(Wizard::Account),
                ["config", "set", "elc_accounts"] => Some(Wizard::Elc),
                ["config", "set", "download_path"] => Some(Wizard::DownloadFolder),
                ["config", "set", "max_workers"] => Some(Wizard::DownloadWorkers),
                ["config", "set", "speed_limit_kbps"] => Some(Wizard::SpeedLimit),
                _ => None,
            };
            let keep_menu = if let Some(wizard) = wizard {
                wizard_action(output, wizard, output_directory, &mut read, &mut dispatch)?
            } else {
                generic_with(
                    output,
                    entry,
                    |question| {
                        read(question, false).map(|answer| answer.map(|answer| answer.to_string()))
                    },
                    &mut dispatch,
                )?
            };
            if !keep_menu {
                return Ok(());
            }
        }
    }
}

fn report(output: &Output, code: i32) -> Result<()> {
    output.message(
        if code == 0 { "SUCCESS" } else { "ERROR" },
        &format!("Command finished with exit code {code}."),
    )
}
fn generic_with(
    output: &Output,
    entry: &Entry,
    mut read: impl FnMut(&str) -> Result<Option<String>>,
    dispatch: impl FnOnce(Vec<std::ffi::OsString>) -> i32,
) -> Result<bool> {
    let mut arguments: Vec<_> = std::iter::once("mb".to_owned())
        .chain(entry.command.iter().map(|word| (*word).to_owned()))
        .map(std::ffi::OsString::from)
        .collect();
    if entry.arguments {
        let Some(text) = read(&format!(
            "Arguments for mb {} (0/back = cancel; --help lists options):",
            entry.command.join(" ")
        ))?
        else {
            return Ok(false);
        };
        if text.trim().eq_ignore_ascii_case("exit") {
            return Ok(false);
        }
        if matches!(text.trim().to_ascii_lowercase().as_str(), "0" | "back") {
            return Ok(true);
        }
        if text.trim().is_empty() && entry.command.len() == 1 {
            output.message("WARNING", "No arguments entered.")?;
            return Ok(true);
        }
        arguments.extend(
            split_arguments(&text)
                .into_iter()
                .map(std::ffi::OsString::from),
        );
    }
    report(output, dispatch(arguments))?;
    Ok(true)
}

pub(super) fn split_arguments(text: &str) -> Vec<String> {
    if text.trim().is_empty() {
        return Vec::new();
    }
    let fallback = || text.split_whitespace().map(str::to_owned).collect();
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut active = false;
    let mut characters = text.chars();
    while let Some(character) = characters.next() {
        match (quote, character) {
            (Some('\''), '\'') | (Some('"'), '"') => quote = None,
            (Some('\''), _) => word.push(character),
            (Some('"'), '\\') => {
                let Some(escaped) = characters.next() else {
                    return fallback();
                };
                if !matches!(escaped, '"' | '\\') {
                    word.push('\\');
                }
                word.push(escaped);
            }
            (Some(_), _) => word.push(character),
            (None, ' ' | '\t' | '\r' | '\n') => {
                if active {
                    words.push(std::mem::take(&mut word));
                    active = false;
                }
            }
            (None, '\'' | '"') => {
                quote = Some(character);
                active = true;
            }
            (None, '\\') => {
                let Some(escaped) = characters.next() else {
                    return fallback();
                };
                word.push(escaped);
                active = true;
            }
            (None, _) => {
                word.push(character);
                active = true;
            }
        }
    }
    if quote.is_some() {
        return fallback();
    }
    if active {
        words.push(word);
    }
    words
}

fn wizard_action(
    output: &Output,
    wizard: Wizard,
    output_directory: &Path,
    read: impl FnMut(&str, bool) -> Result<Option<Zeroizing<String>>>,
    mut dispatch: impl FnMut(Vec<OsString>) -> i32,
) -> Result<bool> {
    match menu_wizard::run_with(wizard, output_directory, read, |message| {
        output.message("WARNING", message)
    })? {
        Outcome::Ready(arguments) => report(output, dispatch(arguments))?,
        Outcome::Back => (),
        Outcome::Quit => return Ok(false),
    }
    Ok(true)
}
