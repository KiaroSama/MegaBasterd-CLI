use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::{Error, Result};
use crate::platform::process;
use crate::terminal::output::Output;
use crate::transfers::control::Control;

#[cfg(test)]
#[path = "hook_parser_tests.rs"]
mod parser_tests;

pub fn command_args(command: &str, appended: &[OsString]) -> Result<(OsString, Vec<OsString>)> {
    command_args_for(command, appended, cfg!(windows))
}

fn command_args_for(
    command: &str,
    appended: &[OsString],
    windows: bool,
) -> Result<(OsString, Vec<OsString>)> {
    if command.len() > 32_768 || command.contains('\0') {
        return Err(Error::invalid(
            "Configured command is empty, too large, or contains NUL",
        ));
    }
    let mut tokens = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut active = false;
    let mut chars = command.chars().peekable();
    while let Some(character) = chars.next() {
        if let Some(delimiter) = quote {
            if character == delimiter {
                quote = None;
                if windows {
                    word.push(character);
                    tokens.push(OsString::from(std::mem::take(&mut word)));
                    active = false;
                }
            } else if !windows && delimiter == '"' && character == '\\' {
                let escaped = chars
                    .next()
                    .ok_or_else(|| Error::invalid("Configured command has an unfinished escape"))?;
                if !matches!(escaped, '"' | '\\') {
                    word.push('\\');
                }
                word.push(escaped);
            } else {
                word.push(character);
            }
        } else if matches!(character, ' ' | '\t' | '\r' | '\n') {
            if active {
                tokens.push(OsString::from(std::mem::take(&mut word)));
                active = false;
            }
        } else if matches!(character, '\'' | '"') && (!windows || !active) {
            quote = Some(character);
            active = true;
            if windows {
                word.push(character);
            }
        } else if !windows && character == '\\' {
            word.push(
                chars
                    .next()
                    .ok_or_else(|| Error::invalid("Configured command has an unfinished escape"))?,
            );
            active = true;
        } else {
            word.push(character);
            active = true;
        }
    }
    if quote.is_some() {
        return Err(Error::invalid("Configured command has an unmatched quote"));
    }
    if active {
        tokens.push(OsString::from(word));
    }
    if tokens.is_empty() || tokens.len() > 256 {
        return Err(Error::invalid(
            "Configured command needs an executable and at most 255 arguments",
        ));
    }
    let program = tokens.remove(0);
    if program.is_empty() {
        return Err(Error::invalid("Configured command has no executable"));
    }
    tokens.extend_from_slice(appended);
    Ok((program, tokens))
}

pub fn execute(
    command: &str,
    appended: &[OsString],
    control: &Control,
    output: &Output,
) -> Result<()> {
    let (program, arguments) = command_args(command, appended)?;
    let name = Path::new(&program)
        .file_name()
        .map_or_else(|| "?".into(), |name| name.to_string_lossy());
    let _ = output.diagnostic(
        "INFO",
        &format!(
            "Running configured command: {name} ({} configured args)",
            arguments.len().saturating_sub(appended.len())
        ),
    );
    let result = process::run(
        Path::new(&program),
        &arguments,
        Duration::from_secs(30),
        64 * 1024,
        64 * 1024,
        control,
    )?;
    if !result.status.success() {
        return Err(Error::protocol(
            "Configured command returned a nonzero exit status",
        ));
    }
    Ok(())
}

pub fn after_file(
    command: Option<&str>,
    path: &Path,
    control: &Control,
    output: &Output,
) -> Result<()> {
    match command.filter(|value| !value.is_empty()) {
        Some(command) => execute(command, &[path.as_os_str().to_owned()], control, output),
        None => Ok(()),
    }
}

pub fn after_batch(
    command: Option<&str>,
    kind: &str,
    succeeded: usize,
    failed: usize,
    control: &Control,
    output: &Output,
) -> Result<()> {
    if succeeded == 0 && failed == 0 {
        return Ok(());
    }
    match command.filter(|value| !value.is_empty()) {
        Some(command) => execute(
            command,
            &[
                kind.into(),
                succeeded.to_string().into(),
                failed.to_string().into(),
            ],
            control,
            output,
        ),
        None => Ok(()),
    }
}

pub fn upload_log(path: &Path, record: &serde_json::Value) -> Result<()> {
    use crate::platform::secure_files::PrivateDirectory;
    use crate::storage::files::Store;
    use std::io::{Seek, SeekFrom, Write};
    let absolute: PathBuf = if path.is_absolute() {
        path.into()
    } else {
        std::env::current_dir()?.join(path)
    };
    let _lock = Store::new(&absolute).lock()?;
    let directory = PrivateDirectory::open(
        absolute
            .parent()
            .ok_or_else(|| Error::invalid("Upload log has no parent"))?,
    )?;
    let name = absolute
        .file_name()
        .ok_or_else(|| Error::invalid("Upload log has no filename"))?;
    let mut file = match directory.open_private(name, true) {
        Ok(file) => file,
        Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            directory.open_private(name, false)?
        }
        Err(error) => return Err(error),
    };
    file.seek(SeekFrom::End(0))?;
    let clean = crate::terminal::redaction::sanitize(record, true);
    serde_json::to_writer(&mut file, &clean)?;
    writeln!(file)?;
    file.flush()?;
    file.sync_data()?;
    directory.sync()?;
    Ok(())
}
