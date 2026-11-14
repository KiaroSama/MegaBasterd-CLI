use std::path::PathBuf;
use std::time::Duration;
#[cfg(any(not(windows), test))]
use std::{ffi::OsString, path::Path};

use super::{args, context::Context};
use crate::error::{Error, Result};
#[cfg(any(not(windows), test))]
use crate::platform::process;
use crate::protocol::links;
use crate::storage::queue::{JobStatus, JobType, Queue, QueuePayload};

#[cfg(test)]
#[path = "watch_tests.rs"]
mod tests;

#[cfg(test)]
const TEST_CLIPBOARD: &[(&str, &[&str])] =
    &[("preferred-clipboard", &[]), ("fallback-clipboard", &[])];
#[cfg(any(target_os = "macos", test))]
const MACOS_CLIPBOARD: &[(&str, &[&str])] = &[("pbpaste", &[])];
#[cfg(any(target_os = "linux", test))]
const LINUX_CLIPBOARD: &[(&str, &[&str])] = &[
    ("wl-paste", &["-n"]),
    ("xclip", &["-selection", "clipboard", "-o"]),
];

#[cfg(windows)]
fn clipboard(context: &Context) -> Result<String> {
    crate::platform::clipboard::read(&context.control)
}

#[cfg(not(windows))]
fn clipboard(context: &Context) -> Result<String> {
    #[cfg(target_os = "macos")]
    let commands = MACOS_CLIPBOARD;
    #[cfg(target_os = "linux")]
    let commands = LINUX_CLIPBOARD;
    clipboard_with(commands, |program, args| {
        process::run(
            program,
            args,
            Duration::from_secs(5),
            1024 * 1024,
            64 * 1024,
            &context.control,
        )
    })
}

#[cfg(any(not(windows), test))]
fn clipboard_with(
    commands: &[(&str, &[&str])],
    mut run: impl FnMut(&Path, &[OsString]) -> Result<process::ProcessOutput>,
) -> Result<String> {
    for &(program, args) in commands {
        let args: Vec<_> = args.iter().map(|arg| OsString::from(*arg)).collect();
        match run(Path::new(program), &args) {
            Ok(output) if output.status.success() => {
                return String::from_utf8(output.stdout)
                    .map_err(|_| Error::protocol("Clipboard backend returned non-UTF-8 text"));
            }
            Err(Error::Canceled) => return Err(Error::Canceled),
            _ => (),
        }
    }
    Err(Error::MissingTool(
        "No usable clipboard backend; install/configure the platform clipboard utility yourself"
            .into(),
    ))
}

pub fn dispatch(
    context: &mut Context,
    interval: f64,
    output: Option<PathBuf>,
    run: bool,
    auth: args::VaultOptions,
) -> Result<()> {
    if !interval.is_finite() || !(0.05..=3600.0).contains(&interval) {
        return Err(Error::invalid(
            "Clipboard interval must be between 0.05 and 3600 seconds",
        ));
    }
    let delay = Duration::try_from_secs_f64(interval)
        .map_err(|_| Error::invalid("Clipboard interval exceeds its supported duration"))?;
    let queue = Queue::new(context.paths.queue());
    let destination = output
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| context.config.download_path.clone());
    drive(
        context,
        &queue,
        &WatchOptions {
            destination,
            run,
            auth,
        },
        clipboard,
        |context| context.control.wait(delay),
        |queue, payload| queue.add(JobType::Download, payload),
    )
}

struct WatchOptions {
    destination: String,
    run: bool,
    auth: args::VaultOptions,
}

fn drive(
    context: &mut Context,
    queue: &Queue,
    options: &WatchOptions,
    mut read: impl FnMut(&Context) -> Result<String>,
    mut wait: impl FnMut(&Context) -> Result<()>,
    mut add: impl FnMut(&Queue, &QueuePayload) -> Result<String>,
) -> Result<()> {
    // Refuse pre-existing corruption before starting a clipboard backend.
    queue.list()?;
    let mut previous = read(context)?;
    context
        .output
        .message("INFO", "Watching clipboard for MEGA links; Ctrl+C to stop.")?;
    loop {
        match wait(context) {
            Err(Error::Canceled) => break,
            result => result?,
        }
        let current = match read(context) {
            Err(Error::Canceled) => break,
            result => result?,
        };
        if current.is_empty() || current == previous {
            continue;
        }
        previous = current.clone();
        for value in current
            .lines()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            if !links::is_mega_url(value) {
                continue;
            }
            let items = match queue.list() {
                Ok(items) => items,
                Err(Error::Busy(_)) => {
                    context
                        .output
                        .message("WARNING", "Queue is busy; copy the link again to retry.")?;
                    continue;
                }
                Err(error) => return Err(error),
            };
            let mut duplicate = false;
            for item in items
                .iter()
                .filter(|item| item.status == JobStatus::Pending)
            {
                if queue.payload(item)?.source == value {
                    duplicate = true;
                    break;
                }
            }
            if duplicate {
                continue;
            }
            let payload = QueuePayload {
                source: value.into(),
                destination: options.destination.clone(),
                account: None,
                password: None,
                error: None,
            };
            match add(queue, &payload) {
                Ok(id) => context.output.message(
                    "SUCCESS",
                    &format!("Queued {} as {id}", crate::terminal::redaction::text(value)),
                )?,
                Err(Error::Busy(_)) => {
                    context
                        .output
                        .message("WARNING", "Queue is busy; copy the link again to retry.")?;
                    continue;
                }
                Err(error) => return Err(error),
            }
            if options.run {
                if options.auth.vault_passphrase.is_none()
                    && std::env::var_os("MEGABASTERD_VAULT_PASSPHRASE").is_none()
                    && queue.list()?.iter().any(|item| {
                        item.kind == JobType::Upload && item.status == JobStatus::Pending
                    })
                {
                    context.output.message(
                        "WARNING",
                        "Queue was not run: pending uploads need a vault passphrase.",
                    )?;
                    continue;
                }
                super::queue::handle(
                    context,
                    args::Queue::Run {
                        auth: options.auth.clone(),
                    },
                    super::queue_transfer::execute,
                )?;
            }
        }
    }
    context.output.message("INFO", "Watch stopped.")
}
