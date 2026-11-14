use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Instant;

use chrono::Utc;
use serde_json::Value;

use super::redaction::{literal, log_text, sanitize, text};
use crate::error::{Error, Result, poisoned};
use crate::platform::secure_files::PrivateDirectory;

#[cfg(test)]
#[path = "logging_open_tests.rs"]
mod open_tests;
#[cfg(test)]
#[path = "logging_write_tests.rs"]
mod write_tests;

struct ActiveLog {
    file: Option<File>,
    bytes: u64,
    segments: u32,
}

pub struct Logger {
    active: Mutex<ActiveLog>,
    directory: PrivateDirectory,
    started: Instant,
    name: OsString,
    run_id: String,
    command: &'static str,
    max_bytes: u64,
    backups: u32,
    failure_warned: AtomicBool,
}

impl Logger {
    pub fn start(directory: &Path) -> Result<Self> {
        Self::configured(directory, 5_000_000, 5)
    }

    pub fn configured(directory: &Path, max_bytes: u64, backups: u32) -> Result<Self> {
        Self::configured_for_command(directory, max_bytes, backups, "unknown")
    }

    pub(crate) fn configured_for_command(
        directory: &Path,
        max_bytes: u64,
        backups: u32,
        command: &'static str,
    ) -> Result<Self> {
        Self::configured_with_opener(directory, max_bytes, backups, command, |directory, name| {
            directory.open_private(name, true)
        })
    }

    fn configured_with_opener(
        directory: &Path,
        max_bytes: u64,
        backups: u32,
        command: &'static str,
        mut open: impl FnMut(&PrivateDirectory, &OsStr) -> Result<File>,
    ) -> Result<Self> {
        let directory = PrivateDirectory::ensure(directory)?;
        let prefix = Utc::now().format("mb_%Y-%m-%d_%H-%M-%S_UTC").to_string();
        for collision in 0..100u32 {
            let name = OsString::from(if collision == 0 {
                format!("{prefix}.log")
            } else {
                format!("{prefix}_{collision}.log")
            });
            match open(&directory, &name) {
                Ok(file) => {
                    let run_id = Path::new(&name)
                        .file_stem()
                        .and_then(OsStr::to_str)
                        .ok_or_else(|| Error::protocol("Generated log filename has no UTF-8 stem"))?
                        .to_owned();
                    let logger = Self {
                        active: Mutex::new(ActiveLog {
                            file: Some(file),
                            bytes: 0,
                            segments: 0,
                        }),
                        directory,
                        started: Instant::now(),
                        name,
                        run_id,
                        command,
                        max_bytes,
                        backups,
                        failure_warned: AtomicBool::new(false),
                    };
                    logger.write("INFO", "RUNTIME", "Started", &serde_json::json!({
                        "version": env!("CARGO_PKG_VERSION"), "os": std::env::consts::OS,
                        "architecture": std::env::consts::ARCH, "log_max_bytes":max_bytes, "log_backups":backups,
                    }))?;
                    return Ok(logger);
                }
                Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    continue;
                }
                Err(error) => return Err(error),
            }
        }
        Err(Error::Busy("Log filenames".into()))
    }

    pub fn name(&self) -> &OsStr {
        &self.name
    }

    /// Shared by every console caller so a disabled file sink warns only once.
    pub fn take_failure_warning(&self) -> bool {
        !self.failure_warned.swap(true, Ordering::Relaxed)
    }

    fn segment(&self, number: u32) -> OsString {
        let mut name = self.name.clone();
        name.push(format!(".{number}"));
        name
    }

    fn rotate(&self, active: &mut ActiveLog) -> Result<()> {
        self.directory.verify_private(
            active
                .file
                .as_ref()
                .ok_or_else(|| Error::protocol("Private file logging is disabled"))?,
        )?;
        let mut file = active
            .file
            .take()
            .ok_or_else(|| Error::protocol("Private file logging is disabled"))?;
        file.flush()?;
        file.sync_all()?;
        // Windows denies rename while this writable handle is open. Every later operation
        // still uses the retained private directory and its native verified opens.
        drop(file);
        let next = active.segments.saturating_add(1).min(self.backups);
        for number in (2..=next).rev() {
            self.directory
                .replace(&self.segment(number - 1), &self.segment(number))?;
        }
        self.directory.replace(&self.name, &self.segment(1))?;
        let _ = self.directory.sync()?;
        active.file = Some(self.directory.open_private(&self.name, true)?);
        active.bytes = 0;
        active.segments = next;
        Ok(())
    }

    pub fn write(&self, level: &str, component: &str, message: &str, fields: &Value) -> Result<()> {
        let stamp = Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
        let fields = sanitize(fields, false);
        let record = format!(
            "[{stamp}] [{}] [{}] run={} cmd={} {} {}\n",
            literal(level),
            literal(component),
            self.run_id,
            literal(self.command),
            literal(&text(message)),
            fields
        );
        let record = log_text(&record);
        let mut active = self.active.lock().map_err(poisoned)?;
        let result = (|| {
            if active.file.is_none() {
                return Err(Error::protocol("Private file logging is disabled"));
            }
            let bytes = record.len() as u64;
            if self.max_bytes > 0
                && self.backups > 0
                && active.bytes > 0
                && active.bytes.saturating_add(bytes) >= self.max_bytes
            {
                self.rotate(&mut active)?;
            }
            let file = active
                .file
                .as_mut()
                .ok_or_else(|| Error::protocol("Private file logging is disabled"))?;
            self.directory.verify_private(file)?;
            file.write_all(record.as_bytes())?;
            file.flush()?;
            active.bytes = active.bytes.saturating_add(bytes);
            Ok(())
        })();
        if result.is_err() {
            active.file = None;
        }
        result
    }

    pub fn finish(&self, exit_code: i32) -> Result<()> {
        self.write(
            "INFO",
            "RUNTIME",
            "Finished",
            &serde_json::json!({
                "exit_code": exit_code, "elapsed_seconds": self.started.elapsed().as_secs_f64(),
            }),
        )?;
        let mut active = self.active.lock().map_err(poisoned)?;
        let mut file = active
            .file
            .take()
            .ok_or_else(|| Error::protocol("Private file logging is disabled"))?;
        file.flush()?;
        file.sync_all()?;
        // Closing here also seals logging while other Arc owners remain alive.
        drop(file);
        Ok(())
    }
}
