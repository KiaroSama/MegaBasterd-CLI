use std::io::Write;
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicU8, Ordering},
};

use serde_json::Value;

use super::logging::Logger;
use super::redaction::{literal, sanitize, text};
use crate::error::{Error, Result, poisoned};

#[cfg(test)]
#[path = "theme_tests.rs"]
mod theme_tests;

pub struct Output {
    pub json: bool,
    pub quiet: bool,
    stdout: Mutex<Box<dyn Write + Send>>,
    stderr: Mutex<Box<dyn Write + Send>>,
    color: bool,
    diagnostic_level: AtomicU8,
    logger: OnceLock<Arc<Logger>>,
}

impl Output {
    pub fn new(json: bool, quiet: bool) -> Self {
        Self::with_writer(json, quiet, std::io::stdout())
    }

    pub fn with_writer(json: bool, quiet: bool, stdout: impl Write + Send + 'static) -> Self {
        let mut output = Self::with_writers(json, quiet, stdout, std::io::stderr());
        output.color = super::theme::stderr_color();
        output
    }

    pub fn with_writers(
        json: bool,
        quiet: bool,
        stdout: impl Write + Send + 'static,
        stderr: impl Write + Send + 'static,
    ) -> Self {
        Self {
            json,
            quiet,
            stdout: Mutex::new(Box::new(stdout)),
            stderr: Mutex::new(Box::new(stderr)),
            color: false,
            diagnostic_level: AtomicU8::new(if quiet { 40 } else { 30 }),
            logger: OnceLock::new(),
        }
    }
    pub fn attach_logger(&self, logger: Arc<Logger>) -> Result<()> {
        self.logger
            .set(logger)
            .map_err(|_| Error::protocol("Output logger is already attached"))
    }
    fn log_message(&self, level: &str, message: &str) {
        if let Some(logger) = self.logger.get() {
            let level = if level == "SUCCESS" { "INFO" } else { level };
            if logger
                .write(level, "OUTPUT", message, &serde_json::json!({}))
                .is_err()
            {
                let _ = self.logging_warning(logger);
            }
        }
    }
    /// A file-sink failure must never retry that sink or disclose its path.
    pub fn logging_warning(&self, logger: &Logger) -> Result<()> {
        if logger.take_failure_warning() {
            let mut stderr = self.stderr.lock().map_err(poisoned)?;
            writeln!(stderr, "[WARNING] Private runtime log write failed.")?;
            stderr.flush()?;
        }
        Ok(())
    }

    pub(crate) fn logging_init_warning(&self) -> Result<()> {
        let mut stderr = self.stderr.lock().map_err(poisoned)?;
        writeln!(
            stderr,
            "[WARNING] Private file logging could not be initialized; only console diagnostics are available."
        )?;
        stderr.flush()?;
        Ok(())
    }

    pub(crate) fn diagnostic_console(&self, level: &str, message: &str) -> Result<()> {
        if self.diagnostic_enabled(level) {
            self.console_message(level, message)?;
        }
        Ok(())
    }
    pub fn set_diagnostic_level(&self, level: &str) -> Result<()> {
        let level = match level.to_ascii_uppercase().as_str() {
            "DEBUG" => 10,
            "INFO" => 20,
            "WARNING" => 30,
            "ERROR" => 40,
            "CRITICAL" => 50,
            _ => return Err(Error::invalid("Console log level is invalid")),
        };
        self.diagnostic_level.store(level, Ordering::Relaxed);
        Ok(())
    }
    pub fn diagnostic_enabled(&self, level: &str) -> bool {
        let rank = match level {
            "DEBUG" => 10,
            "INFO" => 20,
            "WARNING" => 30,
            "ERROR" => 40,
            "CRITICAL" => 50,
            _ => return false,
        };
        (!self.quiet || rank >= 40) && rank >= self.diagnostic_level.load(Ordering::Relaxed)
    }
    pub fn diagnostic(&self, level: &str, message: &str) -> Result<()> {
        self.log_message(level, message);
        self.diagnostic_console(level, message)
    }
    pub fn record(&self, value: &Value) -> Result<()> {
        if !self.json {
            return Ok(());
        }
        let mut stdout = self.stdout.lock().map_err(poisoned)?;
        let clean = sanitize(value, true);
        serde_json::to_writer(&mut **stdout, &clean)?;
        writeln!(stdout)?;
        stdout.flush()?;
        Ok(())
    }
    pub fn message(&self, level: &str, message: &str) -> Result<()> {
        self.log_message(level, message);
        self.console_message(level, message)
    }
    fn console_message(&self, level: &str, message: &str) -> Result<()> {
        if self.quiet && !matches!(level, "ERROR" | "CRITICAL") {
            return Ok(());
        }
        let mut stderr = self.stderr.lock().map_err(poisoned)?;
        let message = literal(&text(message));
        let level = if level == "SUCCESS" { "OK" } else { level };
        if self.color {
            let color = match level {
                "ERROR" | "CRITICAL" => "31",
                "WARNING" => "33",
                _ => "32",
            };
            writeln!(stderr, "[\x1b[{color}m{level}\x1b[0m] {message}")?;
        } else {
            writeln!(stderr, "[{level}] {message}")?;
        }
        stderr.flush()?;
        Ok(())
    }
    pub(crate) fn menu(&self, title: &str, labels: &[&str]) -> Result<()> {
        if self.json || self.quiet {
            return Ok(());
        }
        let rendered = super::theme::menu(title, labels, self.color);
        let mut stderr = self.stderr.lock().map_err(poisoned)?;
        stderr.write_all(rendered.as_bytes())?;
        stderr.flush()?;
        Ok(())
    }

    pub fn error(&self, error: &Error) -> Result<()> {
        let machine = self.record(&serde_json::json!({"event":"result", "status":"failed", "error_code":error.code(), "error":error.to_string()}));
        let human = self.message("ERROR", &error.to_string());
        machine.and(human)
    }
    pub(crate) fn select_files_interactive(&self, count: usize) -> Result<Vec<usize>> {
        use std::io::IsTerminal;

        if std::io::stdin().is_terminal() {
            if let Some(control) = crate::platform::signals::current()? {
                let destination = if self.json {
                    &self.stderr
                } else {
                    &self.stdout
                };
                let mut destination = destination.lock().map_err(poisoned)?;
                return super::prompts::select_controlled(count, &control, &mut *destination);
            }
        }
        self.select_files(count, &mut std::io::stdin().lock())
    }

    pub fn select_files(
        &self,
        count: usize,
        input: &mut impl std::io::BufRead,
    ) -> Result<Vec<usize>> {
        let destination = if self.json {
            &self.stderr
        } else {
            &self.stdout
        };
        let mut destination = destination.lock().map_err(poisoned)?;
        super::prompts::select_with_io(count, input, &mut *destination)
    }

    pub fn value_line(&self, value: &str) -> Result<()> {
        let mut stdout = self.stdout.lock().map_err(poisoned)?;
        writeln!(stdout, "{}", literal(&text(value)))?;
        stdout.flush()?;
        Ok(())
    }

    pub fn public_link(&self, link: &str) -> Result<()> {
        let mut stdout = self.stdout.lock().map_err(poisoned)?;
        writeln!(stdout, "{}", literal(link))?;
        stdout.flush()?;
        Ok(())
    }

    pub fn table(&self, headings: &[&str], rows: &[Vec<String>]) -> Result<()> {
        let mut stdout = self.stdout.lock().map_err(poisoned)?;
        let lines = std::iter::once(headings.iter().map(|h| h.to_string()).collect::<Vec<_>>())
            .chain(rows.iter().cloned());
        for line in lines {
            writeln!(
                stdout,
                "{}",
                line.iter()
                    .map(|s| literal(&text(s)))
                    .collect::<Vec<_>>()
                    .join(" | ")
            )?;
        }
        stdout.flush()?;
        Ok(())
    }
}
