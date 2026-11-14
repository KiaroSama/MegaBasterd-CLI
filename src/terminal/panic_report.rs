//! Capture command-thread panic diagnostics without writing from the panic hook.
use std::{
    backtrace::Backtrace,
    cell::RefCell,
    fmt::{self, Write as _},
    io::Write as _,
    panic::{self, AssertUnwindSafe, PanicHookInfo},
};

use zeroize::Zeroizing;

use super::{logging::Logger, output::Output, redaction::log_text};

const MAX_PAYLOAD: usize = 4096;
const MAX_TRACE: usize = 24 * 1024;

#[derive(Default)]
struct Slot {
    busy: bool,
    report: Option<RawReport>,
}

struct RawReport {
    payload: Zeroizing<String>,
    location: Zeroizing<String>,
    backtrace: Backtrace,
}

thread_local! {
    static CAPTURE: RefCell<Option<Slot>> = const { RefCell::new(None) };
}

struct Scope(Option<Slot>);
impl Drop for Scope {
    fn drop(&mut self) {
        let previous = self.0.take();
        let _ = CAPTURE.try_with(|capture| {
            if let Ok(mut capture) = capture.try_borrow_mut() {
                *capture = previous;
            }
        });
    }
}

struct BoundedText(Zeroizing<String>);
impl fmt::Write for BoundedText {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        if text.len() > MAX_TRACE.saturating_sub(self.0.len()) {
            return Err(fmt::Error);
        }
        self.0.push_str(text);
        Ok(())
    }
}

fn bounded(value: &str) -> Zeroizing<String> {
    Zeroizing::new(if value.len() <= MAX_PAYLOAD {
        value.to_owned()
    } else {
        "Diagnostic omitted: text exceeds the capture bound".into()
    })
}

fn render(report: RawReport) -> String {
    let mut trace = BoundedText(Zeroizing::new(String::new()));
    let complete = write!(trace, "{}", report.backtrace).is_ok();
    let trace = if complete {
        log_text(&trace.0)
    } else {
        "Backtrace omitted: rendered text exceeds the capture bound".into()
    };
    format!(
        "Unexpected native panic: {} at {}; Backtrace status={:?}: {}",
        log_text(&report.payload),
        log_text(&report.location),
        report.backtrace.status(),
        trace,
    )
}

/// Install at executable startup, never temporarily around individual commands.
/// This replaces the default raw-payload printer; library callers keep their own hook.
pub fn install() {
    panic::set_hook(Box::new(|info: &PanicHookInfo<'_>| {
        let active = CAPTURE
            .try_with(|capture| {
                let Ok(mut capture) = capture.try_borrow_mut() else {
                    return false;
                };
                let Some(slot) = capture.as_mut() else {
                    return false;
                };
                if slot.busy {
                    return false;
                }
                slot.busy = true;
                slot.report = None;
                true
            })
            .unwrap_or(false);
        if active {
            // Lazy sanitizers and log locks must only run after the panic has unwound.
            let payload = bounded(info.payload_as_str().unwrap_or("Non-string panic payload"));
            let location = info.location().map_or_else(
                || Zeroizing::new("unknown location".into()),
                |location| {
                    bounded(&format!(
                        "{}:{}:{}",
                        location.file(),
                        location.line(),
                        location.column()
                    ))
                },
            );
            let report = RawReport {
                payload,
                location,
                backtrace: Backtrace::force_capture(),
            };
            let _ = CAPTURE.try_with(|capture| {
                if let Ok(mut capture) = capture.try_borrow_mut()
                    && let Some(slot) = capture.as_mut()
                {
                    slot.report = Some(report);
                    slot.busy = false;
                }
            });
        } else {
            let _ = writeln!(
                std::io::stderr().lock(),
                "[ERROR] Native command failed unexpectedly; no secret values were printed."
            );
        }
    }));
}

pub(crate) fn record(diagnostic: &str, logger: Option<&Logger>, output: &Output) {
    if let Some(logger) = logger
        && logger
            .write("ERROR", "PANIC", diagnostic, &serde_json::json!({}))
            .is_err()
    {
        let _ = output.logging_warning(logger);
    }
}

pub(crate) fn catch<T>(action: impl FnOnce() -> T) -> std::result::Result<T, String> {
    let previous = CAPTURE.with(|capture| capture.replace(Some(Slot::default())));
    let scope = Scope(previous);
    let outcome = panic::catch_unwind(AssertUnwindSafe(action));
    let report = CAPTURE.with(|capture| {
        capture
            .borrow_mut()
            .as_mut()
            .and_then(|slot| slot.report.take())
    });
    drop(scope);
    match outcome {
        Ok(value) => Ok(value),
        Err(_) => Err(report.map_or_else(
            || "Unexpected native panic; detailed capture is unavailable".into(),
            render,
        )),
    }
}

#[cfg(test)]
#[path = "panic_report_tests.rs"]
mod tests;
