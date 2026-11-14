use std::io::IsTerminal;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    terminal,
};

use super::progress::Progress;
use crate::error::{Error, Result};
use crate::transfers::control::Control;

#[derive(Debug, PartialEq, Eq)]
pub enum KeyAction {
    Pause,
    Cancel,
    Ignore,
}

pub fn key_action(key: KeyEvent) -> KeyAction {
    if key.kind != KeyEventKind::Press {
        return KeyAction::Ignore;
    }
    match key.code {
        KeyCode::Char('c' | 'C') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            KeyAction::Cancel
        }
        KeyCode::Char('p' | 'P')
            if key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT =>
        {
            KeyAction::Pause
        }
        _ => KeyAction::Ignore,
    }
}

pub fn enabled(json: bool, stdin_terminal: bool, stderr_terminal: bool) -> bool {
    !json && stdin_terminal && stderr_terminal
}

struct RawMode {
    owned: bool,
}
impl Drop for RawMode {
    fn drop(&mut self) {
        if self.owned && terminal::disable_raw_mode().is_err() {
            eprintln!("[ERROR] Terminal mode restoration failed.");
        }
    }
}

pub struct Input<'a> {
    stopped: Arc<AtomicBool>,
    reader: Option<std::thread::ScopedJoinHandle<'a, Result<()>>>,
    _mode: RawMode,
}

impl<'a> Input<'a> {
    /// Start only after all prompts; the scoped reader is the sole terminal-event consumer.
    pub fn start<'env: 'a>(
        scope: &'a std::thread::Scope<'a, 'env>,
        json: bool,
        control: &'a Control,
        progress: &'a Progress,
    ) -> Result<Self> {
        let stopped = Arc::new(AtomicBool::new(false));
        if !enabled(
            json,
            std::io::stdin().is_terminal(),
            std::io::stderr().is_terminal(),
        ) {
            return Ok(Self {
                stopped,
                reader: None,
                _mode: RawMode { owned: false },
            });
        }
        let mode = RawMode {
            owned: !terminal::is_raw_mode_enabled()?,
        };
        if mode.owned {
            terminal::enable_raw_mode()?;
        }
        let stop = stopped.clone();
        let reader = std::thread::Builder::new()
            .name("transfer-input".into())
            .spawn_scoped(scope, move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    while !stop.load(Ordering::Acquire) && !control.is_canceled() {
                        if !event::poll(Duration::from_millis(100))? {
                            continue;
                        }
                        if let Event::Key(key) = event::read()? {
                            match key_action(key) {
                                KeyAction::Pause => {
                                    progress.pause(control.toggle_pause()?)?;
                                }
                                KeyAction::Cancel => {
                                    control.cancel();
                                    break;
                                }
                                KeyAction::Ignore => (),
                            }
                        }
                    }
                    Ok(())
                }))
                .unwrap_or_else(|_| {
                    Err(Error::protocol(
                        "Transfer keyboard listener was interrupted",
                    ))
                });
                if result.is_err() {
                    control.cancel();
                }
                result
            })?;
        Ok(Self {
            stopped,
            reader: Some(reader),
            _mode: mode,
        })
    }
}

impl Drop for Input<'_> {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        if let Some(reader) = self.reader.take() {
            match reader.join() {
                Ok(Ok(())) => (),
                _ => eprintln!("[ERROR] Transfer keyboard listener failed; transfer was canceled."),
            }
        }
    }
}
