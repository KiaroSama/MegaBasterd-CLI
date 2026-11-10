//! Owned progress rendering: snapshot under the model lock, draw only after releasing it.
use std::io;

use super::Shared;
use crate::error::{Result, poisoned};
use std::{
    thread::JoinHandle,
    time::{Duration, Instant},
};

pub(super) fn spawn(
    state: Shared,
    mut draw: impl FnMut(&str, bool) -> io::Result<()> + Send + 'static,
) -> JoinHandle<Result<()>> {
    std::thread::spawn(move || {
        let (mutex, wake) = &*state;
        loop {
            let mut locked = mutex.lock().map_err(poisoned)?;
            if locked.closed.is_none() {
                let (next, _) = wake
                    .wait_timeout(locked, Duration::from_millis(200))
                    .map_err(poisoned)?;
                locked = next;
            }
            let now = Instant::now();
            let overall = locked.overall(now);
            let (rows, hidden) = locked.visible();
            let paused = locked.paused;
            let closed = locked.closed.is_some();
            drop(locked);
            let rows = rows
                .iter()
                .map(|row| row.render_at(paused, now))
                .collect::<Vec<_>>()
                .join(" | ");
            let overall = match overall {
                Ok(overall) => overall.render(paused, now),
                Err(error) => format!("Overall | Failed: {error}"),
            };
            let mut line = if rows.is_empty() {
                overall
            } else {
                format!("{overall} | {rows}")
            };
            if hidden != 0 {
                line.push_str(&format!(" | (+{hidden} more files)"));
            }
            draw(&line, closed)?;
            if closed {
                return Ok(());
            }
        }
    })
}

#[cfg(test)]
#[path = "progress_renderer_tests.rs"]
mod tests;
