use std::collections::{BTreeMap, VecDeque};
use std::io::{IsTerminal, Write};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use super::redaction::literal;
use crate::error::{Error, Result, poisoned};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Queued,
    Active,
    Verifying,
    Paused,
    Complete,
    Failed,
    Canceled,
    Skipped,
}

impl Status {
    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Complete | Self::Failed | Self::Canceled | Self::Skipped
        )
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Queued => "Queued",
            Self::Active => "Active",
            Self::Verifying => "Verifying",
            Self::Paused => "Paused",
            Self::Complete => "Done",
            Self::Failed => "Failed",
            Self::Canceled => "Canceled",
            Self::Skipped => "Skipped",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub total: u64,
    pub completed: u64,
    pub status: Status,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Totals {
    pub total: u64,
    pub completed: u64,
    pub items: usize,
    pub finished: usize,
    pub failed: usize,
    pub status: Status,
}

pub const MAX_VISIBLE_FILE_ROWS: usize = 12;

#[derive(Clone, Default)]
struct RollingRate {
    samples: VecDeque<(Instant, u64)>,
    speed: f64,
}

impl RollingRate {
    const WINDOW: Duration = Duration::from_secs(5);
    const MIN_INTERVAL: Duration = Duration::from_millis(250);

    fn update(&mut self, completed: u64, now: Instant) {
        let now = self.samples.back().map_or(now, |&(last, _)| now.max(last));
        if self
            .samples
            .back()
            .is_some_and(|&(_, last)| completed < last)
        {
            *self = Self::default();
        }
        // Keep the latest count but coalesce bursts: any three samples span at least100ms.
        if self.samples.len() >= 2
            && now.saturating_duration_since(self.samples[self.samples.len() - 2].0)
                < Duration::from_millis(100)
        {
            self.samples.pop_back();
        }
        self.samples.push_back((now, completed));
        while self.samples.len() > 1
            && self
                .samples
                .front()
                .is_some_and(|&(at, _)| now.saturating_duration_since(at) > Self::WINDOW)
        {
            self.samples.pop_front();
        }
        if let Some(&(first, baseline)) = self.samples.front()
            && self.samples.len() >= 2
            && now.saturating_duration_since(first) >= Self::MIN_INTERVAL
        {
            self.speed = completed.saturating_sub(baseline) as f64
                / now.saturating_duration_since(first).as_secs_f64();
        }
    }

    fn current(&self, now: Instant) -> f64 {
        let mut fresh = self
            .samples
            .iter()
            .filter(|&&(at, _)| now.saturating_duration_since(at) <= Self::WINDOW);
        let Some(&(first, baseline)) = fresh.next() else {
            return 0.0;
        };
        let Some(&(_, completed)) = fresh.next_back() else {
            return 0.0;
        };
        let elapsed = now.saturating_duration_since(first);
        if elapsed < Self::MIN_INTERVAL {
            self.speed
        } else {
            completed.saturating_sub(baseline) as f64 / elapsed.as_secs_f64()
        }
    }
}

#[derive(Clone)]
pub struct Row {
    name: String,
    total: u64,
    completed: u64,
    rate: RollingRate,
    started: Instant,
    finished: Option<Instant>,
    status: Status,
    summary: bool,
    deferred: bool,
}

pub fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut number = bytes as f64;
    let mut unit = "EB";
    for candidate in ["KB", "MB", "GB", "TB", "PB", "EB"] {
        number /= 1024.0;
        unit = candidate;
        if number < 1024.0 {
            break;
        }
    }
    format!("{number:.2} {unit}")
}

pub fn duration(seconds: u64) -> String {
    if seconds >= 3600 {
        format!(
            "{}:{:02}:{:02}",
            seconds / 3600,
            seconds / 60 % 60,
            seconds % 60
        )
    } else {
        format!("{:02}:{:02}", seconds / 60, seconds % 60)
    }
}

impl Row {
    pub fn new(name: &str, total: u64) -> Self {
        Self {
            name: literal(name),
            total,
            completed: 0,
            rate: RollingRate::default(),
            started: Instant::now(),
            finished: None,
            status: Status::Queued,
            summary: false,
            deferred: false,
        }
    }
    pub fn render(&self) -> String {
        self.render_paused(false)
    }
    fn render_paused(&self, paused: bool) -> String {
        self.render_at(paused, Instant::now())
    }
    fn render_at(&self, paused: bool, now: Instant) -> String {
        self.render_rate(paused, now, self.rate.current(now))
    }
    fn render_rate(&self, paused: bool, now: Instant, speed: f64) -> String {
        let done = self.status == Status::Complete
            || (!self.deferred
                && !self.status.terminal()
                && self.total > 0
                && self.completed >= self.total);
        let stopped = done || self.status.terminal();
        let paused = paused && !stopped;
        let elapsed = self
            .finished
            .unwrap_or(now)
            .saturating_duration_since(self.started);
        let percent = if self.total == 0 {
            if self.status == Status::Complete {
                100.0
            } else {
                0.0
            }
        } else {
            (self.completed as f64 / self.total as f64 * 100.0).min(100.0)
        };
        let filled = (percent / 10.0) as usize;
        let bar = format!("{}{}", "#".repeat(filled), "-".repeat(10 - filled));
        let eta = if !paused && !stopped {
            let remaining = if speed > 0.0 {
                duration((self.total.saturating_sub(self.completed) as f64 / speed) as u64)
            } else {
                "--:--".to_owned()
            };
            format!(" | ETA {remaining}")
        } else {
            String::new()
        };
        format!(
            "{} [{}] {:5.1}% {} / {} | {}{} | Elapsed {}",
            self.name,
            bar,
            percent,
            if self.completed < 1024 {
                format!("{:.2} B", self.completed as f64)
            } else {
                format_bytes(self.completed)
            },
            if self.total < 1024 {
                format!("{:.2} B", self.total as f64)
            } else {
                format_bytes(self.total)
            },
            if done {
                "Done".to_owned()
            } else if paused {
                "Paused".to_owned()
            } else if self.status == Status::Active {
                if speed < 1024.0 {
                    format!("{speed:.2} B/s")
                } else {
                    format!("{}/s", format_bytes(speed as u64))
                }
            } else {
                self.status.label().to_owned()
            },
            eta,
            duration(elapsed.as_secs())
        )
    }
}

struct State {
    rows: BTreeMap<usize, Row>,
    closed: Option<bool>,
    paused: bool,
    started: Instant,
    finished: Option<Instant>,
}

struct Overall {
    row: Row,
    speed: f64,
    totals: Totals,
}

impl Overall {
    fn render(&self, paused: bool, now: Instant) -> String {
        let mut line = self.row.render_rate(paused, now, self.speed);
        line.push_str(&format!(
            " | {}/{} files",
            self.totals.finished, self.totals.items
        ));
        if self.totals.failed != 0 {
            line.push_str(&format!(", {} failed", self.totals.failed));
        }
        line
    }
}

impl State {
    fn overall(&self, now: Instant) -> Result<Overall> {
        let mut totals = Totals {
            total: 0,
            completed: 0,
            items: 0,
            finished: 0,
            failed: 0,
            status: Status::Active,
        };
        let mut speed = 0.0;
        let mut failed = false;
        for row in self.rows.values() {
            failed |= matches!(row.status, Status::Failed | Status::Canceled);
            if row.summary {
                continue;
            }
            totals.total = totals
                .total
                .checked_add(row.total)
                .ok_or_else(|| Error::invalid("Transfer byte total overflows"))?;
            totals.completed = totals
                .completed
                .checked_add(row.completed)
                .ok_or_else(|| Error::invalid("Completed transfer byte total overflows"))?;
            totals.items += 1;
            totals.finished += usize::from(
                row.status == Status::Complete
                    || (!row.deferred
                        && !row.status.terminal()
                        && row.total > 0
                        && row.completed >= row.total),
            );
            totals.failed += usize::from(row.status == Status::Failed);
            if !row.status.terminal() {
                speed += row.rate.current(now);
            }
        }
        totals.status = if failed || self.closed == Some(false) {
            Status::Failed
        } else if self.closed == Some(true) {
            Status::Complete
        } else {
            Status::Active
        };
        let row = Row {
            name: "Overall".into(),
            total: totals.total,
            completed: totals.completed,
            rate: RollingRate::default(),
            started: self.started,
            finished: self.finished,
            status: totals.status,
            summary: true,
            deferred: true,
        };
        Ok(Overall { row, speed, totals })
    }

    fn visible(&self) -> (Vec<Row>, usize) {
        let mut selected = Vec::with_capacity(MAX_VISIBLE_FILE_ROWS);
        for priority in 0..3 {
            for (&id, row) in &self.rows {
                let rank = if matches!(
                    row.status,
                    Status::Active | Status::Verifying | Status::Paused
                ) {
                    0
                } else if row.status == Status::Queued {
                    1
                } else {
                    2
                };
                if rank == priority {
                    selected.push((id, row));
                    if selected.len() == MAX_VISIBLE_FILE_ROWS {
                        break;
                    }
                }
            }
            if selected.len() == MAX_VISIBLE_FILE_ROWS {
                break;
            }
        }
        selected.sort_unstable_by_key(|(id, _)| *id);
        let hidden = self.rows.len().saturating_sub(selected.len());
        (
            selected.into_iter().map(|(_, row)| row.clone()).collect(),
            hidden,
        )
    }
}

type Shared = Arc<(Mutex<State>, Condvar)>;

#[path = "progress_renderer.rs"]
mod renderer;

pub struct Progress {
    shared: Shared,
    renderer: Option<std::thread::JoinHandle<Result<()>>>,
}

impl Progress {
    pub fn new(visible: bool) -> Self {
        Self::with_renderer(visible && std::io::stderr().is_terminal(), |shared| {
            renderer::spawn(shared, |line, closed| {
                let mut stderr = std::io::stderr().lock();
                write!(stderr, "\r\x1b[2K{line}")?;
                if closed {
                    writeln!(stderr)?;
                }
                stderr.flush()
            })
        })
    }

    fn with_renderer(
        visible: bool,
        factory: impl FnOnce(Shared) -> std::thread::JoinHandle<Result<()>>,
    ) -> Self {
        let shared = Arc::new((
            Mutex::new(State {
                rows: BTreeMap::new(),
                closed: None,
                paused: false,
                started: Instant::now(),
                finished: None,
            }),
            Condvar::new(),
        ));
        let renderer = visible.then(|| factory(shared.clone()));
        Self { shared, renderer }
    }

    pub fn frame(&self) -> Result<(Vec<String>, usize)> {
        self.frame_at(Instant::now())
    }

    fn frame_at(&self, now: Instant) -> Result<(Vec<String>, usize)> {
        let state = self.shared.0.lock().map_err(poisoned)?;
        let (rows, hidden) = state.visible();
        let paused = state.paused;
        drop(state);
        Ok((
            rows.iter().map(|row| row.render_at(paused, now)).collect(),
            hidden,
        ))
    }

    pub fn totals(&self) -> Result<Totals> {
        Ok(self
            .shared
            .0
            .lock()
            .map_err(poisoned)?
            .overall(Instant::now())?
            .totals)
    }

    #[cfg(test)]
    fn overall_at(&self, now: Instant) -> Result<String> {
        let state = self.shared.0.lock().map_err(poisoned)?;
        let overall = state.overall(now)?;
        let paused = state.paused;
        drop(state);
        Ok(overall.render(paused, now))
    }

    pub fn close(&mut self, success: bool) -> Result<bool> {
        self.close_at(success, Instant::now())
    }

    fn close_at(&mut self, success: bool, now: Instant) -> Result<bool> {
        let outcome = (|| {
            let mut state = self.shared.0.lock().map_err(poisoned)?;
            if let Some(outcome) = state.closed {
                return Ok(outcome);
            }
            let mut success = success;
            for row in state.rows.values_mut() {
                if !row.status.terminal() {
                    row.status = if !row.deferred && row.total > 0 && row.completed >= row.total {
                        Status::Complete
                    } else {
                        Status::Canceled
                    };
                    row.finished = Some(now);
                }
                if matches!(row.status, Status::Failed | Status::Canceled) {
                    success = false;
                }
            }
            state.paused = false;
            state.finished = Some(now);
            state.closed = Some(success);
            Ok(success)
        })();
        self.shared.1.notify_all();
        let joined = if let Some(renderer) = self.renderer.take() {
            renderer
                .join()
                .map_err(|_| Error::protocol("Transfer progress renderer was interrupted"))
                .and_then(|result| result)
        } else {
            Ok(())
        };
        if joined.is_err() {
            self.shared
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .closed = Some(false);
        }
        outcome.and_then(|success| joined.map(|()| success))
    }

    pub fn pause(&self, paused: bool) -> Result<()> {
        let mut state = self.shared.0.lock().map_err(poisoned)?;
        if state.closed.is_none() {
            state.paused = paused;
        }
        drop(state);
        self.shared.1.notify_all();
        Ok(())
    }

    pub fn add(&self, name: &str, total: u64) -> Result<usize> {
        let mut state = self.shared.0.lock().map_err(poisoned)?;
        if state.closed.is_some() {
            return Err(Error::protocol("Transfer progress is already closed"));
        }
        let id = state.rows.len();
        state.rows.insert(id, Row::new(name, total));
        Ok(id)
    }
    pub fn summary(&self, id: usize) -> Result<()> {
        let mut state = self.shared.0.lock().map_err(poisoned)?;
        let row = state
            .rows
            .get_mut(&id)
            .ok_or_else(|| Error::protocol("Unknown transfer progress item"))?;
        row.summary = true;
        row.deferred = true;
        Ok(())
    }

    pub fn defer_completion(&self, id: usize) -> Result<()> {
        let mut state = self.shared.0.lock().map_err(poisoned)?;
        let row = state
            .rows
            .get_mut(&id)
            .ok_or_else(|| Error::protocol("Unknown transfer progress item"))?;
        if row.status.terminal() {
            return Err(Error::protocol("Cannot defer a finished transfer"));
        }
        row.deferred = true;
        Ok(())
    }

    pub fn transferred(&self, id: usize) -> Result<()> {
        let mut state = self.shared.0.lock().map_err(poisoned)?;
        let row = state
            .rows
            .get_mut(&id)
            .ok_or_else(|| Error::protocol("Unknown transfer progress item"))?;
        if !row.status.terminal() {
            row.completed = row.total;
            row.status = if row.deferred {
                Status::Verifying
            } else {
                Status::Complete
            };
            if !row.deferred {
                row.finished = Some(Instant::now());
            }
        }
        Ok(())
    }

    pub fn update(&self, id: usize, completed: u64, resumed: bool) -> Result<()> {
        self.update_at(id, completed, resumed, Instant::now())
    }

    fn update_at(&self, id: usize, completed: u64, resumed: bool, now: Instant) -> Result<()> {
        let mut state = self.shared.0.lock().map_err(poisoned)?;
        let row = state
            .rows
            .get_mut(&id)
            .ok_or_else(|| Error::protocol("Unknown transfer progress item"))?;
        if !row.status.terminal() {
            row.completed = completed;
            if resumed {
                row.rate = RollingRate::default();
            }
            row.rate.update(completed, now);
            row.status = Status::Active;
        }
        Ok(())
    }
    pub fn snapshot(&self, id: usize) -> Result<Snapshot> {
        let state = self.shared.0.lock().map_err(poisoned)?;
        let row = state
            .rows
            .get(&id)
            .ok_or_else(|| Error::protocol("Unknown transfer progress item"))?;
        Ok(Snapshot {
            total: row.total,
            completed: row.completed,
            status: row.status,
        })
    }

    pub fn status(&self, id: usize, status: Status) -> Result<()> {
        let mut state = self.shared.0.lock().map_err(poisoned)?;
        let row = state
            .rows
            .get_mut(&id)
            .ok_or_else(|| Error::protocol("Unknown transfer progress item"))?;
        if row.status.terminal() {
            return Ok(());
        }
        row.status = status;
        if status.terminal() {
            row.finished = Some(Instant::now());
            if status == Status::Complete {
                row.completed = row.total
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "progress_lifecycle_tests.rs"]
mod lifecycle_tests;
#[cfg(test)]
#[path = "progress_overall_tests.rs"]
mod overall_tests;
#[cfg(test)]
#[path = "progress_speed_tests.rs"]
mod speed_tests;

impl Drop for Progress {
    fn drop(&mut self) {
        if self.close(false).is_err() {
            eprintln!("[ERROR] Transfer progress could not be finalized.");
        }
    }
}
