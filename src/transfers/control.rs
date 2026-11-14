use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::error::{Error, Result, poisoned};

#[derive(Default)]
struct State {
    paused: bool,
    canceled: bool,
}

#[derive(Clone, Default)]
pub struct Control(Arc<(Mutex<State>, Condvar)>);

impl Control {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        let (mutex, changed) = &*self.0;
        match mutex.lock() {
            Ok(mut state) => state.canceled = true,
            Err(error) => error.into_inner().canceled = true,
        }
        changed.notify_all();
    }

    pub fn is_canceled(&self) -> bool {
        self.0.0.lock().map_or(true, |state| state.canceled)
    }

    pub fn toggle_pause(&self) -> Result<bool> {
        let (mutex, changed) = &*self.0;
        let mut state = mutex.lock().map_err(poisoned)?;
        if state.canceled {
            return Err(Error::Canceled);
        }
        state.paused = !state.paused;
        changed.notify_all();
        Ok(state.paused)
    }

    pub fn checkpoint(&self) -> Result<()> {
        self.checkpoint_with_deadline(None)
    }

    pub(crate) fn checkpoint_until(&self, deadline: Instant) -> Result<()> {
        self.checkpoint_with_deadline(Some(deadline))
    }

    fn checkpoint_with_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        let (mutex, changed) = &*self.0;
        let mut state = mutex.lock().map_err(poisoned)?;
        loop {
            if state.canceled {
                return Err(Error::Canceled);
            }
            let remaining =
                deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()));
            if remaining.is_some_and(|remaining| remaining.is_zero()) {
                return Err(Error::Timeout);
            }
            if !state.paused {
                return Ok(());
            }
            state = if let Some(remaining) = remaining {
                changed.wait_timeout(state, remaining).map_err(poisoned)?.0
            } else {
                changed.wait(state).map_err(poisoned)?
            };
        }
    }

    pub fn wait(&self, duration: Duration) -> Result<()> {
        let deadline = Instant::now()
            .checked_add(duration)
            .ok_or_else(|| Error::invalid("Wait duration is too large"))?;
        let (mutex, changed) = &*self.0;
        let mut state = mutex.lock().map_err(poisoned)?;
        loop {
            if state.canceled {
                return Err(Error::Canceled);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(());
            }
            let (next, _) = changed.wait_timeout(state, remaining).map_err(poisoned)?;
            state = next;
        }
    }
}

#[cfg(test)]
std::thread_local! {
    static LIMITER_OBSERVER: std::cell::RefCell<Option<std::sync::mpsc::SyncSender<(usize, usize)>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn observe_limiters<T>(
    sender: std::sync::mpsc::SyncSender<(usize, usize)>,
    run: impl FnOnce() -> T,
) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            LIMITER_OBSERVER.with(|observer| {
                observer.borrow_mut().take();
            });
        }
    }
    LIMITER_OBSERVER.with(|observer| {
        let mut observer = observer.borrow_mut();
        assert!(observer.is_none(), "limiter observer is already active");
        *observer = Some(sender);
    });
    let _reset = Reset;
    run()
}

#[cfg(test)]
#[path = "limiter_tests.rs"]
mod limiter_tests;

pub struct RateLimiter {
    bytes_per_second: f64,
    next: Mutex<Instant>,
    #[cfg(test)]
    observer: Option<std::sync::mpsc::SyncSender<(usize, usize)>>,
}

impl RateLimiter {
    pub fn new(kbps: f64) -> Result<Self> {
        if !kbps.is_finite() || kbps < 0.0 || !(kbps * 1024.0).is_finite() {
            return Err(Error::invalid(
                "Speed limit must be a finite non-negative number",
            ));
        }
        Ok(Self {
            bytes_per_second: kbps * 1024.0,
            next: Mutex::new(Instant::now()),
            #[cfg(test)]
            observer: LIMITER_OBSERVER.with(|observer| observer.borrow().clone()),
        })
    }

    pub fn acquire(&self, bytes: usize, control: &Control) -> Result<()> {
        #[cfg(test)]
        if let Some(observer) = &self.observer {
            assert!(
                observer
                    .try_send((std::ptr::from_ref(self) as usize, bytes))
                    .is_ok(),
                "limiter observation bound exceeded or receiver disconnected"
            );
        }
        self.acquire_with(bytes, control, Instant::now, |wait| control.wait(wait))
    }

    fn acquire_with(
        &self,
        bytes: usize,
        control: &Control,
        now: impl FnOnce() -> Instant,
        wait: impl FnOnce(Duration) -> Result<()>,
    ) -> Result<()> {
        if self.bytes_per_second == 0.0 || bytes == 0 {
            return control.checkpoint();
        }
        // Reservations serialize an aggregate cap; each network block can exceed a burst without starving.
        let duration = {
            let mut next = self.next.lock().map_err(poisoned)?;
            let now = now();
            let start = (*next).max(now);
            let seconds = bytes as f64 / self.bytes_per_second;
            let duration = Duration::try_from_secs_f64(seconds)
                .map_err(|_| Error::invalid("Speed limit produces an unsupported wait duration"))?;
            *next = start
                .checked_add(duration)
                .ok_or_else(|| Error::invalid("Rate-limit deadline overflows"))?;
            next.saturating_duration_since(now)
        };
        wait(duration)?;
        control.checkpoint()
    }
}
