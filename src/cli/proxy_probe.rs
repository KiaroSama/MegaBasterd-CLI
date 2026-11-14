use std::{
    collections::VecDeque,
    sync::{Mutex, mpsc},
    time::{Duration, Instant},
};

use super::context::Context;
use crate::{
    error::{Error, Result, poisoned},
    services::connect,
    terminal::redaction,
    transfers::control::Control,
};

#[cfg(test)]
#[path = "proxy_probe_tests.rs"]
mod tests;

#[derive(Clone)]
enum Verdict {
    Reachable(u128),
    Failed(&'static str),
    TimedOut,
    NotProbed,
}

fn worker_limit(count: usize, configured: Option<&str>) -> Result<usize> {
    let maximum = match configured {
        Some(value) => value
            .parse::<usize>()
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| {
                Error::invalid("HOOKMAKER_MAX_TEST_WORKERS must be a positive integer")
            })?,
        None => 64,
    };
    Ok(count.min(64).min(maximum))
}

fn reason(error: &Error) -> &'static str {
    match error {
        Error::Invalid(_) => "InvalidInput: endpoint has no supported host and port",
        Error::Io(_) => "IoError: connection refused or unavailable",
        Error::Timeout => "TimeoutError: no answer within the configured timeout",
        Error::Protocol(_) => "ProtocolError: endpoint DNS failed or was refused",
        _ => "ProbeError: endpoint request failed",
    }
}

fn probe_all(
    urls: Vec<String>,
    timeout: Duration,
    workers: usize,
    control: &Control,
    probe: impl Fn(&str, Duration, &Control) -> Result<()> + Sync,
) -> Result<Vec<Verdict>> {
    control.checkpoint()?;
    if urls.is_empty() {
        return Ok(Vec::new());
    }
    if timeout.is_zero() || workers == 0 {
        return Err(Error::invalid("Proxy probe bounds must be positive"));
    }
    let workers = workers.min(urls.len());
    let waves = u32::try_from(urls.len().div_ceil(workers)).map_err(|_| Error::Timeout)?;
    let deadline = Instant::now()
        .checked_add(timeout.checked_mul(waves).ok_or(Error::Timeout)?)
        .ok_or(Error::Timeout)?;
    let pending = Mutex::new(VecDeque::from_iter(urls.into_iter().enumerate()));
    let rows = Mutex::new(vec![
        Verdict::NotProbed;
        pending.lock().map_err(poisoned)?.len()
    ]);
    let stop = Control::new();
    struct StopOnDrop(Control);
    impl Drop for StopOnDrop {
        fn drop(&mut self) {
            self.0.cancel();
        }
    }
    let (finished, done) = mpsc::channel();
    std::thread::scope(|scope| -> Result<()> {
        let _stop_on_failure = StopOnDrop(stop.clone());
        let mut threads = Vec::new();
        for _ in 0..workers {
            let finished = finished.clone();
            let probe = &probe;
            let pending = &pending;
            let rows = &rows;
            let stop = &stop;
            threads.push(scope.spawn(move || -> Result<()> {
                let result = (|| {
                    loop {
                        if stop.is_canceled() || Instant::now() >= deadline {
                            return Ok(());
                        }
                        let Some((index, url)) = pending.lock().map_err(poisoned)?.pop_front()
                        else {
                            return Ok(());
                        };
                        rows.lock().map_err(poisoned)?[index] = Verdict::TimedOut;
                        let started = Instant::now();
                        let result = probe(&url, timeout, stop);
                        let verdict = if stop.is_canceled() || Instant::now() >= deadline {
                            Verdict::TimedOut
                        } else {
                            match result {
                                Ok(()) => Verdict::Reachable(started.elapsed().as_millis()),
                                Err(error) => Verdict::Failed(reason(&error)),
                            }
                        };
                        rows.lock().map_err(poisoned)?[index] = verdict;
                    }
                })();
                let _ = finished.send(());
                result
            }));
        }
        drop(finished);
        let mut completed = 0;
        while completed < workers && !control.is_canceled() && Instant::now() < deadline {
            match done.recv_timeout(
                Duration::from_millis(25).min(deadline.saturating_duration_since(Instant::now())),
            ) {
                Ok(()) => completed += 1,
                Err(mpsc::RecvTimeoutError::Timeout) => (),
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        stop.cancel();
        let mut failure = None;
        for thread in threads {
            match thread.join() {
                Ok(Ok(())) => (),
                Ok(Err(error)) => {
                    if failure.is_none() {
                        failure = Some(error);
                    }
                }
                Err(_) => {
                    if failure.is_none() {
                        failure = Some(Error::protocol("Proxy probe worker was interrupted"));
                    }
                }
            }
        }
        if control.is_canceled() {
            return Err(Error::Canceled);
        }
        if let Some(error) = failure {
            return Err(error);
        }
        Ok(())
    })?;
    rows.into_inner().map_err(poisoned)
}

pub(super) fn run(context: &Context, urls: Vec<String>) -> Result<()> {
    if urls.is_empty() {
        return Err(Error::protocol("No proxies stored; nothing to test."));
    }
    let configured = std::env::var("HOOKMAKER_MAX_TEST_WORKERS")
        .map(Some)
        .or_else(|error| match error {
            std::env::VarError::NotPresent => Ok(None),
            _ => Err(Error::invalid(
                "HOOKMAKER_MAX_TEST_WORKERS must be a positive integer",
            )),
        })?;
    let workers = worker_limit(urls.len(), configured.as_deref())?;
    run_with(context, urls, workers, |url, timeout, control| {
        connect::probe_proxy(url, timeout, control).map(drop)
    })
}

fn run_with(
    context: &Context,
    urls: Vec<String>,
    workers: usize,
    probe: impl Fn(&str, Duration, &Control) -> Result<()> + Sync,
) -> Result<()> {
    let timeout = Duration::from_secs(context.config.timeout_seconds);
    let verdicts = probe_all(urls.clone(), timeout, workers, &context.control, probe)?;
    let reachable = verdicts
        .iter()
        .filter(|row| matches!(row, Verdict::Reachable(_)))
        .count();
    let rows = urls
        .iter()
        .zip(verdicts)
        .map(|(url, verdict)| {
            let (yes, detail) = match verdict {
                Verdict::Reachable(ms) => (true, format!("{ms} ms")),
                Verdict::Failed(reason) => (false, reason.to_owned()),
                Verdict::TimedOut => (false, format!("no answer within {}s", timeout.as_secs())),
                Verdict::NotProbed => (false, "not probed within the run budget".into()),
            };
            vec![
                redaction::text(url),
                if yes { "yes" } else { "no" }.into(),
                detail,
            ]
        })
        .collect::<Vec<_>>();
    context
        .output
        .table(&["URL", "Reachable", "Latency / reason"], &rows)?;
    context
        .output
        .message("INFO", &format!("{reachable}/{} reachable.", urls.len()))?;
    if reachable == 0 {
        return Err(Error::protocol("No configured proxy endpoint is reachable"));
    }
    Ok(())
}
