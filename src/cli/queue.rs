// SPDX-License-Identifier: GPL-3.0-or-later
//! Sequential queue orchestration. The caller supplies the real transfer executor.
#[cfg(test)]
#[path = "queue_progress_tests.rs"]
mod progress_tests;
#[cfg(test)]
#[path = "queue_runner_tests.rs"]
mod runner_tests;

use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use super::{args, context::Context};
use crate::{
    error::{Error, Result},
    services::hooks,
    storage::{
        files::random_id,
        queue::{JobStatus, JobType, LEASE_SECONDS, Queue, QueueItem, QueuePayload},
    },
    terminal::{
        progress::{Progress, Status},
        prompts,
    },
    transfers::control::Control,
};

#[derive(Clone, Copy)]
pub struct HeartbeatTiming {
    pub interval: Duration,
    pub grace: Duration,
}
impl Default for HeartbeatTiming {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(30),
            grace: Duration::from_secs(150),
        }
    }
}
impl HeartbeatTiming {
    fn validate(self) -> Result<()> {
        if self.interval.is_zero()
            || self.interval >= self.grace
            || self.grace > Duration::from_secs(LEASE_SECONDS as u64 / 2)
        {
            return Err(Error::invalid(
                "Queue heartbeat needs a positive interval no longer than its grace, at most half the lease",
            ));
        }
        Ok(())
    }
}

#[derive(Default, Debug)]
pub struct RunSummary {
    pub succeeded: usize,
    pub failed: usize,
    pub recovered: usize,
}

struct Heartbeat {
    stop: mpsc::SyncSender<()>,
    worker: Option<JoinHandle<Result<()>>>,
    lost: Arc<AtomicBool>,
}
impl Heartbeat {
    fn start(
        queue: &Queue,
        lease: &QueueItem,
        control: &Control,
        timing: HeartbeatTiming,
    ) -> Result<Self> {
        let queue = Queue::new(queue.path());
        let lease = lease.clone();
        let control = control.clone();
        let (stop, receive) = mpsc::sync_channel(1);
        let lost = Arc::new(AtomicBool::new(false));
        let failed = lost.clone();
        let cancel = control.clone();
        let worker = std::thread::Builder::new().name("queue-heartbeat".into()).spawn(move || {
            let result = catch_unwind(AssertUnwindSafe(|| {
                let mut last_ok = Instant::now();
                loop {
                    match receive.recv_timeout(timing.interval.min(timing.grace.saturating_sub(last_ok.elapsed()))) {
                        Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
                        Err(mpsc::RecvTimeoutError::Timeout) => (),
                    }
                    if last_ok.elapsed() >= timing.grace {
                        return Err(Error::Busy("Queue lease heartbeat could not renew within its grace; transfer stopped".into()));
                    }
                    let remaining = timing.grace.saturating_sub(last_ok.elapsed());
                    let timeout = Duration::from_secs(10).min(timing.interval).min(remaining);
                    let renewal = Queue::new(queue.path()).with_lock_timeout(timeout).touch(&lease);
                    // A lock acquired after grace cannot retroactively make the transfer healthy.
                    if last_ok.elapsed() >= timing.grace {
                        return Err(Error::Busy("Queue lease heartbeat could not renew within its grace; transfer stopped".into()));
                    }
                    match renewal {
                        Ok(true) => last_ok = Instant::now(),
                        Ok(false) => return Err(Error::Busy("Queue lease was lost; transfer stopped".into())),
                        Err(Error::Busy(_)) => (),
                        Err(error) => return Err(error),
                    }
                }
            })).unwrap_or_else(|_| Err(Error::protocol("Queue heartbeat was interrupted; transfer stopped")));
            if result.is_err() { failed.store(true, Ordering::Release); cancel.cancel(); }
            result
        })?;
        Ok(Self {
            stop,
            worker: Some(worker),
            lost,
        })
    }
    fn finish(&mut self) -> Result<()> {
        let _ = self.stop.try_send(());
        match self.worker.take() {
            Some(worker) => worker
                .join()
                .map_err(|_| Error::protocol("Queue heartbeat could not be reaped"))?,
            None => Ok(()),
        }
    }
}
impl Drop for Heartbeat {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

/// Executor runs synchronously, honors `control`, and reaps its workers before returning.
/// No arbitrary callback preemption: the retained native claim prevents overlapping executors.
pub fn run(
    queue: &Queue,
    control: &Control,
    timing: HeartbeatTiming,
    mut execute: impl FnMut(&QueueItem, &QueuePayload) -> Result<()>,
) -> Result<RunSummary> {
    let mut summary = RunSummary::default();
    run_inner(queue, control, timing, &mut summary, None, &mut execute)?;
    Ok(summary)
}

fn run_inner(
    queue: &Queue,
    control: &Control,
    timing: HeartbeatTiming,
    summary: &mut RunSummary,
    progress: Option<&Progress>,
    execute: &mut impl FnMut(&QueueItem, &QueuePayload) -> Result<()>,
) -> Result<()> {
    timing.validate()?;
    let budget = queue.list()?.len();
    if budget == 0 {
        return Ok(());
    }
    summary.recovered = queue.recover_interrupted()?.len();
    let run_id = random_id()?;
    // Bound one invocation to the initial queue length; concurrent producers cannot keep it alive forever.
    for _ in 0..budget {
        control.checkpoint()?;
        let Some(claim) = queue.claim_next(&run_id)? else {
            break;
        };
        let row = progress
            .map(|progress| {
                let direction = match claim.item.kind {
                    JobType::Upload => "↑ Upload",
                    JobType::Download => "↓ Download",
                };
                let row = progress.add(&format!("Job {} {direction}", claim.item.id), 0)?;
                progress.defer_completion(row)?;
                progress.status(row, Status::Active)?;
                Ok::<_, Error>(row)
            })
            .transpose()?;
        let mut executed = false;
        let execution = (|| {
            let mut heartbeat = Heartbeat::start(queue, &claim.item, control, timing)?;
            let result = (|| {
                let payload = queue.payload(&claim.item)?;
                control.checkpoint()?;
                if heartbeat.lost.load(Ordering::Acquire) || !queue.touch(&claim.item)? {
                    return Err(Error::Busy("Queue lease was lost before execution".into()));
                }
                executed = true;
                let result = catch_unwind(AssertUnwindSafe(|| execute(&claim.item, &payload)))
                    .unwrap_or_else(|_| {
                        Err(Error::protocol("Queue transfer executor was interrupted"))
                    });
                if matches!(&result, Err(error) if !matches!(error, Error::Canceled)) {
                    summary.failed += 1;
                }
                result
            })();
            // Do not stop heartbeating until the synchronous executor has returned/reaped its workers.
            heartbeat.finish()?;
            result
        })();
        match execution {
            Ok(()) => {
                // A completed transfer must not become runnable again if cancellation races with return.
                if let Err(error) = queue.finish(&claim.item, JobStatus::Done, None) {
                    if let (Some(progress), Some(row)) = (progress, row) {
                        progress.status(row, Status::Failed)?;
                    }
                    return Err(error);
                }
                if let (Some(progress), Some(row)) = (progress, row) {
                    progress.status(row, Status::Complete)?;
                }
                summary.succeeded += 1;
                if control.is_canceled() {
                    return Err(Error::Canceled);
                }
            }
            Err(Error::Canceled) => {
                if let (Some(progress), Some(row)) = (progress, row) {
                    progress.status(row, Status::Canceled)?;
                }
                queue.finish(&claim.item, JobStatus::Interrupted, None)?;
                return Err(Error::Canceled);
            }
            Err(error) => {
                if let (Some(progress), Some(row)) = (progress, row) {
                    progress.status(
                        row,
                        if control.is_canceled() {
                            Status::Canceled
                        } else {
                            Status::Failed
                        },
                    )?;
                }
                // Heartbeat/corruption/ownership failures abort the run, never claim more work.
                if !executed
                    || control.is_canceled()
                    || matches!(&error, Error::Corrupt(_) | Error::AmbiguousMutation(_))
                {
                    return Err(error);
                }
                queue.finish(&claim.item, JobStatus::Failed, Some(&error.to_string()))?;
            }
        }
    }
    Ok(())
}

fn run_command_with(
    context: &mut Context,
    queue: &Queue,
    timing: HeartbeatTiming,
    auth: &args::VaultOptions,
    progress: &mut Progress,
    mut execute: impl FnMut(&mut Context, &QueueItem, &QueuePayload, &args::VaultOptions) -> Result<()>,
) -> Result<()> {
    context.require_config()?;
    let control = context.control.clone();
    let mut summary = RunSummary::default();
    let result = run_inner(
        queue,
        &control,
        timing,
        &mut summary,
        Some(progress),
        &mut |item, payload| {
            context.event(
                "queue",
                "Transfer started",
                &serde_json::json!({"job_id":item.id,"generation":item.lease_epoch}),
            );
            let result = execute(context, item, payload, auth);
            if let Err(error) = &result {
                context.diagnostic(
                    "ERROR",
                    "QUEUE",
                    &format!("Job {} failed ({})", item.id, error.code()),
                    &serde_json::json!({"job_id":item.id,"error_code":error.code()}),
                );
            }
            context.event(
                "queue",
                "Transfer executor returned",
                &serde_json::json!({"job_id":item.id,"success":result.is_ok()}),
            );
            result
        },
    );
    let closed = progress.close(result.is_ok() && summary.failed == 0);
    let reporting = (|| -> Result<()> {
        if !context.output.quiet && !context.output.json {
            let (rows, hidden) = progress.frame()?;
            for row in rows {
                context.output.message("INFO", &row)?;
            }
            if hidden != 0 {
                context.output.message(
                    "INFO",
                    &format!(
                        "{hidden} additional queue job rows; use queue list for saved results."
                    ),
                )?;
            }
        }
        if hooks::after_batch(
            context.config.all_finished_command.as_deref(),
            "queue",
            summary.succeeded,
            summary.failed,
            &control,
            &context.output,
        )
        .is_err()
        {
            context.output.message(
                "WARNING",
                "Configured queue completion command failed; transfer results are unchanged.",
            )?;
        }
        Ok(())
    })();
    // Reporting failure must not replace cancellation, corruption or an uncertain mutation.
    result?;
    closed?;
    reporting?;
    context.event("queue", "Run finished", &serde_json::json!({"succeeded":summary.succeeded,"failed":summary.failed,"recovered":summary.recovered}));
    if summary.failed != 0 {
        Err(Error::protocol(format!(
            "{} queue job(s) failed.",
            summary.failed
        )))
    } else if summary.succeeded == 0 {
        context.output.message("SUCCESS", "Queue is empty.")
    } else {
        context.output.message(
            "SUCCESS",
            &format!("{} queue job(s) completed.", summary.succeeded),
        )
    }
}

/// `execute` must perform a real download/upload; dispatcher owns account/transport integration.
pub fn handle(
    context: &mut Context,
    command: args::Queue,
    execute: impl FnMut(&mut Context, &QueueItem, &QueuePayload, &args::VaultOptions) -> Result<()>,
) -> Result<()> {
    let queue = Queue::new(context.paths.queue());
    handle_with(
        context,
        command,
        &queue,
        HeartbeatTiming::default(),
        execute,
    )
}

fn handle_with(
    context: &mut Context,
    command: args::Queue,
    queue: &Queue,
    timing: HeartbeatTiming,
    execute: impl FnMut(&mut Context, &QueueItem, &QueuePayload, &args::VaultOptions) -> Result<()>,
) -> Result<()> {
    match command {
        args::Queue::List => {
            let items = queue.list()?;
            if items.is_empty() {
                return context.output.message("INFO", "Queue is empty.");
            }
            let rows = items
                .iter()
                .map(|item| {
                    let payload = queue.payload(item)?;
                    Ok(vec![
                        item.id.clone(),
                        format!("{:?}", item.kind).to_lowercase(),
                        payload.source.clone(),
                        payload.destination.clone(),
                        item.size.to_string(),
                        item.status.label().into(),
                    ])
                })
                .collect::<Result<Vec<_>>>()?;
            context.output.table(
                &["ID", "Type", "Source", "Destination", "Size", "Status"],
                &rows,
            )
        }
        args::Queue::AddDownload {
            url,
            output,
            password,
        } => {
            let payload = QueuePayload {
                source: url,
                destination: output,
                account: None,
                password,
                error: None,
            };
            let id = queue.add(JobType::Download, &payload)?;
            context.event(
                "queue",
                "Download queued",
                &serde_json::json!({"job_id":id}),
            );
            context.output.message(
                "SUCCESS",
                &format!("Queued download {id}: {}", payload.source),
            )
        }
        args::Queue::AddUpload { path, account } => {
            let metadata = std::fs::symlink_metadata(&path)?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(Error::invalid(
                    "Queued upload needs a regular, non-symlink file",
                ));
            }
            let path = std::fs::canonicalize(path)?;
            let source = path
                .to_str()
                .ok_or_else(|| Error::invalid("Queued upload path is not UTF-8"))?
                .to_owned();
            let payload = QueuePayload {
                source,
                destination: String::new(),
                account,
                password: None,
                error: None,
            };
            let id = queue.add(JobType::Upload, &payload)?;
            context.event("queue", "Upload queued", &serde_json::json!({"job_id":id}));
            context.output.message(
                "SUCCESS",
                &format!("Queued upload {id}: {}", payload.source),
            )
        }
        args::Queue::Remove { item_id } => {
            if !queue.remove(&item_id)? {
                return Err(Error::invalid(format!("Not found: {item_id}")));
            }
            context.event(
                "queue",
                "Item removed",
                &serde_json::json!({"job_id":item_id}),
            );
            context
                .output
                .message("SUCCESS", &format!("Removed {item_id}"))
        }
        args::Queue::Retry { item_id } => {
            let count = if item_id == "all" {
                queue.retry_all()?
            } else if queue.retry(&item_id)? {
                1
            } else {
                return Err(Error::invalid(format!(
                    "Not found or not retryable: {item_id}"
                )));
            };
            context.event(
                "queue",
                "Items returned to pending",
                &serde_json::json!({"count":count}),
            );
            context
                .output
                .message("SUCCESS", &format!("Retrying {count} item(s)."))
        }
        args::Queue::Clear => {
            queue.list()?;
            if !prompts::confirmed("Clear completed and canceled items?", true)? {
                return Ok(());
            }
            let count = queue.clear_done()?;
            context.event(
                "queue",
                "Completed items cleared",
                &serde_json::json!({"count":count}),
            );
            context
                .output
                .message("SUCCESS", &format!("Removed {count} items."))
        }
        args::Queue::Reset => {
            if !prompts::confirmed("Discard the current queue and start empty?", false)? {
                return Ok(());
            }
            queue.reset()?;
            context.event("queue", "Queue explicitly reset", &serde_json::json!({}));
            context.output.message("SUCCESS", "Queue reset to empty.")
        }
        args::Queue::Run { auth } => {
            // File executors own live rendering; queue rows are emitted after they have stopped.
            let mut progress = Progress::new(false);
            run_command_with(context, queue, timing, &auth, &mut progress, execute)
        }
    }
}
