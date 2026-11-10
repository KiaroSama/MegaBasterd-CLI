use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

use serde_json::json;

use super::{accounts::quota, args::Upload, context::Context};
use crate::error::{Error, Result, poisoned};
use crate::protocol::cloud::Cloud;
use crate::services::{hooks, local_crypto::open_source};
use crate::storage::vault::Vault;
use crate::terminal::{
    input::Input,
    progress::{Progress, Status, format_bytes},
};
use crate::transfers::{
    accounts::QuotaLedger,
    control::RateLimiter,
    upload::{self, Uploaded},
    upload_tree::{self, Manifest},
    upload_tree_state::Journal,
};

const MAX_JOBS: usize = 200_000;
const MAX_CHUNK_WORKERS: u32 = 64;

struct Job {
    path: PathBuf,
    size: u64,
    tree: Option<Manifest>,
    item: usize,
}

pub fn dispatch(context: &mut Context, command: Upload) -> Result<i32> {
    execute(context, command, true, None)
}

pub fn execute(
    context: &mut Context,
    command: Upload,
    batch_command: bool,
    operation: Option<&str>,
) -> Result<i32> {
    context.require_config()?;
    if command.paths.is_empty() {
        return Err(Error::invalid("Upload requires a local source"));
    }
    let workers = command.workers.unwrap_or(context.config.upload_workers);
    let parallel = command
        .parallel
        .unwrap_or(context.config.max_parallel_uploads);
    if !(1..=64).contains(&workers) || !(1..=32).contains(&parallel) {
        return Err(Error::invalid(
            "Upload workers must be 1..64 and parallel files 1..32",
        ));
    }
    let limiter = RateLimiter::new(
        command
            .limit
            .unwrap_or(context.config.upload_speed_limit_kbps),
    )?;
    let data = context.accounts().list()?;
    if data.accounts.is_empty() {
        return Err(Error::Auth(
            "No accounts found. Use mb account add first.".into(),
        ));
    }
    let vault = context.vault(command.auth.vault_passphrase.as_deref())?;
    let auto = command.auto_account && command.auth.account.is_none();
    let mut free: BTreeMap<_, _> = data
        .accounts
        .iter()
        .filter_map(|account| {
            Some((
                account.email.clone(),
                account.quota_total?.saturating_sub(account.quota_used?),
            ))
        })
        .collect();
    if auto && free.is_empty() {
        return Err(Error::invalid(
            "--auto-account needs cached quotas; run mb account refresh-all first.",
        ));
    }
    let selected = if auto {
        None
    } else {
        Some(context.selected_account(command.auth.account.as_deref())?)
    };
    let mut clients = BTreeMap::new();
    // Resolve credentials and MFA on the caller thread before raw terminal input or transfer workers.
    for account in data.accounts.iter().filter(|account| {
        auto || selected
            .as_ref()
            .is_some_and(|chosen| chosen.email == account.email)
    }) {
        match context.session(account, &vault, command.auth.mfa_code.as_deref(), None) {
            Ok((api, session)) => {
                clients.insert(account.email.clone(), Cloud::new(api, session));
            }
            Err(error) if auto => {
                // Zero free bytes still admits empty files; an unavailable account is not eligible.
                free.remove(&account.email);
                context.output.message(
                    "WARNING",
                    &format!("Account is unavailable for this batch: {error}"),
                )?;
            }
            Err(error) => return Err(error),
        }
    }
    if clients.is_empty() {
        return Err(Error::Auth(
            "No stored account could be authenticated".into(),
        ));
    }
    let ledger = auto.then(|| QuotaLedger::new(free));
    let fixed = selected.map(|account| account.email);
    let mut progress = Progress::new(!command.json && !context.output.quiet);
    let mut jobs = VecDeque::new();
    for path in &command.paths {
        context.control.checkpoint()?;
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() {
            return Err(Error::invalid("Upload root cannot be a symbolic link"));
        }
        if metadata.is_dir() {
            let manifest = upload_tree::walk(path, &context.control)?;
            if manifest.skipped != 0 {
                context.output.message("WARNING", &format!("Skipped {} symlink/reparse or unsupported entries; the uploaded tree is deliberately incomplete.",manifest.skipped))?;
            }
            if command.keep_structure {
                let item = progress.add(&path.to_string_lossy(), manifest.bytes)?;
                jobs.push_back(Job {
                    path: path.clone(),
                    size: manifest.bytes,
                    tree: Some(manifest),
                    item,
                });
            } else {
                for entry in manifest.entries.iter().filter(|entry| !entry.directory) {
                    let file = path.join(&entry.relative);
                    let item = progress.add(&file.to_string_lossy(), entry.size)?;
                    jobs.push_back(Job {
                        path: file,
                        size: entry.size,
                        tree: None,
                        item,
                    });
                    if jobs.len() > MAX_JOBS {
                        return Err(Error::invalid("Upload manifest exceeds 200000 jobs"));
                    }
                }
            }
        } else {
            let (_directory, file) = open_source(path)?;
            let size = file.metadata()?.len();
            let item = progress.add(&path.to_string_lossy(), size)?;
            jobs.push_back(Job {
                path: path.clone(),
                size,
                tree: None,
                item,
            });
        }
        if jobs.len() > MAX_JOBS {
            return Err(Error::invalid("Upload manifest exceeds 200000 jobs"));
        }
    }
    let single_file = jobs.len() == 1 && jobs.front().is_some_and(|job| job.tree.is_none());
    let slots = if command.keep_structure {
        1
    } else {
        parallel as usize
    }
    .min(jobs.len());
    let workers = if slots == 0 {
        workers
    } else {
        workers.min(MAX_CHUNK_WORKERS / slots as u32)
    };
    let pending = Mutex::new(jobs);
    let counts = Mutex::new((0usize, 0usize));
    let errors = Mutex::new(Vec::new());
    let state_directory = context.paths.user.join("Data/transfers/upload");
    let context: &Context = context;
    std::thread::scope(|scope| -> Result<()> {
        let _input = Input::start(scope, command.json, &context.control, &progress)?;
        let mut threads = Vec::new();
        for _ in 0..slots {
            threads.push(scope.spawn(|| {
                let result = (|| -> Result<()> {
                    loop {
                        context.control.checkpoint()?;
                        let Some(job) = pending.lock().map_err(poisoned)?.pop_front() else { return Ok(()); };
                        let rename = if single_file { command.rename.as_deref() } else { None };
                        let result = run_one(context, &command, &clients, ledger.as_ref(), fixed.as_deref(), &vault,
                            &job, rename, workers, &state_directory, operation, &limiter, &progress);
                        match result {
                            Ok(()) => { counts.lock().map_err(poisoned)?.0 += 1; }
                            Err(error) => {
                                counts.lock().map_err(poisoned)?.1 += 1;
                                progress.status(job.item, if matches!(error, Error::Canceled) { Status::Canceled } else { Status::Failed })?;
                                context.diagnostic("ERROR", "UPLOAD", &error.to_string(), &json!({"error_code":error.code()}));
                                context.output.record(&json!({"event":"result","type":"upload","status":"failed", "path":job.path,
                                    "error_code":error.code(),"error":error.to_string()}))?;
                                if matches!(error, Error::Canceled | Error::AmbiguousMutation(_) | Error::Corrupt(_)) { return Err(error); }
                            }
                        }
                    }
                })();
                if let Err(error) = result && let Ok(mut errors) = errors.lock() { errors.push(error); }
            }));
        }
        for thread in threads {
            if thread.join().is_err()
                && let Ok(mut errors) = errors.lock()
            {
                errors.push(Error::protocol(
                    "Upload orchestration worker was interrupted",
                ));
            }
        }
        Ok(())
    })?;
    let (succeeded, failed) = counts.into_inner().map_err(poisoned)?;
    let errors = errors.into_inner().map_err(poisoned)?;
    let worker_failed = !errors.is_empty() || !pending.into_inner().map_err(poisoned)?.is_empty();
    for error in &errors {
        context.output.message("ERROR", &error.to_string())?;
    }
    if let Err(error) = hooks::after_batch(
        if batch_command {
            context.config.all_finished_command.as_deref()
        } else {
            None
        },
        "upload",
        succeeded,
        failed,
        &context.control,
        &context.output,
    ) {
        context
            .output
            .message("WARNING", &format!("All-finished command failed: {error}"))?;
    }
    let closed = progress.close(failed == 0 && !worker_failed);
    if context.control.is_canceled() && (failed != 0 || worker_failed) {
        return Err(Error::Canceled);
    }
    if let Some(error) = errors.into_iter().next() {
        return Err(error);
    }
    Ok(if closed? { 0 } else { 1 })
}

#[allow(
    clippy::too_many_arguments,
    reason = "Explicit transfer state and cancellation dependencies at this boundary."
)]
fn run_one(
    context: &Context,
    command: &Upload,
    clients: &BTreeMap<String, Cloud>,
    ledger: Option<&QuotaLedger>,
    fixed: Option<&str>,
    vault: &Vault,
    job: &Job,
    rename: Option<&str>,
    workers: u32,
    states: &Path,
    operation: Option<&str>,
    limiter: &RateLimiter,
    progress: &Progress,
) -> Result<()> {
    let mut attempted = HashSet::new();
    loop {
        context.control.checkpoint()?;
        let email = match ledger {
            Some(ledger) => ledger.reserve(job.size, &attempted)?.ok_or_else(|| {
                Error::invalid("No stored account has enough known free space for this upload")
            })?,
            None => fixed
                .ok_or_else(|| Error::Auth("No upload account selected".into()))?
                .to_owned(),
        };
        attempted.insert(email.clone());
        let prepared = clients
            .get(&email)
            .ok_or_else(|| Error::Auth("Selected account is unavailable".into()))
            .and_then(|base| Ok(Cloud::new(base.api.fork()?, base.session.clone())));
        let mut cloud = match prepared {
            Ok(cloud) => cloud,
            Err(error) => {
                if let Some(ledger) = ledger {
                    ledger.release(&email, job.size)?;
                }
                return Err(error);
            }
        };
        let mut registered = false;
        let result = (|| {
            let target = match command.target.as_deref() {
                Some(target) => {
                    let node = cloud.find(target)?;
                    if !node.is_folder() {
                        return Err(Error::invalid("Upload target must be a folder"));
                    }
                    node.handle
                }
                None => cloud.root()?,
            };
            match &job.tree {
                Some(manifest) => structured(
                    context, command, &mut cloud, vault, job, manifest, &target, workers, states,
                    operation, limiter, progress,
                ),
                None => {
                    progress.defer_completion(job.item)?;
                    let start = Instant::now();
                    upload::upload(
                        &mut cloud,
                        &job.path,
                        &target,
                        rename,
                        workers,
                        states,
                        vault,
                        context.config.auto_resume,
                        operation,
                        limiter,
                        progress,
                        job.item,
                        &context.control,
                    )
                    .map_err(Error::transfer)
                    .and_then(|uploaded| {
                        registered = true;
                        finalize(
                            context,
                            command,
                            &mut cloud,
                            &job.path,
                            &uploaded,
                            start.elapsed().as_secs_f64(),
                        )?;
                        if operation.is_none() {
                            acknowledge(context, &uploaded);
                        }
                        progress.status(job.item, Status::Complete)?;
                        Ok(())
                    })
                }
            }
        })();
        match result {
            Ok(()) => return Ok(()),
            Err(error) => {
                if let Some(ledger) = ledger {
                    let quota_error = matches!(
                        error,
                        Error::Mega {
                            code: -17 | -24,
                            ..
                        }
                    );
                    if quota_error
                        || registered
                        || job.tree.is_some()
                        || matches!(error, Error::AmbiguousMutation(_))
                    {
                        if let Err(reconciliation) = reconcile(context, &mut cloud, ledger) {
                            context.diagnostic("WARNING", "UPLOAD", "Quota reconciliation failed; preserving the original transfer outcome", &json!({"error_code":reconciliation.code()}));
                            return Err(error);
                        }
                        if quota_error && !registered && job.tree.is_none() {
                            continue;
                        }
                    } else if let Err(release) = ledger.release(&email, job.size) {
                        context.diagnostic("WARNING", "UPLOAD", "Quota reservation cleanup failed; preserving the original transfer outcome", &json!({"error_code":release.code()}));
                    }
                }
                return Err(error);
            }
        }
    }
}

fn reconcile(context: &Context, cloud: &mut Cloud, ledger: &QuotaLedger) -> Result<()> {
    let value = cloud.api.request(json!({"a":"uq","strg":1,"xfer":1}), &[]);
    match value.and_then(|value| quota(&value)) {
        Ok((total, used)) => {
            ledger.reconcile(&cloud.session.email, total.saturating_sub(used))?;
            context
                .accounts()
                .quota(&cloud.session.email, total, used)?;
        }
        Err(_) => ledger.reconcile(&cloud.session.email, 0)?,
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "Explicit transfer state and cancellation dependencies at this boundary."
)]
fn structured(
    context: &Context,
    command: &Upload,
    cloud: &mut Cloud,
    vault: &Vault,
    job: &Job,
    manifest: &Manifest,
    target: &str,
    workers: u32,
    states: &Path,
    operation: Option<&str>,
    limiter: &RateLimiter,
    progress: &Progress,
) -> Result<()> {
    let name = job
        .path
        .file_name()
        .ok_or_else(|| Error::invalid("Upload directory needs a name"))?
        .to_string_lossy();
    let binding = serde_json::to_string(&json!([
        cloud.session.email.to_lowercase(),
        cloud.session.user_handle,
        target,
        name,
        operation
    ]))?;
    let mut journal = Journal::open(states, &job.path, &binding, operation, manifest)?;
    let root = tree_folder(&mut journal, cloud, Path::new(""), &name, target)?;
    let file_operation = journal.operation().to_owned();
    let mut parents = HashMap::from([(PathBuf::new(), root)]);
    let mut failed_parents: Vec<PathBuf> = Vec::new();
    progress.summary(job.item)?;
    let mut file_rows = HashMap::new();
    for entry in manifest.entries.iter().filter(|entry| !entry.directory) {
        let item = progress.add(&entry.relative.to_string_lossy(), entry.size)?;
        progress.defer_completion(item)?;
        file_rows.insert(entry.relative.clone(), item);
    }
    let (mut failed, mut completed) = (0usize, 0u64);
    for entry in &manifest.entries {
        context.control.checkpoint()?;
        let local = job.path.join(&entry.relative);
        let parent = entry.relative.parent().unwrap_or(Path::new(""));
        let result = (|| {
            if failed_parents
                .iter()
                .any(|failed| entry.relative.starts_with(failed))
            {
                return Err(Error::protocol("Parent cloud folder creation failed"));
            }
            let target = parents
                .get(parent)
                .ok_or_else(|| Error::protocol("Upload tree parent is missing"))?
                .clone();
            if entry.directory {
                let name = entry
                    .relative
                    .file_name()
                    .ok_or_else(|| Error::invalid("Folder has no name"))?
                    .to_string_lossy();
                let handle = tree_folder(&mut journal, cloud, &entry.relative, &name, &target)?;
                parents.insert(entry.relative.clone(), handle);
            } else {
                let item = *file_rows
                    .get(&entry.relative)
                    .ok_or_else(|| Error::protocol("Upload file progress item is missing"))?;
                let start = Instant::now();
                let uploaded = upload::upload(
                    cloud,
                    &local,
                    &target,
                    None,
                    workers,
                    states,
                    vault,
                    context.config.auto_resume,
                    Some(&file_operation),
                    limiter,
                    progress,
                    item,
                    &context.control,
                )
                .map_err(Error::transfer)?;
                finalize(
                    context,
                    command,
                    cloud,
                    &local,
                    &uploaded,
                    start.elapsed().as_secs_f64(),
                )?;
                journal.file_finished(&entry.relative, &uploaded.handle)?;
                progress.status(item, Status::Complete)?;
                // Retain each confirmed receipt until the entire tree has finished; a later
                // sibling failure must not register an already successful file a second time.
                completed = completed
                    .checked_add(entry.size)
                    .ok_or_else(|| Error::invalid("Upload tree progress overflows"))?;
                progress.update(job.item, completed, false)?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            if let Some(&item) = file_rows.get(&entry.relative) {
                progress.status(
                    item,
                    if matches!(error, Error::Canceled) {
                        Status::Canceled
                    } else {
                        Status::Failed
                    },
                )?;
            }
            if matches!(error, Error::Canceled | Error::AmbiguousMutation(_)) {
                return Err(error);
            }
            failed += 1;
            if entry.directory {
                failed_parents.push(entry.relative.clone());
            }
            context
                .output
                .message("ERROR", &format!("Directory item failed: {error}"))?;
            context.output.record(
                &json!({"event":"result","type":"upload","status":"failed", "path":local,
                "account":cloud.session.email,"error_code":error.code(),"error":error.to_string()}),
            )?;
        }
    }
    if failed != 0 {
        let error = Error::protocol(format!(
            "{failed} directory upload item(s) failed; successful remote nodes were preserved"
        ));
        return Err(if command.keep_going {
            error
        } else {
            Error::transfer(error)
        });
    }
    progress.status(job.item, Status::Complete)?;
    if journal.acknowledge().is_err() {
        let _ = context.output.message("WARNING", "Directory upload succeeded; its completion journal could not be finalized. Folder and file receipts were retained to prevent duplicate registration.");
    }
    Ok(())
}

#[cfg(test)]
#[path = "upload_tree_peer_tests.rs"]
mod tree_peer_tests;

fn tree_folder(
    journal: &mut Journal,
    cloud: &mut Cloud,
    path: &Path,
    name: &str,
    parent: &str,
) -> Result<String> {
    if let Some(handle) = journal.folder_handle(path)? {
        return Ok(handle.to_owned());
    }
    let prepared = cloud.prepare_mkdir(name, Some(parent))?;
    journal.folder(path, || cloud.create_folder(prepared))
}

fn acknowledge(context: &Context, uploaded: &Uploaded) {
    if uploaded.acknowledge().is_err() {
        let _ = context.output.message("WARNING", "Upload succeeded; its completion receipt could not be cleared and will prevent duplicate registration on retry.");
    }
}

pub fn finalize(
    context: &Context,
    command: &Upload,
    cloud: &mut Cloud,
    path: &Path,
    uploaded: &Uploaded,
    elapsed: f64,
) -> Result<()> {
    uploaded.finalize(|| finalize_effects(context, command, cloud, path, uploaded, elapsed))
}

fn finalize_effects(
    context: &Context,
    command: &Upload,
    cloud: &mut Cloud,
    path: &Path,
    uploaded: &Uploaded,
    elapsed: f64,
) -> Result<()> {
    let thumbnail = match crate::services::attributes::attach(
        cloud,
        path,
        &uploaded.handle,
        &uploaded.raw_key,
        &context.control,
    ) {
        Ok(attachment) => {
            if let crate::services::attributes::Attachment::Attached {
                warning: Some(warning),
            } = &attachment
            {
                context.output.message("WARNING", warning)?;
            }
            serde_json::to_value(attachment)?
        }
        Err(error) => {
            context.output.message(
                "WARNING",
                &format!("Upload succeeded, but media thumbnail attachment failed: {error}"),
            )?;
            json!({"status":"failed","error_code":error.code(),"warning":error.to_string()})
        }
    };
    let mut share = None;
    if command.share {
        match cloud.export(&uploaded.handle, command.share_password.as_deref()) {
            Ok(link) => {
                if !command.json {
                    context.output.public_link(&link)?;
                }
                share = Some(link);
            }
            Err(error) => {
                context.output.message(
                    "WARNING",
                    &format!("Upload succeeded, but public sharing failed: {error}"),
                )?;
            }
        }
    }
    let record = json!({"event":"result","type":"upload","status":"success", "name":uploaded.name,
        "path":path,"size":uploaded.size,"elapsed_seconds":(elapsed*100.0).round()/100.0,"handle":uploaded.handle,
        "account":cloud.session.email,"share_link":share,"thumbnail":thumbnail});
    context.output.record(&record)?;
    context.output.message(
        "INFO",
        &format!(
            "Uploaded {} ({})",
            uploaded.name,
            format_bytes(uploaded.size)
        ),
    )?;
    context.event(
        "UPLOAD",
        "File transfer completed",
        &json!({"bytes":uploaded.size}),
    );
    if let Some(path) = context.config.upload_log_path.as_deref() {
        let mut log = record.clone();
        log["public_link"] = log["share_link"].clone();
        log["ts"] = json!(chrono::Utc::now().to_rfc3339());
        if let Err(error) = hooks::upload_log(Path::new(path), &log) {
            context.output.message(
                "WARNING",
                &format!("Upload succeeded, but its result log could not be written: {error}"),
            )?;
        }
    }
    if let Err(error) = hooks::after_file(
        context.config.run_command.as_deref(),
        path,
        &context.control,
        &context.output,
    ) {
        context
            .output
            .message("WARNING", &format!("Post-upload command failed: {error}"))?;
    }
    Ok(())
}
