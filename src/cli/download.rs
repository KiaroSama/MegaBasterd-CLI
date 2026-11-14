use std::collections::VecDeque;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

use serde_json::json;

use super::{args::Download, context::Context};
use crate::error::{Error, Result, poisoned};
use crate::protocol::{
    api::Api,
    link_services::{MegaCrypterResolution, Resolver},
    links::{self, LinkType},
    metadata,
};
use crate::services::{hooks, local_crypto::open_source};
use crate::terminal::progress::{Progress, Status, format_bytes};
use crate::transfers::{
    control::RateLimiter,
    download::{self, DownloadOptions},
    folders::{self, Source, TransferJob},
    quota,
};

#[cfg(test)]
#[path = "download_outcome_tests.rs"]
mod outcome_tests;

const MAX_LINKS: usize = 200_000;
const MAX_INPUT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_CHUNK_WORKERS: u32 = 64;

#[derive(Default)]
struct Group {
    source: String,
    folder: bool,
    succeeded: usize,
    failed: usize,
    bytes: u64,
    planned: usize,
    skipped: bool,
    reported: bool,
}

fn read_input(path: &Path) -> Result<String> {
    let (_directory, file) = open_source(path)?;
    if file.metadata()?.len() > MAX_INPUT_BYTES {
        return Err(Error::invalid("Input link file exceeds 16 MiB"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_INPUT_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(Error::invalid("Input link file exceeds 16 MiB"));
    }
    String::from_utf8(bytes).map_err(|_| Error::invalid("Input link file is not UTF-8"))
}

fn resolver<'a>(api: &'a Api, command: &'a Download, context: &'a Context) -> Resolver<'a> {
    Resolver {
        transport: &api.transport,
        password: command.password.as_deref(),
        elc_user: command.elc_user.as_deref(),
        elc_api_key: command.elc_api_key.as_deref(),
        elc_accounts: &context.config.elc_accounts,
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "Explicit transfer state and cancellation dependencies at this boundary."
)]
fn prepare(
    context: &Context,
    api: &mut Api,
    command: &Download,
    options: &DownloadOptions,
    group: &mut Group,
    root: &Path,
    rename: Option<&str>,
    progress: &Progress,
    select: &mut impl FnMut(&crate::terminal::output::Output, usize) -> Result<Vec<usize>>,
) -> Result<Option<Vec<TransferJob>>> {
    let parsed = links::resolve_offline(
        &links::parse_link(&group.source)?,
        command.password.as_deref(),
    )?;
    let parsed = if parsed.kind == LinkType::Megacrypter {
        match resolver(api, command, context).megacrypter_source(&parsed)? {
            MegaCrypterResolution::Link(inline) => {
                links::resolve_offline(&links::parse_link(&inline)?, command.password.as_deref())?
            }
            MegaCrypterResolution::Metadata { info, download_url } => {
                let url = match download_url {
                    Some(url) => url,
                    None => {
                        return Err(Error::protocol(
                            "MegaCrypter returned no usable download URL",
                        ));
                    }
                };
                let info = metadata::FileInfo::megacrypter(parsed, *info, url)?;
                let destination = folders::file_destination(root, &info, rename);
                let item = progress.add(&info.name, info.size)?;
                return Ok(Some(vec![TransferJob {
                    source: Source::File(info),
                    destination,
                    item,
                }]));
            }
        }
    } else {
        parsed
    };
    let routing = api.transport.routing.clone();
    if parsed.kind == LinkType::File {
        let info = quota::retry(options, &routing, &context.control, || {
            metadata::file(api, &parsed)
        })?;
        let destination = folders::file_destination(root, &info, rename);
        let item = progress.add(&info.name, info.size)?;
        return Ok(Some(vec![TransferJob {
            source: Source::File(info),
            destination,
            item,
        }]));
    }
    if !matches!(
        parsed.kind,
        LinkType::Folder | LinkType::FolderInFolder | LinkType::FileInFolder
    ) {
        return Err(Error::invalid(
            "Container did not resolve to a downloadable MEGA source",
        ));
    }
    group.folder = parsed.is_folder();
    let (_tree, jobs) = quota::retry(options, &routing, &context.control, || {
        metadata::folder(api, &parsed)
    })?;
    let mut jobs = folders::select_jobs(jobs, &command.include, &command.exclude, None)?;
    if command.select && !jobs.is_empty() {
        context
            .output
            .message("INFO", &format!("Folder contains {} file(s):", jobs.len()))?;
        for (index, job) in jobs.iter().enumerate() {
            context.output.message(
                "INFO",
                &format!(
                    "{}: {}  {}",
                    index + 1,
                    format_bytes(job.node.size),
                    job.relative.display()
                ),
            )?;
        }
        let chosen = select(&context.output, jobs.len())?;
        if chosen.is_empty() {
            context
                .output
                .message("INFO", "Selection cancelled; skipped folder.")?;
            context.output.record(
                &json!({"event":"result","type":"download","status":"skipped","source":group.source}),
            )?;
            return Ok(None);
        }
        jobs = folders::select_jobs(jobs, &[], &[], Some(&chosen))?;
    }
    let jobs = jobs
        .into_iter()
        .map(|job| {
            let destination = root.join(&job.relative);
            let item = progress.add(&job.relative.to_string_lossy(), job.node.size)?;
            Ok(TransferJob {
                source: Source::FolderFile {
                    link: parsed.clone(),
                    job,
                },
                destination,
                item,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Some(jobs))
}

pub fn dispatch(context: &mut Context, command: Download) -> Result<i32> {
    execute(context, command, true)
}

pub fn execute(context: &mut Context, command: Download, batch_command: bool) -> Result<i32> {
    execute_with(context, command, batch_command, None, |output, count| {
        output.select_files_interactive(count)
    })
}

fn execute_with(
    context: &mut Context,
    command: Download,
    batch_command: bool,
    progress: Option<&mut Progress>,
    mut select: impl FnMut(&crate::terminal::output::Output, usize) -> Result<Vec<usize>>,
) -> Result<i32> {
    context.require_config()?;
    let parallel = command
        .parallel
        .unwrap_or(context.config.max_parallel_downloads);
    if !(1..=32).contains(&parallel) {
        return Err(Error::invalid(
            "Parallel downloads must be between 1 and 32",
        ));
    }
    let mut options = DownloadOptions::from_config(
        &context.config,
        command.workers,
        command.no_verify,
        command.overwrite,
    )?;
    let limiter = RateLimiter::new(command.limit.unwrap_or(context.config.speed_limit_kbps))?;
    let mut api = if command.auth.account.is_some() {
        context
            .authenticated_api(&command.auth, command.proxy.as_deref())?
            .0
    } else {
        context.api(command.proxy.as_deref())?
    };
    let mut inputs = command.urls.clone();
    if let Some(path) = &command.input_file {
        let text = read_input(path)?;
        if path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("dlc"))
        {
            inputs.extend(resolver(&api, &command, context).dlc(&text)?);
        } else {
            inputs.extend(
                text.lines()
                    .map(str::trim)
                    .filter(|line| !line.is_empty() && !line.starts_with('#'))
                    .map(str::to_owned),
            );
        }
    }
    if inputs.is_empty() {
        return Err(Error::invalid(
            "No URLs given. Pass URLs as arguments or use -i <file>.",
        ));
    }
    if inputs.len() > MAX_LINKS {
        return Err(Error::invalid("Input exceeds 200000 links"));
    }
    let root = command.output.clone().unwrap_or_else(|| {
        context
            .paths
            .download(&context.config.download_path)
            .to_owned()
    });
    let mut owned_progress;
    let progress = match progress {
        Some(progress) => progress,
        None => {
            owned_progress = Progress::new(!command.json && !context.output.quiet);
            &mut owned_progress
        }
    };
    let mut pending: VecDeque<_> = inputs.into_iter().map(|input| (input, 0usize)).collect();
    let mut groups = Vec::new();
    let mut transfers = VecDeque::new();
    let mut expansion_count = pending.len();
    while let Some((input, depth)) = pending.pop_front() {
        context.control.checkpoint()?;
        let group = groups.len();
        groups.push(Group {
            source: input.clone(),
            ..Default::default()
        });
        let mut expanded_container = false;
        let prepared = (|| {
            if depth >= 8 {
                return Err(Error::invalid(
                    "Link container nesting exceeds eight levels",
                ));
            }
            let parsed =
                links::resolve_offline(&links::parse_link(&input)?, command.password.as_deref())?;
            groups[group].folder = parsed.is_folder();
            if parsed.kind == LinkType::ElcContainer {
                let expanded = resolver(&api, &command, context).elc(&parsed)?;
                expansion_count = expansion_count
                    .checked_add(expanded.len())
                    .filter(|count| *count <= MAX_LINKS)
                    .ok_or_else(|| Error::invalid("Expanded input exceeds 200000 links"))?;
                pending.extend(expanded.into_iter().map(|link| (link, depth + 1)));
                expanded_container = true;
                return Ok(None);
            }
            let rename = if expansion_count == 1 {
                command.rename.as_deref()
            } else {
                None
            };
            prepare(
                context,
                &mut api,
                &command,
                &options,
                &mut groups[group],
                &root,
                rename,
                progress,
                &mut select,
            )
        })();
        match prepared {
            Ok(Some(jobs)) => {
                if transfers
                    .len()
                    .checked_add(jobs.len())
                    .is_none_or(|count| count > MAX_LINKS)
                {
                    return Err(Error::invalid("Download manifest exceeds 200000 files"));
                }
                groups[group].planned = jobs.len();
                transfers.extend(jobs.into_iter().map(|job| (group, job)));
            }
            Ok(None) if expanded_container => {
                groups.pop();
            }
            Ok(None) => {
                groups[group].skipped = true;
                groups[group].reported = true;
            }
            Err(Error::Canceled) => return Err(Error::Canceled),
            Err(error) => {
                groups[group].failed = 1;
                context.output.message("ERROR", &error.to_string())?;
                context.output.record(
                    &json!({"event":if groups[group].folder { "summary" } else { "result" },
                    "type":"download","status":"failed", "source":input,
                    "error_code":error.code(),"error":error.to_string()}),
                )?;
                groups[group].reported = true;
            }
        }
    }
    let slots = (parallel as usize).min(transfers.len());
    if slots != 0 {
        options.workers = options.workers.min(MAX_CHUNK_WORKERS / slots as u32);
    }
    let pending = Mutex::new(transfers);
    let groups = Mutex::new(groups);
    let worker_errors = Mutex::new(Vec::new());
    let state_directory: PathBuf = context.paths.user.join("Data/transfers/download");
    let context: &Context = context;
    std::thread::scope(|scope| -> Result<()> {
        let progress: &Progress = progress;
        let _input =
            crate::terminal::input::Input::start(scope, command.json, &context.control, progress)?;
        let mut workers = Vec::new();
        for _ in 0..slots {
            workers.push(scope.spawn(|| {
                let run = || -> Result<()> {
                    loop {
                        context.control.checkpoint()?;
                        let Some((group, job)) = pending.lock().map_err(poisoned)?.pop_front() else { return Ok(()); };
                        let start = Instant::now();
                        let mut client = api.fork()?;
                        let result = job.resolve(&mut client, &options, &context.control).and_then(|info| {
                            download::download(client, info, &job.destination, &state_directory, &options,
                                &limiter, progress, job.item, &context.control).map_err(Error::transfer)
                        });
                        match result {
                            Ok(path) => {
                                let mut groups = groups.lock().map_err(poisoned)?;
                                groups[group].succeeded += 1;
                                groups[group].bytes = groups[group].bytes.checked_add(job.size()).ok_or_else(|| Error::protocol("Batch byte count overflows"))?;
                                drop(groups);
                                context.output.record(&json!({"event":"result","type":"download","status":"success",
                                    "name":path.file_name().map(|name| name.to_string_lossy()),"path":path,"size":job.size(),
                                    "elapsed_seconds":(start.elapsed().as_secs_f64()*100.0).round()/100.0,"integrity_ok":options.verify}))?;
                                context.output.message("INFO", &format!("Downloaded {} ({})", path.display(), format_bytes(job.size())))?;
                                context.event("DOWNLOAD","File transfer completed", &json!({"bytes":job.size(),"verified":options.verify}));
                                if let Err(error) = hooks::after_file(context.config.run_command.as_deref(), &path, &context.control, &context.output) {
                                    context.output.message("WARNING", &format!("Post-transfer command failed: {error}"))?;
                                }
                            }
                            Err(error) => {
                                progress.status(job.item, if matches!(error, Error::Canceled) { Status::Canceled } else { Status::Failed })?;
                                let source = {
                                    let mut groups = groups.lock().map_err(poisoned)?;
                                    let group = &mut groups[group];
                                    group.failed += 1;
                                    (!group.folder).then(|| group.source.clone())
                                };
                                context.diagnostic("ERROR", "DOWNLOAD", &error.to_string(), &json!({"error_code":error.code()}));
                                let mut record = json!({"event":"result","type":"download","status":"failed", "name":job.name(),
                                    "path":job.destination,"error_code":error.code(),"error":error.to_string()});
                                if let Some(source) = source { record["source"] = json!(source); }
                                context.output.record(&record)?;
                                if matches!(error, Error::Canceled) { return Err(error); }
                            }
                        }
                    }
                };
                if let Err(error) = run() && let Ok(mut errors) = worker_errors.lock() { errors.push(error); }
            }));
        }
        for worker in workers {
            if worker.join().is_err()
                && let Ok(mut errors) = worker_errors.lock()
            {
                errors.push(Error::protocol(
                    "Download orchestration worker was interrupted",
                ));
            }
        }
        Ok(())
    })?;
    let worker_errors = worker_errors.into_inner().map_err(poisoned)?;
    let worker_failed = !worker_errors.is_empty();
    for error in worker_errors {
        context.output.message("ERROR", &error.to_string())?;
    }
    let groups = groups.into_inner().map_err(poisoned)?;
    let (mut succeeded, mut failed) = (0usize, 0usize);
    for group in groups {
        let complete = group.failed == 0 && (group.skipped || group.succeeded == group.planned);
        succeeded += usize::from(complete);
        failed += usize::from(!complete);
        if group.folder && !group.reported {
            context.output.record(&json!({"event":"summary","type":"download","status":if complete {"success"} else {"failed"},
                "source":group.source,"files":group.succeeded,"total_bytes":group.bytes}))?;
        }
    }
    if let Err(error) = hooks::after_batch(
        if batch_command {
            context.config.all_finished_command.as_deref()
        } else {
            None
        },
        "download",
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
    Ok(if closed? { 0 } else { 1 })
}
