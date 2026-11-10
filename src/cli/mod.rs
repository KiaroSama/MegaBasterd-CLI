#[cfg(test)]
mod account_logout_peer_tests;
#[cfg(test)]
mod account_peer_tests;
#[cfg(test)]
mod account_refresh_lifecycle_tests;
mod accounts;
pub mod args;
#[cfg(test)]
mod auto_account_parallel_tests;
#[cfg(test)]
mod auto_account_peer_tests;
#[cfg(test)]
mod batch_hook_peer_tests;
#[cfg(test)]
mod client_lifecycle_peer_tests;
mod cloud;
#[cfg(test)]
mod cloud_auth_peer_tests;
#[cfg(test)]
mod cloud_lifecycle_peer_tests;
#[cfg(test)]
mod cloud_render_peer_tests;
mod config;
#[cfg(test)]
mod config_gate_peer_tests;
#[cfg(test)]
mod config_lock_tests;
pub mod context;
mod download;
#[cfg(test)]
mod download_isolation_peer_tests;
#[cfg(test)]
mod download_routing_peer_tests;
#[cfg(test)]
mod execution_tests;
#[cfg(test)]
mod folder_download_peer_tests;
pub mod info;
#[cfg(test)]
mod info_peer_tests;
mod local_files;
#[cfg(test)]
mod machine_peer_tests;
#[cfg(test)]
mod megacrypter_peer_tests;
mod menu;
mod menu_wizard;
mod proxy;
#[cfg(test)]
mod proxy_fetch_tests;
#[cfg(test)]
mod proxy_peer_tests;
mod proxy_probe;
#[cfg(test)]
mod proxy_routing_tests;
pub mod queue;
mod queue_transfer;
#[cfg(test)]
mod session_command_peer_tests;
#[cfg(test)]
mod session_peer_tests;
#[cfg(test)]
mod share_command_peer_tests;
mod stream;
#[cfg(test)]
mod stream_peer_tests;
mod upload;
mod values;
mod watch;

use std::ffi::OsString;

use crate::error::{Error, Result};
use crate::platform::signals;
use crate::terminal::{output::Output, prompts, redaction};
use args::{Cli, Command};
use clap::Parser;
use context::Context;

pub fn run(arguments: impl IntoIterator<Item = OsString>) -> i32 {
    let arguments: Vec<_> = arguments.into_iter().collect();
    let json = arguments.iter().any(|value| value == "--json");
    let cli = match Cli::try_parse_from(arguments) {
        Ok(cli) => cli,
        Err(error) if error.exit_code() == 0 => {
            if error.print().is_err() {
                return 1;
            }
            return 0;
        }
        Err(error) => {
            let output = Output::new(json, false);
            let _ = output.error(&Error::invalid(redaction::text(&error.to_string())));
            return 2;
        }
    };
    if cli.command.is_none() {
        return menu::run(cli);
    }
    execute(cli)
}

pub(crate) fn execute(cli: Cli) -> i32 {
    let Some(command) = cli.command else {
        return 0;
    };
    let json = match &command {
        Command::Download(args) => args.json,
        Command::Upload(args) => args.json,
        Command::Info(args) => args.json,
        _ => false,
    };
    let logging = if cli.no_log_file {
        Some(false)
    } else if cli.log_file {
        Some(true)
    } else {
        None
    };
    let mut context = match Context::start_for_command(json, cli.quiet, logging, command.log_name())
    {
        Ok(context) => context,
        Err(error) => {
            let _ = Output::new(json, cli.quiet).error(&error);
            return error.exit_code();
        }
    };
    if cli.verbose > 0 {
        let _ =
            context
                .output
                .set_diagnostic_level(if cli.verbose >= 2 { "DEBUG" } else { "INFO" });
    }
    let _signal = match signals::activate(&context.control) {
        Ok(signal) => signal,
        Err(error) => {
            context.report_error(&error);
            context.finish(error.exit_code());
            return error.exit_code();
        }
    };
    if cli.verbose != 0 {
        let _ = context.output.message(
            "INFO",
            &format!(
                "MegaBasterd-CLI {} ({})",
                env!("CARGO_PKG_VERSION"),
                std::env::consts::OS
            ),
        );
    }
    execute_in_context(&mut context, command, cli.verbose, json, dispatch)
}

fn execute_in_context(
    context: &mut Context,
    command: Command,
    verbose: u8,
    json: bool,
    dispatch: impl FnOnce(&mut Context, Command) -> Result<i32>,
) -> i32 {
    context.event(
        "CLI",
        "Command started",
        &serde_json::json!({"verbose":verbose,"json":json}),
    );
    let outcome = crate::terminal::panic_report::catch(|| dispatch(context, command))
        .unwrap_or_else(|diagnostic| {
            crate::terminal::panic_report::record(
                &diagnostic,
                context.logger.as_deref(),
                &context.output,
            );
            Err(Error::Unexpected)
        });
    let code = match outcome {
        Ok(code) => code,
        Err(error) => {
            context.report_error(&error);
            error.exit_code()
        }
    };
    context.finish(code);
    code
}

fn dispatch(context: &mut Context, command: Command) -> Result<i32> {
    if !matches!(&command, Command::Config(_)) {
        context.require_config()?;
    }
    match command {
        Command::Download(command) => return download::dispatch(context, command),
        Command::Upload(command) => return upload::dispatch(context, command),
        Command::Stream(command) => stream::dispatch(context, command)?,
        Command::Info(command) => info::dispatch(context, command)?,
        Command::Share {
            target,
            password,
            remove,
            auth,
        } => cloud::share(context, &target, password.as_deref(), remove, &auth)?,
        Command::Ls { path, all, auth } => cloud::list(context, &path, all, &auth)?,
        Command::Mkdir { name, parent, auth } => {
            let (mut cloud, _) = context.cloud(&auth)?;
            let handle = cloud.mkdir(&name, parent.as_deref())?;
            context
                .output
                .message("SUCCESS", &format!("Folder created: {handle}"))?;
        }
        Command::Rm { target, yes, auth } => {
            if !yes && !prompts::confirmed("Permanently delete the selected cloud node?", false)? {
                return Ok(0);
            }
            let (mut cloud, _) = context.cloud(&auth)?;
            cloud.delete(&target)?;
            context.output.message("SUCCESS", "Cloud node deleted.")?;
        }
        Command::Mv {
            source,
            destination,
            auth,
        } => {
            let (mut cloud, _) = context.cloud(&auth)?;
            cloud.move_node(&source, &destination)?;
            context.output.message("SUCCESS", "Cloud node moved.")?;
        }
        Command::Rename {
            target,
            new_name,
            auth,
        } => {
            let (mut cloud, _) = context.cloud(&auth)?;
            cloud.rename(&target, &new_name)?;
            context.output.message("SUCCESS", "Cloud node renamed.")?;
        }
        Command::Search {
            pattern,
            regex,
            auth,
        } => cloud::search(context, &pattern, regex, &auth)?,
        Command::Import {
            share_url,
            target,
            auth,
        } => cloud::import(context, &share_url, target.as_deref(), &auth)?,
        Command::Trash(command) => cloud::trash(context, command)?,
        Command::Account(command) => accounts::dispatch(context, command)?,
        Command::Queue(command) => queue::handle(context, command, queue_transfer::execute)?,
        Command::Proxy(command) => proxy::dispatch(context, command)?,
        Command::Crypter(command) => local_files::crypter(context, command)?,
        Command::Split {
            source,
            part_size_mb,
            output_dir,
        } => local_files::split(context, &source, part_size_mb, output_dir.as_deref())?,
        Command::Merge {
            any_part,
            output,
            no_verify,
            delete_parts,
        } => local_files::merge(
            context,
            &any_part,
            output.as_deref(),
            no_verify,
            delete_parts,
        )?,
        Command::Thumbnail {
            source,
            destination,
        } => local_files::thumbnail(context, &source, &destination)?,
        Command::Watch {
            interval,
            output,
            run,
            auth,
        } => watch::dispatch(context, interval, output, run, auth)?,
        Command::Config(command) => config::dispatch(context, command)?,
    }
    Ok(0)
}
