"""MegaBasterd CLI entry point."""

from __future__ import annotations

import contextlib
import logging
import os
import platform
import sys
from pathlib import Path

import click

from . import __version__
from .commands.account_cmd import account
from .commands.cloud_cmd import (
    import_cmd,
    ls_cmd,
    mkdir_cmd,
    mv_cmd,
    rename_cmd,
    rm_cmd,
    search_cmd,
    trash_cmd,
)
from .commands.config_cmd import config_cmd
from .commands.crypter_cmd import crypter_cmd
from .commands.download_cmd import download
from .commands.file_ops_cmd import merge_cmd, split_cmd, thumbnail_cmd
from .commands.info_cmd import info_cmd
from .commands.proxy_cmd import proxy_cmd
from .commands.queue_cmd import queue
from .commands.share_cmd import share_cmd
from .commands.stream_cmd import stream
from .commands.upload_cmd import upload
from .commands.watch_cmd import watch_cmd
from .config import ConfigStore, config_file, data_dir, log_dir, user_dir
from .ui.theme import make_console
from .utils.logger import setup_logging

console = make_console()


def _redacted_argv(argv: list[str]) -> list[str]:
    """Hide share keys, passwords, and token-like values in debug logs."""
    redacted: list[str] = []
    sensitive_next = False
    sensitive_options = {
        "-p",
        "--password",
        "--share-password",
        "--vault-passphrase",
        "--mfa-code",
        "--elc-api-key",
        "--token",
    }
    for arg in argv:
        if sensitive_next:
            redacted.append("<redacted>")
            sensitive_next = False
            continue
        if arg in sensitive_options:
            redacted.append(arg)
            sensitive_next = True
            continue
        # Also redact inline `--option=value` forms of sensitive options.
        if "=" in arg and arg.split("=", 1)[0] in sensitive_options:
            redacted.append(arg.split("=", 1)[0] + "=<redacted>")
            continue
        if any(prefix in arg for prefix in ("mega.nz/", "mega.co.nz/", "mc://", "mega://")):
            redacted.append("<redacted-link>")
            continue
        redacted.append(arg)
    return redacted


def _startup_args_for_log() -> list[str]:
    """Return process args only when this process looks like the CLI itself."""
    argv0 = str(sys.argv[0]).replace("\\", "/").rsplit("/", 1)[-1].lower()
    cli_names = {
        "mb",
        "mb.exe",
        "mbcli",
        "mbcli.exe",
        "megabasterd-cli",
        "megabasterd-cli.exe",
        "run.ps1",
        "__main__.py",
    }
    if argv0 in cli_names:
        return _redacted_argv(sys.argv[1:])
    return []


def _command_name_for_log(args: list[str]) -> str:
    """Return the first non-global-option token as the command name."""
    if not args:
        return "menu/help"
    for arg in args:
        if arg.startswith("-"):
            continue
        return arg
    return "global"


def _config_summary_for_log(store: ConfigStore) -> dict[str, object]:
    """Return non-secret config values that help debug user runs."""
    cfg = store.config
    return {
        "config_file": str(store.path),
        "user_dir": str(user_dir()),
        "data_dir": str(data_dir()),
        "log_dir": str(log_dir()),
        "download_path": cfg.download_path,
        "max_workers": cfg.max_workers,
        "upload_workers": cfg.upload_workers,
        "max_parallel_downloads": cfg.max_parallel_downloads,
        "max_parallel_uploads": cfg.max_parallel_uploads,
        "chunk_size_kb": cfg.chunk_size_kb,
        "speed_limit_kbps": cfg.speed_limit_kbps,
        "upload_speed_limit_kbps": cfg.upload_speed_limit_kbps,
        "verify_integrity": cfg.verify_integrity,
        "auto_resume": cfg.auto_resume,
        "keep_state_files_on_error": cfg.keep_state_files_on_error,
        "smart_proxy_enabled": cfg.smart_proxy_enabled,
        "force_smart_proxy": cfg.force_smart_proxy,
        "timeout_seconds": cfg.timeout_seconds,
        "quota_wait_seconds": cfg.quota_wait_seconds,
        "quota_max_wait_loops": cfg.quota_max_wait_loops,
        "log_level": cfg.log_level,
        "log_to_file": cfg.log_to_file,
        "log_max_bytes": cfg.log_max_bytes,
        "log_backups": cfg.log_backups,
    }


@click.group(
    context_settings={"help_option_names": ["-h", "--help"]},
    help="MegaBasterd CLI - command-line MEGA.nz transfers.",
)
@click.option(
    "-v",
    "--verbose",
    count=True,
    help="Increase verbosity (-v for INFO, -vv for DEBUG).",
)
@click.option(
    "-q",
    "--quiet",
    is_flag=True,
    help="Suppress console output (errors still shown).",
)
@click.option(
    "--log-file/--no-log-file",
    default=None,
    help="Write a debug log file in the user log directory.",
)
@click.version_option(version=__version__, prog_name="megabasterd-cli")
@click.pass_context
def cli(ctx: click.Context, verbose: int, quiet: bool, log_file: bool | None) -> None:
    """Top-level CLI group."""
    ctx.ensure_object(dict)
    store = ConfigStore()
    ctx.obj["config_store"] = store
    ctx.obj["config"] = store.config
    ctx.obj["console"] = console

    if verbose >= 2:
        level = "DEBUG"
    elif verbose == 1:
        level = "INFO"
    elif quiet:
        level = "ERROR"
    else:
        level = store.config.log_level

    env_log_file = os.environ.get("MEGABASTERD_CLI_LOG_FILE")
    if log_file is False:
        log_path = None
    elif env_log_file:
        log_path = Path(env_log_file)
    else:
        use_log_file = log_file if log_file is not None else store.config.log_to_file
        log_path = (log_dir() / "megabasterd-cli.log") if use_log_file else None

    startup_args = _startup_args_for_log()
    command_name = _command_name_for_log(startup_args)
    setup_logging(
        level=level,
        log_file=log_path,
        quiet=quiet,
        max_bytes=store.config.log_max_bytes,
        backup_count=store.config.log_backups,
        command=command_name,
    )
    log = logging.getLogger(__name__)
    log.info(
        "CLI start version=%s cwd=%s executable=%s python=%s platform=%s args=%s "
        "log_file=%s config_file=%s effective_level=%s quiet=%s verbose=%s",
        __version__,
        os.getcwd(),
        sys.executable,
        sys.version.replace("\n", " "),
        platform.platform(),
        startup_args,
        log_path,
        config_file(),
        level,
        quiet,
        verbose,
    )
    log.debug(
        "Runtime paths project_root=%s user_dir=%s data_dir=%s log_dir=%s",
        os.environ.get("MEGABASTERD_PROJECT_ROOT", "<auto>"),
        user_dir(),
        data_dir(),
        log_dir(),
    )
    log.debug(
        "Config summary: %s",
        _config_summary_for_log(store),
    )


# Transfer commands
cli.add_command(download)
cli.add_command(upload)
cli.add_command(stream)

# Cloud operations
cli.add_command(ls_cmd)
cli.add_command(mkdir_cmd)
cli.add_command(rm_cmd)
cli.add_command(mv_cmd)
cli.add_command(rename_cmd)
cli.add_command(search_cmd)
cli.add_command(import_cmd)
cli.add_command(trash_cmd)
cli.add_command(share_cmd)
cli.add_command(info_cmd)

# Local Crypter + MegaCrypter operations
cli.add_command(crypter_cmd)

# Local file ops
cli.add_command(split_cmd)
cli.add_command(merge_cmd)
cli.add_command(thumbnail_cmd)

# Automation
cli.add_command(watch_cmd)

# Management
cli.add_command(account)
cli.add_command(queue)
cli.add_command(proxy_cmd)
cli.add_command(config_cmd, name="config")


def main() -> int:
    """Console script entry point."""
    # Make stdout/stderr Unicode-safe on legacy Windows terminals so messages
    # that contain characters outside cp1252 (e.g. arrows, em-dashes, non-Latin
    # filenames returned by MEGA) don't crash the process.
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            with contextlib.suppress(ValueError, OSError):
                reconfigure(encoding="utf-8", errors="replace")
    try:
        cli(prog_name="mb")
        return 0
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/yellow]")
        return 130
    except Exception as e:
        logging.getLogger(__name__).exception("Fatal error: %s", e)
        console.print(f"[bold red]Error:[/bold red] {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
