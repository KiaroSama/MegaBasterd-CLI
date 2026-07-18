"""`mb config` - view and modify CLI settings."""

from __future__ import annotations

from dataclasses import asdict

import click
from rich.table import Table

from ..config import (
    ConfigCorruptionError,
    ConfigLockError,
    ConfigStore,
    config_file,
    display_value,
)
from ..ui.prompts import confirm, print_success
from ..ui.theme import make_console

_console = make_console()


def _warn_if_corrupt(store: ConfigStore) -> None:
    """Read-only commands report corruption but never rewrite anything."""
    if store.is_corrupt:
        click.echo(store.corruption_reason, err=True)


@click.group("config", short_help="View or modify CLI settings.")
def config_cmd() -> None:
    """Manage configuration."""


@config_cmd.command("show", short_help="Print current configuration.")
@click.pass_context
def config_show(ctx: click.Context) -> None:
    store: ConfigStore = ctx.obj["config_store"]
    cfg = store.config
    _warn_if_corrupt(store)
    table = Table(
        title=f"Configuration ({config_file()})",
        show_header=True,
        header_style="mb.table.header",
        border_style="mb.table.border",
    )
    table.add_column("Key", style="mb.info")
    table.add_column("Value", style="mb.value")
    for key, value in asdict(cfg).items():
        # Secret values are redacted; elc_accounts is recursively scrubbed.
        table.add_row(key, str(display_value(key, value)))
    _console.print(table)


@config_cmd.command("set", short_help="Set a configuration value.")
@click.argument("key")
@click.argument("value")
@click.pass_context
def config_set(ctx: click.Context, key: str, value: str) -> None:
    store: ConfigStore = ctx.obj["config_store"]
    try:
        store.set(key, value)
    except KeyError:
        click.echo(f"Unknown config key: {key}", err=True)
        ctx.exit(2)
    except (ValueError, TypeError) as e:
        click.echo(f"Bad value: {e}", err=True)
        ctx.exit(2)
    except (ConfigLockError, ConfigCorruptionError) as e:
        click.echo(str(e), err=True)
        ctx.exit(1)
    # Never echo the value: secrets must not reach stdout. Confirm the key only.
    print_success(f"{key} updated.")


@config_cmd.command("unset", short_help="Clear a nullable setting (set it to null).")
@click.argument("key")
@click.pass_context
def config_unset(ctx: click.Context, key: str) -> None:
    store: ConfigStore = ctx.obj["config_store"]
    try:
        store.unset(key)
    except KeyError:
        click.echo(f"Unknown config key: {key}", err=True)
        ctx.exit(2)
    except ValueError as e:
        click.echo(str(e), err=True)
        ctx.exit(2)
    except (ConfigLockError, ConfigCorruptionError) as e:
        click.echo(str(e), err=True)
        ctx.exit(1)
    print_success(f"{key} cleared.")


@config_cmd.command("get", short_help="Get a configuration value.")
@click.argument("key")
@click.pass_context
def config_get(ctx: click.Context, key: str) -> None:
    cfg = ctx.obj["config"]
    _warn_if_corrupt(ctx.obj["config_store"])
    if not hasattr(cfg, key):
        click.echo(f"Unknown config key: {key}", err=True)
        ctx.exit(2)
    # Secret values print as <redacted> by default so scripting `config get`
    # can never dump a password or API key.
    click.echo(display_value(key, getattr(cfg, key)))


@config_cmd.command("reset", short_help="Reset to defaults.")
@click.pass_context
def config_reset(ctx: click.Context) -> None:
    if not confirm("Reset all settings to defaults?", default=False):
        return  # declined: exit 0, nothing written
    try:
        ctx.obj["config_store"].reset()
    except (ConfigLockError, ConfigCorruptionError) as e:
        click.echo(str(e), err=True)
        ctx.exit(1)
    print_success("Configuration reset to defaults.")


@config_cmd.command("recover", short_help="Recover from a corrupt config file.")
@click.option(
    "--reset",
    "do_reset",
    is_flag=True,
    help="Discard the corrupt config and start from defaults (the original is kept as a backup).",
)
@click.pass_context
def config_recover(ctx: click.Context, do_reset: bool) -> None:
    """Report or resolve a corrupt config file.

    Without `--reset` this only reports the state; the corrupt file is never
    rewritten implicitly. With `--reset` a fresh default config is written and
    the preserved backup is kept.
    """
    store: ConfigStore = ctx.obj["config_store"]
    store.load()  # refresh the corruption state (and preserve/back up once)
    if not do_reset:
        if store.is_corrupt:
            click.echo(store.corruption_reason, err=True)
            click.echo("Run `mb config recover --reset` to start from defaults.", err=True)
            ctx.exit(1)
        print_success("Configuration file is valid; nothing to recover.")
        return
    try:
        backup = store.recover()
    except ConfigLockError as e:
        click.echo(str(e), err=True)
        ctx.exit(1)
    if backup is not None:
        print_success(f"Configuration reset to defaults; corrupt file kept as {backup.name}.")
    else:
        print_success("Configuration reset to defaults.")


@config_cmd.command("path", short_help="Print config file path.")
def config_path() -> None:
    click.echo(str(config_file()))


@config_cmd.command("migrate", short_help="Normalize the config file (drop dead keys).")
@click.pass_context
def config_migrate(ctx: click.Context) -> None:
    """Rewrite config.json without deprecated/unknown keys.

    Lets an external caller clean old config files it wrote for
    earlier versions. Valid settings are preserved; removed keys are listed.
    """
    store: ConfigStore = ctx.obj["config_store"]
    try:
        removed = store.migrate()
    except (ConfigLockError, ConfigCorruptionError) as e:
        click.echo(str(e), err=True)
        ctx.exit(1)
    if removed:
        print_success(f"Config normalized; removed keys: {', '.join(removed)}")
    else:
        print_success("Config already normalized; nothing to remove.")
