"""`mb config` - view and modify CLI settings."""

from __future__ import annotations

from dataclasses import asdict

import click
from rich.table import Table

from ..config import ConfigLockError, ConfigStore, config_file, display_value
from ..ui.prompts import confirm, print_success
from ..ui.theme import make_console

_console = make_console()


@click.group("config", short_help="View or modify CLI settings.")
def config_cmd() -> None:
    """Manage configuration."""


@config_cmd.command("show", short_help="Print current configuration.")
@click.pass_context
def config_show(ctx: click.Context) -> None:
    cfg = ctx.obj["config_store"].config
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
    except ConfigLockError as e:
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
    except ConfigLockError as e:
        click.echo(str(e), err=True)
        ctx.exit(1)
    print_success(f"{key} cleared.")


@config_cmd.command("get", short_help="Get a configuration value.")
@click.argument("key")
@click.pass_context
def config_get(ctx: click.Context, key: str) -> None:
    cfg = ctx.obj["config"]
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
        return
    ctx.obj["config_store"].reset()
    print_success("Configuration reset to defaults.")


@config_cmd.command("path", short_help="Print config file path.")
def config_path() -> None:
    click.echo(str(config_file()))


@config_cmd.command("migrate", short_help="Normalize the config file (drop dead keys).")
@click.pass_context
def config_migrate(ctx: click.Context) -> None:
    """Rewrite config.json without deprecated/unknown keys.

    Lets external callers (e.g. EVdlc) clean old config files they wrote for
    earlier versions. Valid settings are preserved; removed keys are listed.
    """
    store: ConfigStore = ctx.obj["config_store"]
    try:
        removed = store.migrate()
    except ConfigLockError as e:
        click.echo(str(e), err=True)
        ctx.exit(1)
    if removed:
        print_success(f"Config normalized; removed keys: {', '.join(removed)}")
    else:
        print_success("Config already normalized; nothing to remove.")
