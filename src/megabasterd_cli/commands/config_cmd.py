"""`mb config` - view and modify CLI settings."""

from __future__ import annotations

from dataclasses import asdict

import click
from rich.table import Table

from ..config import ConfigStore, config_file
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
        table.add_row(key, str(value))
    _console.print(table)


@config_cmd.command("set", short_help="Set a configuration value.")
@click.argument("key")
@click.argument("value")
@click.pass_context
def config_set(ctx: click.Context, key: str, value: str) -> None:
    store: ConfigStore = ctx.obj["config_store"]
    try:
        store.set(key, value)
        print_success(f"{key} = {getattr(store.config, key)}")
    except KeyError as e:
        click.echo(f"Unknown key: {e}", err=True)
    except (ValueError, TypeError) as e:
        click.echo(f"Bad value: {e}", err=True)


@config_cmd.command("get", short_help="Get a configuration value.")
@click.argument("key")
@click.pass_context
def config_get(ctx: click.Context, key: str) -> None:
    cfg = ctx.obj["config"]
    if not hasattr(cfg, key):
        click.echo(f"Unknown key: {key}", err=True)
        return
    click.echo(getattr(cfg, key))


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
