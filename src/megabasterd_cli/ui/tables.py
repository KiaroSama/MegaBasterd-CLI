"""Rich table renderers for account lists, queues, etc."""

from __future__ import annotations

from ..accounts.storage import Account
from ..utils.helpers import format_bytes
from .theme import SafeTable, make_console, markup

_console = make_console()


def render_accounts(accounts: list[Account], default_email: str | None = None) -> None:
    if not accounts:
        _console.print("[mb.dim]No accounts stored.[/mb.dim]")
        return

    table = SafeTable(
        title="MEGA Accounts",
        show_header=True,
        header_style="mb.table.header",
        border_style="mb.table.border",
    )
    table.add_column("Default", justify="center", width=8)
    table.add_column("Email")
    table.add_column("Label")
    table.add_column("Used")
    table.add_column("Quota")
    table.add_column("Last used")

    for a in accounts:
        is_default = markup("[mb.success]Y[/mb.success]") if a.email == default_email else ""
        used = format_bytes(a.quota_used) if a.quota_used is not None else "-"
        total = format_bytes(a.quota_total) if a.quota_total is not None else "-"
        table.add_row(
            is_default,
            a.email,
            a.label or "",
            used,
            total,
            a.last_used_iso or "-",
        )
    _console.print(table)


def render_queue(items: list[dict]) -> None:
    if not items:
        _console.print("[mb.dim]Queue is empty.[/mb.dim]")
        return

    table = SafeTable(
        title="Transfer Queue",
        show_header=True,
        header_style="mb.table.header",
        border_style="mb.table.border",
    )
    table.add_column("#", width=4)
    table.add_column("Type", width=10)
    table.add_column("Source")
    table.add_column("Destination")
    table.add_column("Size")
    table.add_column("Status")

    for i, item in enumerate(items, 1):
        table.add_row(
            str(i),
            item.get("type", "?"),
            item.get("source", ""),
            item.get("destination", ""),
            format_bytes(item.get("size", 0)),
            item.get("status", ""),
        )
    _console.print(table)
