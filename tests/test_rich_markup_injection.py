"""Regression tests: untrusted remote text must never be parsed as Rich markup.

MEGA filenames, MegaCrypter server responses and server-supplied error strings all
reach a Rich console with markup enabled. Rich would either apply attacker-chosen
styling or raise `MarkupError` on an unbalanced tag and abort the whole listing.
"""

from __future__ import annotations

import pytest
from rich.markup import MarkupError

from megabasterd_cli.commands import cloud_cmd
from megabasterd_cli.core.client import MegaNode
from megabasterd_cli.ui import prompts, tables
from megabasterd_cli.ui.theme import make_console


def _node(name: str) -> MegaNode:
    return MegaNode(
        handle="AAAAAAAA",
        parent="PPPPPPPP",
        owner="OOOOOOOO",
        node_type=0,
        size=1234,
        timestamp=0,
        raw_attrs=b"",
        raw_key="",
        name=name,
    )


@pytest.fixture
def wide_console(monkeypatch):
    """Give the module consoles a wide, non-wrapping capture surface."""
    consoles = {}

    def patch(module):
        console = make_console(width=200)
        monkeypatch.setattr(module, "_console", console)
        consoles[module] = console
        return console

    patch(cloud_cmd)
    patch(prompts)
    patch(tables)
    return consoles


def _capture(console, fn, *args, **kwargs) -> str:
    with console.capture() as cap:
        fn(*args, **kwargs)
    return cap.get()


# --------------------------------------------------------------------------
# Untrusted values must be shown literally
# --------------------------------------------------------------------------


def test_remote_name_with_markup_is_shown_literally(wide_console):
    out = _capture(cloud_cmd._console, cloud_cmd._render_nodes, [_node("[bold red]x[/]")])
    assert "[bold red]x[/]" in out


def test_remote_name_with_lone_bracket_does_not_abort_listing(wide_console):
    """A lone `[` used to raise MarkupError and kill the entire `mb ls` output."""
    nodes = [_node("weird[name.mp4"), _node("holiday [/] clip.mp4"), _node("normal.mp4")]
    try:
        out = _capture(cloud_cmd._console, cloud_cmd._render_nodes, nodes)
    except MarkupError as exc:  # pragma: no cover - the bug we are fixing
        pytest.fail(f"listing aborted on a lone '[' in a remote name: {exc}")
    assert "weird[name.mp4" in out
    assert "holiday [/] clip.mp4" in out
    assert "normal.mp4" in out


def test_server_error_text_with_markup_is_neutralised(wide_console):
    exc = RuntimeError("boom [bold red]pwned[/bold red] [/]")
    out = _capture(prompts._console, prompts.print_error, f"Login failed: {exc}")
    assert "[bold red]pwned[/bold red]" in out


def test_error_text_with_lone_bracket_does_not_raise(wide_console):
    out = _capture(prompts._console, prompts.print_error, "Lookup failed: bad token [oops")
    assert "[oops" in out


def test_untrusted_table_cell_via_safe_table(wide_console):
    from megabasterd_cli.ui.theme import SafeTable

    table = SafeTable(show_header=False)
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Name", "[bold red]evil[/bold red]")
    table.add_row("Handle", "abc[def")
    out = _capture(cloud_cmd._console, cloud_cmd._console.print, table)
    assert "[bold red]evil[/bold red]" in out
    assert "abc[def" in out


# --------------------------------------------------------------------------
# The app's own deliberate styling must keep working
# --------------------------------------------------------------------------


def test_app_own_markup_still_renders(wide_console):
    out = _capture(cloud_cmd._console, cloud_cmd._render_nodes, [])
    assert "No items" in out
    assert "[mb.dim]" not in out


def test_print_helper_prefix_still_renders(wide_console):
    out = _capture(prompts._console, prompts.print_success, "done")
    assert "OK" in out and "done" in out
    assert "[mb.success]" not in out


def test_trusted_cell_markup_still_renders(wide_console):
    accounts_out = _capture(
        tables._console,
        tables.render_accounts,
        [_FakeAccount("a@b.c")],
        "a@b.c",
    )
    assert "[mb.success]" not in accounts_out
    assert "Y" in accounts_out


class _FakeAccount:
    def __init__(self, email: str) -> None:
        self.email = email
        self.label = "[bold red]label[/bold red]"
        self.quota_used = None
        self.quota_total = None
        self.last_used_iso = None


def test_account_label_is_untrusted(wide_console):
    out = _capture(tables._console, tables.render_accounts, [_FakeAccount("a@b.c")], "a@b.c")
    assert "[bold red]label[/bold red]" in out
