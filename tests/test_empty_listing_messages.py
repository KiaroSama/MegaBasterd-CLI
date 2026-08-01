"""An empty listing must say WHICH thing is empty.

`_render_nodes` printed one line - `No items` - for five different situations:
an empty account, an empty Cloud Drive root, an empty folder the user named, a
search that matched nothing, and an empty trash. From the output you could not
tell "you have no files" from "that folder is empty" from "your search found
nothing", and none of them from a listing that silently returned nothing.

That is the shape this project keeps getting burnt by: one message for several
outcomes. A decline, a repair and a no-op all printed "Command completed
successfully" once, which is how an unrecognised answer at a y/n prompt read as
a successful removal.

Found while fixing that: the emptiness check ran BEFORE the loop that skips
root/trash/inbox, so an account holding only those three system nodes passed
`if not nodes` and rendered a table with headers and zero rows. `mb ls --all`
on an empty account printed that, not a message.
"""

from __future__ import annotations

import io

import pytest

from megabasterd_cli.commands import cloud_cmd
from megabasterd_cli.ui.theme import make_console

from .fake_mega import FakeMegaAPI, logged_in_client


@pytest.fixture()
def rendered(monkeypatch):
    """Capture what `_render_nodes` prints, through the real project theme."""
    buf = io.StringIO()
    monkeypatch.setattr(cloud_cmd, "_console", make_console(file=buf, width=100))
    return buf


def _account(*, files: bool = False):
    api = FakeMegaAPI().with_default_tree()
    if files:
        api.add_file("keep.bin", api.root)
    client, _ = logged_in_client(api)
    return client, api


# ---------------------------------------------------------------------------
# the header-only table
# ---------------------------------------------------------------------------


def test_an_account_with_only_system_nodes_prints_a_message_not_a_table(rendered):
    """`mb ls --all` on an empty account rendered headers and zero rows."""
    client, _ = _account()

    cloud_cmd._render_nodes(client.list_files(), empty_message="Your MEGA account is empty.")

    out = rendered.getvalue()
    assert "Handle" not in out, "an empty account still drew the table header"
    assert "Your MEGA account is empty." in out


def test_a_non_empty_account_still_renders_the_table(rendered):
    """The guard must not swallow real rows."""
    client, _ = _account(files=True)

    cloud_cmd._render_nodes(client.list_files())

    out = rendered.getvalue()
    assert "Handle" in out and "keep.bin" in out


# ---------------------------------------------------------------------------
# one message per situation
# ---------------------------------------------------------------------------


def test_each_caller_supplies_its_own_wording(rendered):
    client, api = _account()
    empty_folder = api.add_folder("photos", api.root)
    client.invalidate_cache()

    cloud_cmd._render_nodes(
        client.list_files(),
        parent_filter=empty_folder,
        empty_message="Folder 'photos' is empty.",
    )

    assert "Folder 'photos' is empty." in rendered.getvalue()


def test_the_default_wording_is_still_available(rendered):
    """Callers that have nothing more specific to say keep the old line."""
    client, _ = _account()

    cloud_cmd._render_nodes(client.list_files(), parent_filter="nosuchparent")

    assert "No items" in rendered.getvalue()


@pytest.mark.parametrize(
    "command,expected",
    [
        ("ls_cmd", "Cloud Drive is empty"),
        ("search_cmd", "Nothing matched"),
        ("trash_list", "trash is empty"),
    ],
)
def test_every_listing_command_names_what_is_empty(command, expected):
    """Source-level, because the wording is the whole point of this change.

    Asserting on the command bodies rather than driving each CLI keeps this
    honest about WHICH command owns WHICH message - a single behavioural test
    would pass with all five sharing one string again.
    """
    import inspect

    source = inspect.getsource(getattr(cloud_cmd, command).callback)
    assert "empty_message" in source, f"{command} still uses the generic line"
    assert expected in source


def test_no_two_listing_commands_share_an_empty_message():
    """The regression that would undo this: someone factors the strings back
    into one constant and every situation reads the same again."""
    import inspect
    import re

    seen: dict[str, str] = {}
    for name in ("ls_cmd", "search_cmd", "trash_list"):
        source = inspect.getsource(getattr(cloud_cmd, name).callback)
        for message in re.findall(r"empty_message=[^,)]*?['\"]([^'\"]+)['\"]", source):
            assert message not in seen, f"{name} reuses {seen[message]}'s wording: {message!r}"
            seen[message] = name
    assert len(seen) >= 3, f"expected a distinct message per situation, found {seen}"


# ---------------------------------------------------------------------------
# the message crosses the trusted/untrusted boundary
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "hostile",
    ["[bold red]owned[/bold red]", "unbalanced [tag", "[/close-only]"],
    ids=["styled", "unbalanced", "closing"],
)
def test_a_folder_name_in_the_message_cannot_inject_markup(rendered, hostile):
    """The folder name comes from the user (and, for a share, from MEGA).

    `theme.py` draws this line explicitly: a plain `str` is UNTRUSTED and must
    render verbatim. An f-string into Rich markup would let a name restyle the
    line, or abort the whole render with MarkupError on an unbalanced tag.
    """
    client, _ = _account()

    cloud_cmd._render_nodes(
        client.list_files(),
        empty_message=f"Folder {hostile!r} is empty.",
    )

    out = rendered.getvalue()
    assert hostile in out, "the name was not rendered verbatim"
