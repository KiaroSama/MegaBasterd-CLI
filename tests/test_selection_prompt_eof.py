"""EOF at the file-selection prompt must cancel cleanly, not crash.

Reported:

    echo "0" | mb download <folder-url> --output <dir> --select

`0` is out of range, so the picker prints "Invalid selection" and loops to ask
again - but stdin is now exhausted. `click.prompt` raises `click.Abort` on EOF,
with an EMPTY message, and nothing between the picker and the command's
catch-all handles it. The consumer got "Unexpected error during folder
download" plus a raw traceback out of `_apply_file_filter`.

The prompt already offers `none`, and answering it is a documented clean skip
(`SelectionCancelled` -> "skipped", exit stays 0). End of input is the same
answer: there is nobody left to ask. So EOF routes there instead of escaping.

Note the invalid answer is what exposes it. Without it the first prompt hits
EOF too, so any non-interactive `--select` run was affected; the reported
recipe just makes the loop obvious.
"""

from __future__ import annotations

import io
import sys
from pathlib import Path

import click
import pytest

from megabasterd_cli.commands.download_support import _interactive_file_picker
from megabasterd_cli.utils.selection import SelectionCancelled


class _Node:
    """Only what the picker reads off a node."""

    def __init__(self, name="a.mkv", size=100):
        self.name = name
        self.size = size


def _jobs(count=1):
    return [(_Node(f"f{i}.mkv"), Path("out") / f"f{i}.mkv") for i in range(count)]


@pytest.fixture()
def stdin_text(monkeypatch):
    def _set(text: str):
        monkeypatch.setattr(sys, "stdin", io.StringIO(text))

    return _set


def test_an_invalid_answer_then_eof_cancels_instead_of_crashing(stdin_text):
    """The reported recipe, exactly: one out-of-range token, then nothing."""
    stdin_text("0\n")
    with pytest.raises(SelectionCancelled):
        _interactive_file_picker(Path("out"))(_jobs())


def test_immediate_eof_cancels(stdin_text):
    """No answer at all is the same situation: nobody left to ask."""
    stdin_text("")
    with pytest.raises(SelectionCancelled):
        _interactive_file_picker(Path("out"))(_jobs())


def test_eof_does_not_raise_click_abort(stdin_text):
    """`click.Abort` carries an empty message, which is why the old failure
    surfaced as a bare traceback rather than anything a consumer could read."""
    stdin_text("0\n")
    try:
        _interactive_file_picker(Path("out"))(_jobs())
    except SelectionCancelled:
        pass
    except click.Abort as exc:  # pragma: no cover - the defect
        pytest.fail(f"click.Abort escaped the picker: {exc!r}")


def test_the_cancellation_is_explained_on_stdout(capsys, stdin_text):
    """A silent cancel is the shape this project keeps getting burnt by - the
    operator must be able to tell "input ran out" from "I chose none"."""
    stdin_text("0\n")
    with pytest.raises(SelectionCancelled):
        _interactive_file_picker(Path("out"))(_jobs())
    out = capsys.readouterr().out
    assert "end of input" in out.lower()


def test_an_explicit_none_still_cancels(stdin_text):
    """The path EOF now joins must keep working on its own."""
    stdin_text("none\n")
    with pytest.raises(SelectionCancelled):
        _interactive_file_picker(Path("out"))(_jobs())


def test_a_valid_answer_after_an_invalid_one_still_selects(stdin_text):
    """The retry loop is the point of the prompt; EOF handling must not eat it."""
    stdin_text("0\n2\n")
    chosen = _interactive_file_picker(Path("out"))(_jobs(3))
    assert [job[1].name for job in chosen] == ["f1.mkv"]


def test_the_default_all_still_applies(stdin_text):
    """A blank answer means every file, and that is not EOF."""
    stdin_text("\n")
    chosen = _interactive_file_picker(Path("out"))(_jobs(2))
    assert len(chosen) == 2
