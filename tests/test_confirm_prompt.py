"""An unrecognised answer at a y/n prompt must be re-asked, not scored as no.

Reported from a real session: at `Really remove <account>? (y/n) [N]:` the
operator typed a character in the wrong keyboard layout. It was not "y", so it
counted as no, `account remove` returned without printing anything, and the
launcher reported "Command completed successfully". The account was still
there. Nothing about that output distinguished "declined" from "done".

Two separate defects, and the second is the one that made the first invisible:

* `confirm` accepted anything-that-is-not-yes as no, silently;
* every caller was `if not confirm(...): return` with no output at all.
"""

from __future__ import annotations

import pytest

from megabasterd_cli.ui import prompts


def _answers(monkeypatch, *lines):
    """Feed `input()` a script, and record what was printed."""
    queue = list(lines)
    printed: list[str] = []

    def fake_input(_prompt=""):
        if not queue:
            raise EOFError
        return queue.pop(0)

    monkeypatch.setattr("builtins.input", fake_input)
    monkeypatch.setattr(prompts._console, "print", lambda *a, **kw: printed.append(_text(a)))
    return printed, queue


def _text(args) -> str:
    return " ".join(getattr(a, "plain", str(a)) for a in args)


# ---------------------------------------------------------------------------
# confirm
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("answer", ["غ", "بله", "q", "1", "yep", "sure", "ن"])
def test_an_unrecognised_answer_is_re_asked(monkeypatch, answer):
    """The concrete report: one keystroke in the wrong layout."""
    printed, queue = _answers(monkeypatch, answer, "y")

    assert prompts.confirm("Really remove it?", default=False) is True
    assert not queue, "the second answer was never read, so it did not re-ask"
    assert any("y or n" in line for line in printed), printed


def test_enter_still_takes_the_shown_default(monkeypatch):
    _answers(monkeypatch, "")
    assert prompts.confirm("Proceed?", default=False) is False
    _answers(monkeypatch, "")
    assert prompts.confirm("Proceed?", default=True) is True


@pytest.mark.parametrize(
    ("answer", "expected"), [("y", True), ("Yes", True), ("n", False), ("NO", False)]
)
def test_the_explicit_answers_still_work(monkeypatch, answer, expected):
    _answers(monkeypatch, answer)
    assert prompts.confirm("Proceed?", default=not expected) is expected


def test_eof_takes_the_default_rather_than_looping(monkeypatch):
    """A redirected or closed stdin must not spin here forever."""
    _answers(monkeypatch)  # no lines at all -> EOFError on the first read
    assert prompts.confirm("Proceed?", default=False) is False


# ---------------------------------------------------------------------------
# confirmed
# ---------------------------------------------------------------------------


def test_declining_says_so(monkeypatch):
    """A declined action and a completed one used to look identical."""
    printed, _ = _answers(monkeypatch, "n")

    assert prompts.confirmed("Really remove it?") is False
    assert any("Cancelled" in line for line in printed), printed


def test_accepting_prints_no_cancellation_note(monkeypatch):
    printed, _ = _answers(monkeypatch, "y")

    assert prompts.confirmed("Really remove it?") is True
    assert not any("Cancelled" in line for line in printed), printed


def test_every_destructive_confirm_reports_a_decline():
    """No caller may go back to the silent form.

    `confirm` is still fine for branching, but a command that RETURNS on a no
    has to say so, or the launcher's "Command completed successfully" is the
    only thing the operator sees.
    """
    import inspect

    from megabasterd_cli.commands import account_cmd, proxy_cmd, queue_cmd

    for module in (account_cmd, proxy_cmd, queue_cmd):
        source = inspect.getsource(module)
        assert (
            "if not confirm(" not in source
        ), f"{module.__name__} declines silently; use `confirmed()`"
