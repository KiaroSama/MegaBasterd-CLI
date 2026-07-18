"""`mb watch` defects (C9).

1. The full clipboard link - decryption key included - was echoed to the
   terminal and into scrollback. Every comparable site uses `redact_link()`.
2. `--interval` was an unvalidated float: 0 busy-spins the poller and a
   negative value made `time.sleep()` raise ValueError on the first tick.
3. `q.add()` raises QueueCorruptionError/QueueLockError, neither of which the
   `except KeyboardInterrupt` handler caught, so one corrupt queue file killed
   the long-running watcher with a traceback.
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner

import megabasterd_cli.commands.watch_cmd as watch_cmd
from megabasterd_cli.cli import cli
from megabasterd_cli.queue.manager import QueueCorruptionError, QueueLockError, QueueManager

FILE_URL = "https://mega.nz/file/abc123#SuperSecretKeyMaterial"
KEY = "SuperSecretKeyMaterial"


@pytest.fixture()
def cli_env(tmp_path, monkeypatch):
    monkeypatch.setenv("MEGABASTERD_USER_DIR", str(tmp_path / "user"))
    monkeypatch.setenv("MEGABASTERD_LOG_DIR", str(tmp_path / "logs"))
    return tmp_path


def _clipboard(monkeypatch, *values: str) -> None:
    """Feed the watcher a fixed script, then stop it with Ctrl-C."""
    queued = list(values)

    def fake_read() -> str:
        if not queued:
            raise KeyboardInterrupt
        return queued.pop(0)

    monkeypatch.setattr(watch_cmd, "_read_clipboard", fake_read)


def _queue_path(cli_env):
    from megabasterd_cli.config import data_dir

    return data_dir() / "queue.json"


def test_queued_link_is_redacted_on_screen(cli_env, monkeypatch):
    _clipboard(monkeypatch, "", FILE_URL)
    result = CliRunner().invoke(cli, ["watch", "--interval", "0.05"])
    assert result.exit_code == 0
    assert KEY not in result.output, "the decryption key must never reach the terminal"
    assert "#<key>" in result.output
    # The real link is still stored so the job can actually run.
    assert QueueManager(_queue_path(cli_env)).items[0].source == FILE_URL


@pytest.mark.parametrize("bad", ["0", "-1", "-0.5"])
def test_non_positive_interval_is_rejected(cli_env, bad):
    result = CliRunner().invoke(cli, ["watch", "--interval", bad])
    assert result.exit_code == 2, "an unusable poll interval must fail fast"
    assert "interval" in result.output.lower()


def test_corrupt_queue_exits_cleanly_instead_of_raising(cli_env, monkeypatch):
    _clipboard(monkeypatch, "", FILE_URL)

    def corrupt_add(self, item):
        raise QueueCorruptionError("The transfer queue file is corrupt and was preserved.")

    monkeypatch.setattr(QueueManager, "add", corrupt_add)
    result = CliRunner().invoke(cli, ["watch", "--interval", "0.05"])
    assert result.exit_code == 1
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "corrupt" in result.output.lower()


def test_transient_lock_error_does_not_kill_the_watcher(cli_env, monkeypatch):
    _clipboard(monkeypatch, "", FILE_URL, "https://mega.nz/file/second#k2")
    calls: list[str] = []
    real_add = QueueManager.add

    def flaky_add(self, item):
        calls.append(item.source)
        if len(calls) == 1:
            raise QueueLockError("Could not lock the transfer queue within 10s")
        return real_add(self, item)

    monkeypatch.setattr(QueueManager, "add", flaky_add)
    result = CliRunner().invoke(cli, ["watch", "--interval", "0.05"])
    assert result.exit_code == 0, "a transient lock failure must not stop the watcher"
    assert len(calls) == 2, "the watcher must keep polling after a lock failure"
    assert QueueManager(_queue_path(cli_env)).items[0].source == "https://mega.nz/file/second#k2"


def test_an_already_corrupt_queue_is_reported_before_watching(cli_env, monkeypatch):
    path = _queue_path(cli_env)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{not json", encoding="utf-8")
    _clipboard(monkeypatch, "", FILE_URL)
    result = CliRunner().invoke(cli, ["watch", "--interval", "0.05"])
    assert result.exit_code == 1
    assert "corrupt" in result.output.lower()
