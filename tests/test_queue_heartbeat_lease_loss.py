"""A runner that stops heartbeating must stop transferring (B12, part 2).

Historical bug: `queue run` wrapped `q.touch` in `contextlib.suppress(Exception)`,
so a `QueueLockError` from the 10s file-lock timeout was swallowed. The run kept
downloading with a lease it had silently stopped renewing; after LEASE_SECONDS a
second run re-leased the job and BOTH processes wrote to the same directory.

Every wait here is driven by `threading.Event` and bounded by a hard timeout.
"""

from __future__ import annotations

import threading

import pytest
from click.testing import CliRunner

import megabasterd_cli.commands.queue_cmd as queue_cmd
from megabasterd_cli.cli import cli
from megabasterd_cli.core.downloader import DownloadResult, MegaDownloader
from megabasterd_cli.core.errors import TransferCancelled
from megabasterd_cli.queue.manager import (
    JobStatus,
    QueueLockError,
    QueueManager,
)

FILE_URL = "https://mega.nz/file/abc123#xyz"
# Hard bound: every blocking wait in this module fails rather than hanging.
TIMEOUT = 30.0


@pytest.fixture()
def cli_env(tmp_path, monkeypatch):
    monkeypatch.setenv("MEGABASTERD_USER_DIR", str(tmp_path / "user"))
    monkeypatch.setenv("MEGABASTERD_LOG_DIR", str(tmp_path / "logs"))
    # Beat fast so the test is driven by events, never by wall-clock waiting.
    monkeypatch.setattr(queue_cmd, "_HEARTBEAT_SECONDS", 0.01)
    monkeypatch.setattr(queue_cmd, "_HEARTBEAT_GRACE_SECONDS", 0.05)
    return tmp_path


def _queue(cli_env) -> QueueManager:
    from megabasterd_cli.config import data_dir

    return QueueManager(data_dir() / "queue.json")


def _add_job(cli_env) -> CliRunner:
    runner = CliRunner()
    result = runner.invoke(cli, ["-q", "queue", "add-download", FILE_URL, "-o", str(cli_env / "o")])
    assert result.exit_code == 0
    return runner


def _blocking_download(started: threading.Event):
    """A transfer that only ends when the runner calls `MegaDownloader.stop()`."""

    def fake(self, url, output_dir, **kwargs):
        started.set()
        if not self._stop_event.wait(TIMEOUT):
            raise AssertionError("the runner never stopped the in-flight transfer")
        raise TransferCancelled(message="stopped by the runner")

    return fake


def test_repeated_heartbeat_failures_stop_the_in_flight_transfer(cli_env, monkeypatch):
    runner = _add_job(cli_env)
    started = threading.Event()

    def locked_touch(self, item_id, run_id, lease_epoch=None):
        # Healthy until the transfer is genuinely in flight, so the test always
        # exercises "stop the running transfer", never "refuse to start".
        if not started.is_set():
            return True
        raise QueueLockError("Could not lock the transfer queue within 10s")

    monkeypatch.setattr(QueueManager, "touch", locked_touch)
    monkeypatch.setattr(MegaDownloader, "download_link", _blocking_download(started))

    result = runner.invoke(cli, ["-q", "queue", "run"])
    assert started.is_set(), "the transfer must have started before the heartbeat failed"
    assert result.exit_code == 1
    assert "lease" in result.output.lower()
    assert _queue(cli_env).items[0].status != JobStatus.DONE.value


def test_a_lost_lease_stops_the_in_flight_transfer(cli_env, monkeypatch):
    """`touch` reporting False (another run owns the job) is equally fatal."""
    runner = _add_job(cli_env)
    started = threading.Event()

    def stolen_touch(self, item_id, run_id, lease_epoch=None):
        return started.is_set() is False  # healthy until the transfer starts

    monkeypatch.setattr(QueueManager, "touch", stolen_touch)
    monkeypatch.setattr(MegaDownloader, "download_link", _blocking_download(started))

    result = runner.invoke(cli, ["-q", "queue", "run"])
    assert started.is_set()
    assert result.exit_code == 1
    assert _queue(cli_env).items[0].status != JobStatus.DONE.value


def test_a_lost_lease_stops_the_run_instead_of_claiming_more_jobs(cli_env, monkeypatch):
    runner = _add_job(cli_env)
    second = runner.invoke(
        cli, ["-q", "queue", "add-download", "https://mega.nz/file/second#k", "-o", str(cli_env)]
    )
    assert second.exit_code == 0
    started = threading.Event()
    calls: list[str] = []

    def stolen_touch(self, item_id, run_id, lease_epoch=None):
        return started.is_set() is False  # healthy until the transfer starts

    def fake(self, url, output_dir, **kwargs):
        calls.append(url)
        return _blocking_download(started)(self, url, output_dir, **kwargs)

    monkeypatch.setattr(QueueManager, "touch", stolen_touch)
    monkeypatch.setattr(MegaDownloader, "download_link", fake)

    result = runner.invoke(cli, ["-q", "queue", "run"])
    assert result.exit_code == 1
    assert len(calls) == 1, "a run that lost its lease must not claim the next job"


def test_a_healthy_heartbeat_still_completes_the_job(cli_env, monkeypatch):
    """The guard must not abort runs whose heartbeat is working."""
    runner = _add_job(cli_env)
    out = cli_env / "o" / "file.bin"

    def fake(self, url, output_dir, **kwargs):
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(b"x")
        return DownloadResult(path=out, size=1, elapsed_seconds=0.1, integrity_ok=True)

    monkeypatch.setattr(MegaDownloader, "download_link", fake)
    result = runner.invoke(cli, ["-q", "queue", "run"])
    assert result.exit_code == 0, result.output
    assert _queue(cli_env).items[0].status == JobStatus.DONE.value
