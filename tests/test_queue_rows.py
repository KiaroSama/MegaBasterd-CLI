"""Queue progress rows must end in the real job status (Mandatory Fix 5)."""

from __future__ import annotations

import pytest
from click.testing import CliRunner

import megabasterd_cli.ui.transfer_progress as tp_module
from megabasterd_cli.cli import cli
from megabasterd_cli.core.downloader import MegaDownloader
from megabasterd_cli.core.errors import TransferError
from megabasterd_cli.queue.manager import JobStatus, QueueItem, QueueManager

FILE_URL = "https://mega.nz/file/abc123#xyz"


@pytest.fixture()
def cli_env(tmp_path, monkeypatch):
    monkeypatch.setenv("MEGABASTERD_USER_DIR", str(tmp_path / "user"))
    monkeypatch.setenv("MEGABASTERD_LOG_DIR", str(tmp_path / "logs"))
    return tmp_path


@pytest.fixture()
def captured_progress(monkeypatch):
    """Record every TransferProgress the queue run creates."""
    instances: list[tp_module.TransferProgress] = []
    original = tp_module.TransferProgress

    class Recording(original):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            instances.append(self)

    monkeypatch.setattr(tp_module, "TransferProgress", Recording)
    return instances


def _queue_path(tmp_path):
    from megabasterd_cli.config import data_dir

    return data_dir() / "queue.json"


def _statuses(instances) -> list[str]:
    assert instances, "queue run must create a progress controller"
    return list(instances[-1].statuses().values())


def test_download_error_finalizes_row_failed(cli_env, monkeypatch, captured_progress):
    runner = CliRunner()
    runner.invoke(cli, ["-q", "queue", "add-download", FILE_URL, "-o", str(cli_env / "o")])

    def boom(self, url, output_dir, **kwargs):
        raise TransferError(message="simulated")

    monkeypatch.setattr(MegaDownloader, "download_link", boom)
    result = runner.invoke(cli, ["-q", "queue", "run"])
    assert result.exit_code == 1
    statuses = _statuses(captured_progress)
    assert statuses == ["failed"]
    q = QueueManager(_queue_path(cli_env))
    assert q.items[0].status == JobStatus.FAILED.value
    assert captured_progress[-1].final_success() is False


def test_missing_local_file_creates_visible_failed_row(cli_env, monkeypatch, captured_progress):
    runner = CliRunner()
    src = cli_env / "gone.bin"
    src.write_bytes(b"x")
    add = runner.invoke(cli, ["-q", "queue", "add-upload", str(src), "-a", "acc@example.com"])
    assert add.exit_code == 0
    src.unlink()  # file disappears before the run

    # An account store exists so the account-resolution branch is passed.
    from megabasterd_cli.accounts.manager import AccountManager
    from megabasterd_cli.config import accounts_file
    from megabasterd_cli.core.client import MegaClient, MegaSession

    mgr = AccountManager(accounts_file())
    mgr.unlock("pp")
    mgr.add_account("acc@example.com", "secret", make_default=True)

    def fake_login(self, email, password, mfa_code=None, mfa_prompt=None):
        self.session = MegaSession(sid="sid", master_key=b"\x00" * 16, email=email)
        return self.session

    monkeypatch.setattr(MegaClient, "login", fake_login)
    monkeypatch.setattr(MegaClient, "logout", lambda self: None)

    result = runner.invoke(cli, ["-q", "queue", "run", "--vault-passphrase", "pp"])
    assert result.exit_code == 1
    assert _statuses(captured_progress) == ["failed"]
    q = QueueManager(_queue_path(cli_env))
    assert q.items[0].status == JobStatus.FAILED.value
    assert "missing" in (q.items[0].error or "").lower()


def test_unknown_job_type_in_file_is_corruption(cli_env, captured_progress):
    """MF7: an unknown job type in the queue file is a schema violation and is
    treated as corruption (preserved + non-zero exit), not silently run."""
    q = QueueManager(_queue_path(cli_env))
    q.add(
        QueueItem(
            id=QueueItem.new_id(),
            type="teleport",
            source="somewhere",
            destination="",
        )
    )
    original = _queue_path(cli_env).read_bytes()
    runner = CliRunner()
    result = runner.invoke(cli, ["-q", "queue", "run"])
    assert result.exit_code == 1
    # No transfer controller is created: the corrupt file is not run.
    assert captured_progress == [] or _statuses(captured_progress) == []
    # Original preserved byte-for-byte; a backup exists.
    assert _queue_path(cli_env).read_bytes() == original
    backups = list(_queue_path(cli_env).parent.glob("queue.json.corrupt.*"))
    assert backups, "a corrupt-queue backup must be created"


def test_keyboard_interrupt_cancels_row_and_releases_lease(cli_env, monkeypatch, captured_progress):
    runner = CliRunner()
    runner.invoke(cli, ["-q", "queue", "add-download", FILE_URL, "-o", str(cli_env / "o")])

    def interrupted(self, url, output_dir, **kwargs):
        raise KeyboardInterrupt()

    monkeypatch.setattr(MegaDownloader, "download_link", interrupted)
    result = runner.invoke(cli, ["-q", "queue", "run"], standalone_mode=False)
    # click surfaces KeyboardInterrupt as Abort in non-standalone mode.
    import click as click_module

    assert isinstance(result.exception, (KeyboardInterrupt, click_module.exceptions.Abort))
    assert _statuses(captured_progress) == ["canceled"]
    q = QueueManager(_queue_path(cli_env))
    assert q.items[0].status == JobStatus.INTERRUPTED.value
    assert q.items[0].run_id is None, "the lease must be released on cancellation"


def test_no_queue_run_leaves_active_rows(cli_env, monkeypatch, captured_progress):
    runner = CliRunner()
    runner.invoke(cli, ["-q", "queue", "add-download", FILE_URL, "-o", str(cli_env / "o")])
    runner.invoke(
        cli, ["-q", "queue", "add-download", "https://mega.nz/file/def#u", "-o", str(cli_env / "o")]
    )

    calls = {"n": 0}

    def flaky(self, url, output_dir, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise TransferError(message="first fails")
        from pathlib import Path

        from megabasterd_cli.core.downloader import DownloadResult

        p = Path(output_dir) / "ok.bin"
        p.write_bytes(b"x")
        return DownloadResult(path=p, size=1, elapsed_seconds=0.1, integrity_ok=True)

    monkeypatch.setattr(MegaDownloader, "download_link", flaky)
    result = runner.invoke(cli, ["-q", "queue", "run"])
    assert result.exit_code == 1
    statuses = _statuses(captured_progress)
    assert sorted(statuses) == ["complete", "failed"]
    assert all(s in {"complete", "failed", "canceled", "skipped"} for s in statuses)
    q = QueueManager(_queue_path(cli_env))
    by_type = sorted(i.status for i in q.items)
    assert by_type == [JobStatus.DONE.value, JobStatus.FAILED.value]
