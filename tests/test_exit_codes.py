"""Non-zero exit codes for failed transfers.

Historical bug: transfer helpers caught errors, printed a message, and
returned normally, so automation received exit code 0 after failures.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

import megabasterd_cli.commands.download_cmd as download_cmd_module
from megabasterd_cli.cli import cli
from megabasterd_cli.core.downloader import DownloadResult, MegaDownloader
from megabasterd_cli.core.errors import TransferError
from megabasterd_cli.core.uploader import MegaUploader, UploadResult

FILE_URL = "https://mega.nz/file/abc123#xyz"
FILE_URL_2 = "https://mega.nz/file/def456#uvw"


@pytest.fixture()
def cli_env(tmp_path, monkeypatch):
    monkeypatch.setenv("MEGABASTERD_USER_DIR", str(tmp_path / "user"))
    monkeypatch.setenv("MEGABASTERD_LOG_DIR", str(tmp_path / "logs"))
    return tmp_path


def test_single_failed_download_exits_nonzero(cli_env, monkeypatch):
    def boom(self, url, output_dir, **kwargs):
        raise TransferError(message="simulated failure")

    monkeypatch.setattr(MegaDownloader, "download_link", boom)
    runner = CliRunner()
    result = runner.invoke(cli, ["-q", "download", FILE_URL, "-o", str(cli_env / "out")])
    assert result.exit_code == 1


def test_mixed_batch_completes_then_exits_nonzero(cli_env, monkeypatch):
    calls: list[str] = []

    def flaky(self, url, output_dir, **kwargs):
        calls.append(url)
        if "abc123" in url:
            raise TransferError(message="simulated failure")
        path = Path(output_dir) / "ok.bin"
        path.write_bytes(b"x")
        return DownloadResult(path=path, size=1, elapsed_seconds=0.1, integrity_ok=True)

    monkeypatch.setattr(MegaDownloader, "download_link", flaky)
    runner = CliRunner()
    result = runner.invoke(
        cli, ["-q", "download", FILE_URL, FILE_URL_2, "-P", "1", "-o", str(cli_env / "out")]
    )
    assert len(calls) == 2, "--batch must continue past the failed item"
    assert result.exit_code == 1


def test_fully_successful_download_exits_zero(cli_env, monkeypatch):
    def ok(self, url, output_dir, **kwargs):
        path = Path(output_dir) / "ok.bin"
        path.write_bytes(b"x")
        return DownloadResult(path=path, size=1, elapsed_seconds=0.1, integrity_ok=True)

    monkeypatch.setattr(MegaDownloader, "download_link", ok)
    runner = CliRunner()
    result = runner.invoke(cli, ["-q", "download", FILE_URL, "-o", str(cli_env / "out")])
    assert result.exit_code == 0


def test_invalid_link_counts_as_failure(cli_env):
    runner = CliRunner()
    result = runner.invoke(cli, ["-q", "download", "not-a-mega-link", "-o", str(cli_env / "o")])
    assert result.exit_code == 1


def _setup_account(tmp_path):
    from megabasterd_cli.accounts.manager import AccountManager
    from megabasterd_cli.config import accounts_file

    mgr = AccountManager(accounts_file())
    mgr.unlock("pp")
    mgr.add_account("acc@example.com", "secret", make_default=True)


def _fake_login(self, email, password, mfa_code=None, mfa_prompt=None):
    from megabasterd_cli.core.client import MegaSession

    self.session = MegaSession(sid="sid", master_key=b"\x00" * 16, email=email)
    return self.session


def test_failed_upload_exits_nonzero(cli_env, monkeypatch, tmp_path):
    from megabasterd_cli.core.client import MegaClient

    _setup_account(cli_env)
    monkeypatch.setattr(MegaClient, "login", _fake_login)
    monkeypatch.setattr(MegaClient, "logout", lambda self: None)

    def boom(self, source, **kwargs):
        raise TransferError(message="simulated upload failure")

    monkeypatch.setattr(MegaUploader, "upload_file", boom)
    src = tmp_path / "up.bin"
    src.write_bytes(b"data")
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["-q", "upload", str(src), "--vault-passphrase", "pp", "-a", "acc@example.com"],
    )
    assert result.exit_code == 1


def test_successful_upload_exits_zero(cli_env, monkeypatch, tmp_path):
    from megabasterd_cli.core.client import MegaClient

    _setup_account(cli_env)
    monkeypatch.setattr(MegaClient, "login", _fake_login)
    monkeypatch.setattr(MegaClient, "logout", lambda self: None)

    def ok(self, source, **kwargs):
        return UploadResult(file_handle="H", name=source.name, size=4, elapsed_seconds=0.2)

    monkeypatch.setattr(MegaUploader, "upload_file", ok)
    src = tmp_path / "up.bin"
    src.write_bytes(b"data")
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["-q", "upload", str(src), "--vault-passphrase", "pp", "-a", "acc@example.com"],
    )
    assert result.exit_code == 0, result.output


def test_queue_run_exits_nonzero_and_keeps_item_statuses(cli_env, monkeypatch):
    from megabasterd_cli.config import data_dir
    from megabasterd_cli.queue.manager import JobStatus, QueueManager

    runner = CliRunner()
    add = runner.invoke(cli, ["-q", "queue", "add-download", FILE_URL, "-o", str(cli_env / "out")])
    assert add.exit_code == 0

    def boom(self, url, output_dir, **kwargs):
        raise TransferError(message="simulated failure")

    monkeypatch.setattr(MegaDownloader, "download_link", boom)
    result = runner.invoke(cli, ["-q", "queue", "run"])
    assert result.exit_code == 1
    q = QueueManager(data_dir() / "queue.json")
    assert q.items[0].status == JobStatus.FAILED.value


def test_selection_cancellation_is_a_skip_not_a_failure(cli_env, monkeypatch):
    from megabasterd_cli.core.folder_downloader import MegaFolderDownloader
    from megabasterd_cli.utils.selection import SelectionCancelled

    def cancelled(self, url, output_dir, **kwargs):
        raise SelectionCancelled()

    monkeypatch.setattr(MegaFolderDownloader, "download_folder", cancelled)
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["-q", "download", "https://mega.nz/folder/abc123#xyz", "-o", str(cli_env / "out")],
    )
    assert result.exit_code == 0, result.output


def test_download_file_reports_failure_to_controller(cli_env, monkeypatch):
    """The shared controller marks the failed row, not just the exit code."""
    from megabasterd_cli.ui.transfer_progress import TransferProgress

    def boom(self, url, output_dir, **kwargs):
        raise TransferError(message="nope")

    monkeypatch.setattr(MegaDownloader, "download_link", boom)
    tp = TransferProgress(title="t", quiet=True)
    ok = download_cmd_module._download_file(MegaDownloader(api=None), FILE_URL, cli_env, tp)
    assert ok is False
    assert list(tp.statuses().values()) == ["failed"]
