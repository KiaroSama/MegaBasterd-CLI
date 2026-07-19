"""Machine-readable `--json` mode (Mandatory Fix 9).

In machine mode, stdout must contain ONLY structured JSONL records; human
output goes to stderr; records never expose keys/passwords/SIDs.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from megabasterd_cli.cli import cli
from megabasterd_cli.core.downloader import DownloadResult, MegaDownloader
from megabasterd_cli.core.errors import TransferError
from megabasterd_cli.core.uploader import MegaUploader, UploadResult

FILE_URL = "https://mega.nz/file/abc123#supersecretkey"


def _runner() -> CliRunner:
    """CliRunner with stdout/stderr separated across click versions.

    click < 8.2 mixes stderr into stdout by default, which would fold the
    human progress lines into the JSONL stream; `mix_stderr=False` restores
    the real-terminal separation. click >= 8.2 removed the parameter (streams
    are always separate).

    Kept after the Python 3.9 drop: `click>=8.1.0` still permits an 8.1
    resolution, so the fallback is about the click version, not the
    interpreter it happened to ship with.
    """
    try:
        return CliRunner(mix_stderr=False)
    except TypeError:
        return CliRunner()


@pytest.fixture()
def cli_env(tmp_path, monkeypatch):
    monkeypatch.setenv("MEGABASTERD_USER_DIR", str(tmp_path / "user"))
    monkeypatch.setenv("MEGABASTERD_LOG_DIR", str(tmp_path / "logs"))
    return tmp_path


def _records(stdout: str) -> list[dict]:
    lines = [line for line in stdout.splitlines() if line.strip()]
    records = []
    for line in lines:
        records.append(json.loads(line))  # every stdout line must be JSON
    return records


def test_download_json_success_record(cli_env, monkeypatch):
    def ok(self, url, output_dir, **kwargs):
        path = Path(output_dir) / "ok.bin"
        path.write_bytes(b"xy")
        return DownloadResult(path=path, size=2, elapsed_seconds=1.25, integrity_ok=True)

    monkeypatch.setattr(MegaDownloader, "download_link", ok)
    runner = _runner()
    result = runner.invoke(cli, ["download", "--json", FILE_URL, "-o", str(cli_env / "out")])
    assert result.exit_code == 0, result.output
    records = _records(result.stdout)
    assert len(records) == 1
    record = records[0]
    assert record["event"] == "result"
    assert record["type"] == "download"
    assert record["status"] == "success"
    assert record["name"] == "ok.bin"
    assert record["size"] == 2
    assert record["integrity_ok"] is True
    assert "supersecretkey" not in result.stdout, "link keys must never reach stdout"


def test_download_json_failure_record_and_exit_code(cli_env, monkeypatch):
    def boom(self, url, output_dir, **kwargs):
        raise TransferError(message="simulated failure")

    monkeypatch.setattr(MegaDownloader, "download_link", boom)
    runner = _runner()
    result = runner.invoke(cli, ["download", "--json", FILE_URL, "-o", str(cli_env / "out")])
    assert result.exit_code == 1
    records = _records(result.stdout)
    assert any(r["status"] == "failed" for r in records)
    failed = next(r for r in records if r["status"] == "failed")
    assert failed["source"].endswith("#<key>"), "sources must be redacted"
    assert "supersecretkey" not in result.stdout


def test_download_json_human_messages_go_to_stderr(cli_env, monkeypatch):
    def ok(self, url, output_dir, **kwargs):
        path = Path(output_dir) / "ok.bin"
        path.write_bytes(b"x")
        return DownloadResult(path=path, size=1, elapsed_seconds=0.1, integrity_ok=True)

    monkeypatch.setattr(MegaDownloader, "download_link", ok)
    runner = _runner()
    result = runner.invoke(cli, ["download", "--json", FILE_URL, "-o", str(cli_env / "out")])
    assert result.exit_code == 0
    # stdout is pure JSONL (parse would fail otherwise); the human success
    # line ("OK ...") must have gone to stderr instead.
    _records(result.stdout)
    assert "OK" not in result.stdout


def test_upload_json_success_record_with_share_link(cli_env, monkeypatch, tmp_path):
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
    monkeypatch.setattr(
        MegaClient, "export_link", lambda self, handle, password=None: "https://mega.nz/file/H#K"
    )

    def ok(self, source, **kwargs):
        return UploadResult(file_handle="HANDLE", name=source.name, size=4, elapsed_seconds=0.5)

    monkeypatch.setattr(MegaUploader, "upload_file", ok)
    src = tmp_path / "up.bin"
    src.write_bytes(b"data")
    runner = _runner()
    result = runner.invoke(
        cli,
        [
            "upload",
            "--json",
            str(src),
            "--share",
            "--vault-passphrase",
            "pp",
            "-a",
            "acc@example.com",
        ],
    )
    assert result.exit_code == 0, result.output
    records = _records(result.stdout)
    record = next(r for r in records if r["event"] == "result")
    assert record["type"] == "upload"
    assert record["status"] == "success"
    assert record["handle"] == "HANDLE"
    assert record["account"] == "acc@example.com"
    assert record["share_link"] == "https://mega.nz/file/H#K"
    assert "vault_passphrase" not in record, "no passphrase field may exist"
    assert "secret" not in result.stdout, "account passwords must never reach stdout"


def test_upload_json_failure_record(cli_env, monkeypatch, tmp_path):
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

    def boom(self, source, **kwargs):
        raise TransferError(message="simulated upload failure")

    monkeypatch.setattr(MegaUploader, "upload_file", boom)
    src = tmp_path / "up.bin"
    src.write_bytes(b"data")
    runner = _runner()
    result = runner.invoke(
        cli,
        ["upload", "--json", str(src), "--vault-passphrase", "pp", "-a", "acc@example.com"],
    )
    assert result.exit_code == 1
    records = _records(result.stdout)
    assert any(r["status"] == "failed" and r["type"] == "upload" for r in records)


def test_human_mode_remains_backward_compatible(cli_env, monkeypatch):
    def ok(self, url, output_dir, **kwargs):
        path = Path(output_dir) / "ok.bin"
        path.write_bytes(b"x")
        return DownloadResult(path=path, size=1, elapsed_seconds=0.1, integrity_ok=True)

    monkeypatch.setattr(MegaDownloader, "download_link", ok)
    runner = _runner()
    result = runner.invoke(cli, ["-q", "download", FILE_URL, "-o", str(cli_env / "out")])
    assert result.exit_code == 0
    # Human mode: no JSONL records on stdout.
    for line in result.output.splitlines():
        if line.strip().startswith("{"):
            raise AssertionError("human mode must not emit JSON records")
