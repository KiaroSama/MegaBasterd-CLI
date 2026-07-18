"""MF8: API/HTTP sessions are closed on failed login (upload + queue)."""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from megabasterd_cli.cli import cli
from megabasterd_cli.core.api import MegaAPIClient
from megabasterd_cli.core.client import MegaClient, MegaSession
from megabasterd_cli.core.errors import AuthError
from megabasterd_cli.core.uploader import UploadResult


@pytest.fixture()
def account_env(tmp_path, monkeypatch):
    monkeypatch.setenv("MEGABASTERD_USER_DIR", str(tmp_path / "user"))
    monkeypatch.setenv("MEGABASTERD_LOG_DIR", str(tmp_path / "logs"))
    from megabasterd_cli.accounts.manager import AccountManager
    from megabasterd_cli.config import accounts_file

    mgr = AccountManager(accounts_file())
    mgr.unlock("pp")
    mgr.add_account("acc@example.com", "secret", make_default=True)
    return tmp_path


def _count_closes(monkeypatch) -> list[int]:
    closed: list[int] = []
    original = MegaAPIClient.close

    def counting_close(self):
        closed.append(id(self))
        original(self)

    monkeypatch.setattr(MegaAPIClient, "close", counting_close)
    return closed


def test_failed_upload_login_closes_api(account_env, monkeypatch, tmp_path):
    closed = _count_closes(monkeypatch)

    def failing_login(self, email, password, mfa_code=None, mfa_prompt=None):
        raise AuthError(message="bad password")

    monkeypatch.setattr(MegaClient, "login", failing_login)
    src = tmp_path / "up.bin"
    src.write_bytes(b"data")
    result = CliRunner().invoke(
        cli, ["-q", "upload", str(src), "--vault-passphrase", "pp", "-a", "acc@example.com"]
    )
    assert result.exit_code != 0
    assert len(closed) >= 1, "the API of a failed-login client must be closed"


def test_failed_queue_login_closes_api(account_env, monkeypatch):
    closed = _count_closes(monkeypatch)

    def failing_login(self, email, password, mfa_code=None, mfa_prompt=None):
        raise AuthError(message="bad password")

    monkeypatch.setattr(MegaClient, "login", failing_login)
    runner = CliRunner()
    runner.invoke(cli, ["-q", "queue", "add-upload", _make(account_env), "-a", "acc@example.com"])
    result = runner.invoke(cli, ["-q", "queue", "run", "--vault-passphrase", "pp"])
    assert result.exit_code != 0
    assert len(closed) >= 1, "queue failed-login API must be closed before caching"


def test_successful_upload_client_closes_once(account_env, monkeypatch, tmp_path):
    closed = _count_closes(monkeypatch)

    def ok_login(self, email, password, mfa_code=None, mfa_prompt=None):
        self.session = MegaSession(sid="sid", master_key=b"\x00" * 16, email=email)
        return self.session

    from megabasterd_cli.core.uploader import MegaUploader

    monkeypatch.setattr(MegaClient, "login", ok_login)
    monkeypatch.setattr(MegaClient, "logout", lambda self: None)
    monkeypatch.setattr(
        MegaUploader,
        "upload_file",
        lambda self, source, **kw: UploadResult(
            file_handle="H", name=source.name, size=4, elapsed_seconds=0.1
        ),
    )
    src = tmp_path / "up.bin"
    src.write_bytes(b"data")
    result = CliRunner().invoke(
        cli, ["-q", "upload", str(src), "--vault-passphrase", "pp", "-a", "acc@example.com"]
    )
    assert result.exit_code == 0, result.output
    # Base client + one per-transfer worker are both closed; each API id once.
    assert len(closed) == len(set(closed)), "no API is closed twice"
    assert len(closed) >= 2


def _make(tmp_path):
    p = tmp_path / "queued.bin"
    p.write_bytes(b"data")
    return str(p)
