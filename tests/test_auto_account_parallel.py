"""MF3: real parallel --auto-account for flat files."""

from __future__ import annotations

import threading
import time

import pytest
from click.testing import CliRunner

from megabasterd_cli.cli import cli
from megabasterd_cli.core.api import MegaAPIClient
from megabasterd_cli.core.client import MegaClient, MegaSession
from megabasterd_cli.core.errors import QuotaError
from megabasterd_cli.core.uploader import MegaUploader, UploadResult

GB = 1024**3


@pytest.fixture()
def cli_env(tmp_path, monkeypatch):
    monkeypatch.setenv("MEGABASTERD_USER_DIR", str(tmp_path / "user"))
    monkeypatch.setenv("MEGABASTERD_LOG_DIR", str(tmp_path / "logs"))

    from megabasterd_cli.accounts.manager import AccountManager
    from megabasterd_cli.config import accounts_file

    mgr = AccountManager(accounts_file())
    mgr.unlock("pp")
    mgr.add_account("a@example.com", "pw-a", make_default=True)
    mgr.add_account("b@example.com", "pw-b")
    mgr.update_quota("a@example.com", used=0, total=100 * GB)
    mgr.update_quota("b@example.com", used=0, total=100 * GB)

    logins: list[str] = []
    login_lock = threading.Lock()

    def fake_login(self, email, password, mfa_code=None, mfa_prompt=None):
        with login_lock:
            logins.append(email)
        self.session = MegaSession(sid=f"sid-{email}", master_key=b"\x00" * 16, email=email)
        return self.session

    monkeypatch.setattr(MegaClient, "login", fake_login)
    monkeypatch.setattr(MegaClient, "logout", lambda self: None)
    monkeypatch.setattr(
        MegaClient, "get_quota", lambda self: {"cstrg": 100 * GB, "mstrg": 100 * GB}
    )
    return tmp_path, logins


def _files(tmp_path, n):
    paths = []
    for i in range(n):
        p = tmp_path / f"f{i}.bin"
        p.write_bytes(b"x" * 64)
        paths.append(str(p))
    return paths


def test_auto_account_parallel_runs_concurrently(cli_env, monkeypatch):
    tmp_path, _logins = cli_env
    active = {"cur": 0, "max": 0}
    lock = threading.Lock()

    def slow_upload(self, source, **kwargs):
        with lock:
            active["cur"] += 1
            active["max"] = max(active["max"], active["cur"])
        time.sleep(0.3)
        with lock:
            active["cur"] -= 1
        return UploadResult(file_handle="H", name=source.name, size=64, elapsed_seconds=0.3)

    monkeypatch.setattr(MegaUploader, "upload_file", slow_upload)
    files = _files(tmp_path, 4)
    result = CliRunner().invoke(
        cli, ["-q", "upload", *files, "--auto-account", "-P", "3", "--vault-passphrase", "pp"]
    )
    assert result.exit_code == 0, result.output
    assert active["max"] >= 2, "auto-account -P3 must upload files concurrently, not sequentially"


def test_auto_account_parallel_uses_isolated_api_objects(cli_env, monkeypatch):
    tmp_path, _logins = cli_env
    # Keep OBJECT references (not id()s): closed short-lived clients would be
    # GC'd and their memory address reused, making id()-based identity flaky.
    apis: list = []
    sessions: list = []
    lock = threading.Lock()

    def record_upload(self, source, **kwargs):
        with lock:
            apis.append(self.client.api)
            sessions.append(self.client.api._session)
        return UploadResult(file_handle="H", name=source.name, size=64, elapsed_seconds=0.1)

    monkeypatch.setattr(MegaUploader, "upload_file", record_upload)
    files = _files(tmp_path, 4)
    result = CliRunner().invoke(
        cli, ["-q", "upload", *files, "--auto-account", "-P", "3", "--vault-passphrase", "pp"]
    )
    assert result.exit_code == 0, result.output
    # Each of the 4 transfers gets its own API client + HTTP session object.
    assert len({id(a) for a in apis}) == 4
    assert len({id(s) for s in sessions}) == 4


def test_auto_account_parallel_does_not_reprompt_mfa(cli_env, monkeypatch):
    tmp_path, logins = cli_env

    monkeypatch.setattr(
        MegaUploader,
        "upload_file",
        lambda self, source, **kw: UploadResult(
            file_handle="H", name=source.name, size=64, elapsed_seconds=0.1
        ),
    )
    files = _files(tmp_path, 6)
    result = CliRunner().invoke(
        cli, ["-q", "upload", *files, "--auto-account", "-P", "4", "--vault-passphrase", "pp"]
    )
    assert result.exit_code == 0, result.output
    # Each account logs in at most once despite many parallel files.
    assert sorted(logins) == ["a@example.com"] or len(set(logins)) <= 2
    assert len(logins) == len(set(logins)), "no account logs in twice (no repeated MFA)"


def test_auto_account_parallel_closes_all_temporary_clients(cli_env, monkeypatch):
    tmp_path, _logins = cli_env
    closed: list[int] = []
    original_close = MegaAPIClient.close

    def counting_close(self):
        closed.append(id(self))
        original_close(self)

    monkeypatch.setattr(MegaAPIClient, "close", counting_close)
    monkeypatch.setattr(
        MegaUploader,
        "upload_file",
        lambda self, source, **kw: UploadResult(
            file_handle="H", name=source.name, size=64, elapsed_seconds=0.1
        ),
    )
    files = _files(tmp_path, 3)
    result = CliRunner().invoke(
        cli, ["-q", "upload", *files, "--auto-account", "-P", "2", "--vault-passphrase", "pp"]
    )
    assert result.exit_code == 0, result.output
    # 3 per-transfer worker clients + base account client(s), all closed.
    assert len(closed) >= 4


def test_auto_account_parallel_reroutes_after_quota_error(cli_env, monkeypatch):
    tmp_path, _logins = cli_env
    # Give A almost no room so its file overflows to B under concurrency.
    from megabasterd_cli.accounts.manager import AccountManager
    from megabasterd_cli.config import accounts_file

    mgr = AccountManager(accounts_file())
    mgr.unlock("pp")

    attempts: list[str] = []
    lock = threading.Lock()

    def flaky_upload(self, source, **kwargs):
        email = self.client.session.email
        with lock:
            attempts.append(email)
        if email == "a@example.com":
            raise QuotaError(message="EOVERQUOTA")
        return UploadResult(file_handle="H", name=source.name, size=64, elapsed_seconds=0.1)

    # Live quota for A comes back full so re-planning avoids it thereafter.
    monkeypatch.setattr(
        MegaClient,
        "get_quota",
        lambda self: (
            {"cstrg": 100 * GB, "mstrg": 100 * GB}
            if self.session and self.session.email == "a@example.com"
            else {"cstrg": 0, "mstrg": 100 * GB}
        ),
    )
    monkeypatch.setattr(MegaUploader, "upload_file", flaky_upload)
    files = _files(tmp_path, 3)
    result = CliRunner().invoke(
        cli, ["-q", "upload", *files, "--auto-account", "-P", "3", "--vault-passphrase", "pp"]
    )
    assert result.exit_code == 0, result.output
    # Every file ultimately succeeded on B; A was attempted but bounded.
    assert attempts.count("a@example.com") <= 3
    assert "b@example.com" in attempts
