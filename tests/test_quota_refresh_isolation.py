"""MF4: quota refresh after a QuotaError runs on an isolated short-lived client.

Parallel `--auto-account` uploads already get isolated per-transfer clients,
but the post-QuotaError quota refresh used to call `get_quota()` on the SHARED
cached base client. Two files failing on one account then drove one mutable
API/session/request-sequence concurrently.
"""

from __future__ import annotations

import threading

import pytest
from click.testing import CliRunner

from megabasterd_cli.core.api import MegaAPIClient
from megabasterd_cli.core.client import MegaClient, MegaSession
from megabasterd_cli.core.errors import MegaError, QuotaError
from megabasterd_cli.core.uploader import MegaUploader, UploadResult
from megabasterd_cli.upload_support import QuotaLedger
from tests.upload_helpers import files as _files

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
    return tmp_path, logins


def _quota_error_on_a():
    def flaky_upload(self, source, **kwargs):
        if self.client.session.email == "a@example.com":
            raise QuotaError(message="EOVERQUOTA")
        return UploadResult(file_handle="H", name=source.name, size=64, elapsed_seconds=0.1)

    return flaky_upload


def test_concurrent_quota_refreshes_never_share_one_api(cli_env, monkeypatch):
    """Two simultaneous QuotaErrors on one account must not overlap on a
    single API object, and must not reuse the cached base client's API."""
    tmp_path, _logins = cli_env
    refresh_apis: list = []
    overlaps: list[str] = []
    in_flight: set[int] = set()
    lock = threading.Lock()

    def slow_quota(self):
        api_id = id(self.api)
        with lock:
            refresh_apis.append(self.api)  # hold a reference: id() reuse is real
            if api_id in in_flight:
                overlaps.append("two refreshes shared one API object")
            in_flight.add(api_id)
        threading.Event().wait(0.2)  # widen the overlap window
        with lock:
            in_flight.discard(api_id)
        if self.session and self.session.email == "a@example.com":
            return {"cstrg": 100 * GB, "mstrg": 100 * GB}  # A is full
        return {"cstrg": 0, "mstrg": 100 * GB}

    monkeypatch.setattr(MegaClient, "get_quota", slow_quota)
    monkeypatch.setattr(MegaUploader, "upload_file", _quota_error_on_a())

    from megabasterd_cli.cli import cli

    files = _files(tmp_path, 4)
    run = CliRunner().invoke(
        cli, ["-q", "upload", *files, "--auto-account", "-P", "4", "--vault-passphrase", "pp"]
    )
    assert run.exit_code == 0, run.output
    assert not overlaps, overlaps
    assert len(refresh_apis) >= 2, "the test must actually exercise concurrent refreshes"
    # Every refresh ran on its own API object.
    assert len({id(a) for a in refresh_apis}) == len(refresh_apis)


def test_refresh_clients_are_closed(cli_env, monkeypatch):
    tmp_path, _logins = cli_env
    closed: list = []
    original_close = MegaAPIClient.close

    def counting_close(self):
        closed.append(self)
        original_close(self)

    monkeypatch.setattr(MegaAPIClient, "close", counting_close)
    monkeypatch.setattr(
        MegaClient,
        "get_quota",
        lambda self: (
            {"cstrg": 100 * GB, "mstrg": 100 * GB}
            if self.session and self.session.email == "a@example.com"
            else {"cstrg": 0, "mstrg": 100 * GB}
        ),
    )
    monkeypatch.setattr(MegaUploader, "upload_file", _quota_error_on_a())

    from megabasterd_cli.cli import cli

    files = _files(tmp_path, 2)
    run = CliRunner().invoke(
        cli, ["-q", "upload", *files, "--auto-account", "-P", "2", "--vault-passphrase", "pp"]
    )
    assert run.exit_code == 0, run.output
    # Worker clients + refresh clients + base clients: all closed exactly once.
    assert len(closed) == len({id(c) for c in closed}), "no client is closed twice"
    assert len(closed) >= 4


def test_quota_refresh_does_not_reprompt_login(cli_env, monkeypatch):
    tmp_path, logins = cli_env
    monkeypatch.setattr(
        MegaClient,
        "get_quota",
        lambda self: (
            {"cstrg": 100 * GB, "mstrg": 100 * GB}
            if self.session and self.session.email == "a@example.com"
            else {"cstrg": 0, "mstrg": 100 * GB}
        ),
    )
    monkeypatch.setattr(MegaUploader, "upload_file", _quota_error_on_a())

    from megabasterd_cli.cli import cli

    files = _files(tmp_path, 3)
    run = CliRunner().invoke(
        cli, ["-q", "upload", *files, "--auto-account", "-P", "3", "--vault-passphrase", "pp"]
    )
    assert run.exit_code == 0, run.output
    assert len(logins) == len(set(logins)), "quota refresh must not trigger a second login/MFA"


def test_failed_refresh_marks_the_account_unusable(cli_env, monkeypatch):
    tmp_path, _logins = cli_env

    def failing_quota(self):
        if self.session and self.session.email == "a@example.com":
            raise MegaError(message="quota lookup failed")
        return {"cstrg": 0, "mstrg": 100 * GB}

    monkeypatch.setattr(MegaClient, "get_quota", failing_quota)
    monkeypatch.setattr(MegaUploader, "upload_file", _quota_error_on_a())

    from megabasterd_cli.cli import cli

    files = _files(tmp_path, 3)
    run = CliRunner().invoke(
        cli, ["-q", "upload", *files, "--auto-account", "-P", "3", "--vault-passphrase", "pp"]
    )
    # A is unusable after the failed refresh; every file lands on B.
    assert run.exit_code == 0, run.output


# ---------------------------------------------------------------------------
# Ledger reconciliation invariant (unit level).
# ---------------------------------------------------------------------------


def test_reconcile_never_restores_stale_free_space():
    ledger = QuotaLedger({"a@example.com": 1000})
    assert ledger.reserve(900) == "a@example.com"
    assert ledger.free_of("a@example.com") == 100
    # A live read that does not know about the in-flight 900-byte reservation
    # must NOT hand that space back.
    ledger.reconcile_free("a@example.com", 1000)
    assert ledger.free_of("a@example.com") == 100


def test_concurrent_reconciles_do_not_increase_free_space():
    ledger = QuotaLedger({"a@example.com": 500})
    barrier = threading.Barrier(8)

    def refresh(value: int) -> None:
        barrier.wait()
        ledger.reconcile_free("a@example.com", value)

    threads = [threading.Thread(target=refresh, args=(v,)) for v in (900, 400, 900, 0) * 2]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert ledger.free_of("a@example.com") == 0


def test_failed_refresh_sets_free_space_to_zero():
    ledger = QuotaLedger({"a@example.com": 500})
    ledger.reconcile_free("a@example.com", 0)
    assert ledger.free_of("a@example.com") == 0
    assert ledger.reserve(1) is None


# ---------------------------------------------------------------------------
# Adjacent path found while re-verifying issue 10: `account refresh` /
# `refresh-all` invalidated the session but never released the HTTP session,
# leaking one connection pool per account.
# ---------------------------------------------------------------------------


def test_account_refresh_all_closes_every_http_session(cli_env, monkeypatch):
    tmp_path, _logins = cli_env
    closed: list = []
    original_close = MegaAPIClient.close

    def counting_close(self):
        closed.append(self)
        original_close(self)

    monkeypatch.setattr(MegaAPIClient, "close", counting_close)
    monkeypatch.setattr(MegaClient, "get_quota", lambda self: {"cstrg": 1, "mstrg": 100 * GB})
    monkeypatch.setattr(MegaClient, "logout", lambda self: None)

    from megabasterd_cli.cli import cli

    result = CliRunner().invoke(cli, ["-q", "account", "refresh-all", "--vault-passphrase", "pp"])
    assert result.exit_code == 0, result.output
    assert len(closed) >= 2, "each account's API session must be closed"
    assert len(closed) == len({id(c) for c in closed}), "no client closed twice"


def test_account_info_closes_the_session_even_when_quota_fails(cli_env, monkeypatch):
    tmp_path, _logins = cli_env
    closed: list = []
    original_close = MegaAPIClient.close

    def counting_close(self):
        closed.append(self)
        original_close(self)

    def failing_quota(self):
        raise MegaError(message="quota lookup failed")

    monkeypatch.setattr(MegaAPIClient, "close", counting_close)
    monkeypatch.setattr(MegaClient, "get_quota", failing_quota)
    monkeypatch.setattr(MegaClient, "logout", lambda self: None)

    from megabasterd_cli.cli import cli

    result = CliRunner().invoke(cli, ["-q", "account", "info", "--vault-passphrase", "pp"])
    assert closed, "the HTTP session must be closed on the failure path too"
    assert result.exit_code == 0
