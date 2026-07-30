"""Every login path must use the session cache, or 2FA is asked every time.

Reported, verbatim: "I entered the 2FA at login, why does it want it again?"

Two paths threw the session away:

* `account add --verify` logged in - answering a 2FA challenge to do it, which
  is the one moment the user has PROVEN they hold the account - and then called
  `logout()` in its `finally`, invalidating that session server-side.
* `upload` had its own `_login_client` that never looked at the cache and never
  wrote to it, so even a saved session would not have been used.

Between them, every command demanded a fresh code. The helpers now live in
`core.session_store` and all three paths (cloud, upload, account add) share
them; a copy per command is what let two of the three skip it.
"""

from __future__ import annotations

import inspect

import pytest
from click.testing import CliRunner

from megabasterd_cli.accounts.manager import AccountManager
from megabasterd_cli.cli import cli
from megabasterd_cli.config import accounts_file
from megabasterd_cli.core.auth import MegaSession
from megabasterd_cli.core.client import MegaClient
from megabasterd_cli.core.session_store import session_path

EMAIL = "someone@example.invalid"
PASSPHRASE = "vault-pp"


class _StubApi:
    def __init__(self, requests=None):
        self.requests = requests if requests is not None else []
        self.sid: str | None = None
        self.closed = False

    def set_session(self, sid):
        self.sid = sid

    def clear_session(self):
        self.sid = None

    def request(self, payload, **kwargs):
        self.requests.append(payload)
        return {}

    def close(self):
        self.closed = True

    def clone(self):
        return self


# ---------------------------------------------------------------------------
# one implementation, three callers
# ---------------------------------------------------------------------------


def test_the_cloud_helpers_are_the_shared_ones():
    from megabasterd_cli.commands import cloud_cmd
    from megabasterd_cli.core import session_store

    assert cloud_cmd._restore_session is session_store.restore_session
    assert cloud_cmd._remember_session is session_store.remember_session


@pytest.mark.parametrize("module_name", ["upload_cmd", "account_cmd"])
def test_the_other_login_paths_reach_the_cache(module_name):
    """A login that ignores the cache re-authenticates, and re-prompts 2FA."""
    import importlib

    module = importlib.import_module(f"megabasterd_cli.commands.{module_name}")
    source = inspect.getsource(module)
    assert "remember_session" in source, f"{module_name} never stores a session"


def test_upload_tries_the_cache_before_logging_in():
    from megabasterd_cli.commands import upload_cmd

    source = inspect.getsource(upload_cmd.upload.callback)
    restore_at = source.index("restore_session(")
    login_at = source.index("client.login(")
    assert restore_at < login_at, "upload logs in before consulting the cache"


# ---------------------------------------------------------------------------
# account add keeps what it authenticated
# ---------------------------------------------------------------------------


def _add(monkeypatch, *, fail: bool = False):
    """Drive `account add --verify` with a stubbed login."""

    def fake_login(self, email, password, mfa_code=None, mfa_prompt=None):
        if fail:
            from megabasterd_cli.core.errors import MegaError

            raise MegaError(message="bad credentials")
        self.session = MegaSession(sid="fresh-sid", master_key=b"\x00" * 16, email=email)
        return self.session

    monkeypatch.setattr(MegaClient, "login", fake_login)
    monkeypatch.setattr(
        "megabasterd_cli.commands.account_cmd.api_for", lambda cfg, **kw: _StubApi()
    )
    monkeypatch.setattr("megabasterd_cli.commands.account_cmd.confirmed", lambda *a, **kw: False)
    return CliRunner().invoke(
        cli,
        [
            "-q",
            "account",
            "add",
            EMAIL,
            "--password",
            "pw",
            "--vault-passphrase",
            PASSPHRASE,
        ],
    )


def test_a_verified_add_keeps_the_session_it_authenticated(monkeypatch):
    """The exact complaint: the 2FA answered here bought nothing."""
    result = _add(monkeypatch)

    assert result.exit_code == 0, result.output
    assert session_path(
        EMAIL
    ).is_file(), "the session proven by this login - 2FA included - was thrown away"


def test_the_kept_session_opens_with_the_vault_passphrase(monkeypatch):
    """Cached under the passphrase the user already typed, so reuse is free."""
    _add(monkeypatch)

    client = MegaClient(api=_StubApi())
    session = client.load_session(session_path(EMAIL), PASSPHRASE)
    assert session is not None and session.sid == "fresh-sid"


def test_a_failed_verification_stores_nothing(monkeypatch):
    result = _add(monkeypatch, fail=True)

    assert not session_path(EMAIL).is_file()
    assert result.exit_code == 0, result.output  # declined the "add anyway?" prompt


def test_a_verified_add_does_not_end_the_session_server_side(monkeypatch):
    """`close()`, not `logout()`: `{"a":"sml"}` would kill what was just cached."""
    seen: list[dict] = []
    monkeypatch.setattr(
        "megabasterd_cli.commands.account_cmd.api_for", lambda cfg, **kw: _StubApi(seen)
    )

    def fake_login(self, email, password, mfa_code=None, mfa_prompt=None):
        self.session = MegaSession(sid="fresh-sid", master_key=b"\x00" * 16, email=email)
        return self.session

    monkeypatch.setattr(MegaClient, "login", fake_login)
    CliRunner().invoke(
        cli,
        ["-q", "account", "add", EMAIL, "--password", "pw", "--vault-passphrase", PASSPHRASE],
    )

    assert {"a": "sml"} not in seen, "the add invalidated the session it just cached"


def test_the_stored_account_is_still_written(monkeypatch):
    """Caching must not have displaced the actual job of the command."""
    _add(monkeypatch)

    mgr = AccountManager(accounts_file())
    assert [a.email for a in mgr.list_accounts()] == [EMAIL]


# ---------------------------------------------------------------------------
# no command may end a session it did not create
# ---------------------------------------------------------------------------

# `account add` on a FAILED verify, and `account logout` itself. Those two are
# the only legitimate `logout()` calls: nothing is cached in the first case, and
# ending the session is the whole job in the second.
_LOGOUT_ALLOWED = {"account_cmd"}


@pytest.mark.parametrize(
    "module_name",
    ["cloud_cmd", "upload_cmd", "queue_cmd", "share_cmd", "download_cmd", "stream_cmd"],
)
def test_no_command_module_ends_a_session_it_did_not_create(module_name):
    """`logout()` sends `{"a":"sml"}` - it invalidates the CACHED session.

    Six modules had it in their teardown, so whichever command ran last left
    the next one to re-authenticate and re-prompt for 2FA. Releasing the
    transport is `close()`; ending the session is `mb account logout`.
    """
    import importlib

    try:
        module = importlib.import_module(f"megabasterd_cli.commands.{module_name}")
    except ModuleNotFoundError:
        pytest.skip(f"{module_name} does not exist")
    source = inspect.getsource(module)
    assert ".logout()" not in source, f"{module_name} invalidates a cached session; use close()"


@pytest.mark.parametrize("module_name", ["cloud_cmd", "upload_cmd", "queue_cmd", "account_cmd"])
def test_every_module_that_logs_in_also_consults_the_cache(module_name):
    """A login path that skips the cache re-prompts 2FA on every run.

    Four modules log in. Two of them (upload, queue) had their own login that
    never touched the cache, and `account info`/`refresh-all` logged in fresh
    per account - so `refresh-all` asked for one code per stored account.
    """
    import importlib

    source = inspect.getsource(importlib.import_module(f"megabasterd_cli.commands.{module_name}"))
    assert "restore_session" in source, f"{module_name} logs in without checking the cache"
    assert "remember_session" in source, f"{module_name} logs in without storing the result"


def test_re_adding_an_existing_account_still_caches_the_session(monkeypatch):
    """The 2FA code must not be spent for nothing.

    Reported live: the user answered a 2FA challenge, verification succeeded,
    and then `add_account` raised "Account already exists" - so the
    `remember_session` call that sat after it never ran and the proven session
    was discarded. Caching is correct either way: the login happened, and the
    passphrase is known to open the vault by the time we get here.
    """
    from megabasterd_cli.accounts.manager import AccountManager

    mgr = AccountManager(accounts_file())
    mgr.unlock(PASSPHRASE)
    mgr.add_account(EMAIL, "pw", make_default=True)
    assert not session_path(EMAIL).is_file()

    result = _add(monkeypatch)

    assert "already exists" in result.output, result.output
    assert session_path(EMAIL).is_file(), "the verified session was thrown away"


def test_a_duplicate_add_exits_non_zero(monkeypatch):
    """`print_error` then falling through reported success in the launcher."""
    from megabasterd_cli.accounts.manager import AccountManager

    mgr = AccountManager(accounts_file())
    mgr.unlock(PASSPHRASE)
    mgr.add_account(EMAIL, "pw", make_default=True)

    result = _add(monkeypatch)

    assert result.exit_code != 0, result.output
