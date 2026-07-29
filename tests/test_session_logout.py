"""A cached session must be endable, and must survive until it is ended.

Three defects that only make sense together:

* `login_client` caches an encrypted session so later commands skip the login
  (and the 2FA prompt), but every cloud command then called `client.logout()`
  in its `finally` - and `logout()` sends `{"a":"sml"}`, which invalidates the
  session server-side. The cache was written and killed in the same run, so the
  reuse path never once reused anything. Nothing failed visibly, because the
  fallback to a full login is correct.
* There was no way to end a session on purpose. `mb account logout` did not
  exist, so a cached session lived until MEGA expired it.
* `mb account remove` deleted the credential and left the cached session file,
  i.e. a token MEGA still honours for an account the user was just told was
  gone - and one no command could reach any more to log out.
"""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from megabasterd_cli.accounts.manager import AccountManager
from megabasterd_cli.cli import cli
from megabasterd_cli.config import accounts_file, session_dir
from megabasterd_cli.core.auth import MegaSession
from megabasterd_cli.core.client import MegaClient
from megabasterd_cli.core.session_store import forget_session, session_path

EMAIL = "someone@example.invalid"
PASSPHRASE = "vault-pp"


@pytest.fixture()
def stored_account(monkeypatch):
    """A real vault with one account, plus a real cached session file."""
    mgr = AccountManager(accounts_file())
    mgr.unlock(PASSPHRASE)
    mgr.add_account(EMAIL, "account-pw", make_default=True)

    client = MegaClient(api=_StubApi())
    client.session = MegaSession(sid="cached-sid", master_key=b"\x00" * 16, email=EMAIL)
    session_dir().mkdir(parents=True, exist_ok=True)
    client.save_session(session_path(EMAIL), PASSPHRASE)
    assert session_path(EMAIL).is_file()
    return EMAIL


class _StubApi:
    """Records every request; enough surface for save/load and logout."""

    def __init__(self):
        self.requests: list[dict] = []
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
# the path helper
# ---------------------------------------------------------------------------


def test_the_cache_path_is_owned_by_one_module():
    """`cloud_cmd` must not keep a second copy of the hashing.

    Two implementations of the filename means the writer and the eraser can
    disagree, leaving a live token in a file nothing looks for.
    """
    from megabasterd_cli.commands import cloud_cmd

    assert cloud_cmd._session_path(EMAIL) == session_path(EMAIL)


def test_forget_session_reports_whether_there_was_one():
    assert forget_session("nobody@example.invalid") is False


# ---------------------------------------------------------------------------
# `mb account logout`
# ---------------------------------------------------------------------------


def _logout(*args):
    return CliRunner().invoke(cli, ["-q", "account", "logout", *args])


def test_logout_invalidates_the_session_server_side_and_drops_the_file(stored_account, monkeypatch):
    """Both halves. The file alone leaves a token MEGA still honours; the
    remote call alone leaves a dead file the next run has to probe."""
    seen: list[dict] = []

    def fake_api(cfg, **kwargs):
        api = _StubApi()
        api.requests = seen
        return api

    monkeypatch.setattr("megabasterd_cli.commands.account_cmd.api_for", fake_api)

    result = _logout(EMAIL, "--vault-passphrase", PASSPHRASE)

    assert result.exit_code == 0, result.output
    assert {"a": "sml"} in seen, "the session was never invalidated server-side"
    assert not session_path(EMAIL).is_file(), "the cached session file survived"


def test_logout_with_no_cached_session_says_so_and_succeeds(monkeypatch):
    mgr = AccountManager(accounts_file())
    mgr.unlock(PASSPHRASE)
    mgr.add_account(EMAIL, "pw", make_default=True)

    result = _logout(EMAIL, "--vault-passphrase", PASSPHRASE)

    assert result.exit_code == 0, result.output
    assert "No stored session" in result.output


def test_logout_still_clears_the_file_when_the_remote_call_fails(stored_account, monkeypatch):
    """A server that will not cooperate must not leave the token cached."""
    from megabasterd_cli.core.errors import MegaError

    class _Failing(_StubApi):
        def request(self, payload, **kwargs):
            raise MegaError(message="network is down")

    monkeypatch.setattr(
        "megabasterd_cli.commands.account_cmd.api_for", lambda cfg, **kw: _Failing()
    )

    result = _logout(EMAIL, "--vault-passphrase", PASSPHRASE)

    assert result.exit_code == 0, result.output
    assert not session_path(EMAIL).is_file()


def test_logout_with_a_wrong_passphrase_removes_the_file_and_says_it_could_not_read_it(
    stored_account, monkeypatch
):
    """An unreadable token cannot log itself out - do not claim it did."""
    seen: list[dict] = []
    monkeypatch.setattr(
        "megabasterd_cli.commands.account_cmd.api_for",
        lambda cfg, **kw: type("A", (_StubApi,), {})(),
    )

    result = _logout(EMAIL, "--vault-passphrase", "not-the-passphrase")

    assert result.exit_code == 0, result.output
    assert "could not be read" in result.output
    assert not session_path(EMAIL).is_file()
    assert {"a": "sml"} not in seen


# ---------------------------------------------------------------------------
# `mb account remove`
# ---------------------------------------------------------------------------


def test_removing_an_account_also_drops_its_cached_session(stored_account, monkeypatch):
    monkeypatch.setattr("megabasterd_cli.commands.account_cmd.confirm", lambda *a, **kw: True)

    result = CliRunner().invoke(cli, ["-q", "account", "remove", EMAIL])

    assert result.exit_code == 0, result.output
    assert not session_path(
        EMAIL
    ).is_file(), "the credential was removed but the session token was left behind"
    doc = json.loads(accounts_file().read_text(encoding="utf-8"))
    assert doc["accounts"] == []


# ---------------------------------------------------------------------------
# the cache has to survive a normal command
# ---------------------------------------------------------------------------


def test_a_cloud_command_does_not_invalidate_the_session_it_cached():
    """`close()`, not `logout()`.

    This is what made the reuse feature dead on arrival: the session was saved
    and then killed in the same run, so every later command re-authenticated.
    Asserted on the source because the alternative is a live MEGA account.
    """
    import inspect

    from megabasterd_cli.commands import cloud_cmd

    source = inspect.getsource(cloud_cmd)
    assert (
        "client.logout()" not in source
    ), "a cloud command ends the session it just cached; use close() to keep it"
    assert "client.close()" in source
