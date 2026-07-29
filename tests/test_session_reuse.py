"""A stored session must skip the login - but only while it still works.

`save_session`/`load_session` existed and were fully implemented, with no
caller anywhere: every command logged in from scratch, re-prompting for MFA
each time. They are now wired into the shared `login_client`, keyed on the
passphrase the user already types to unlock the account vault, so reuse costs
no extra prompt.

The risk this file guards is the obvious one: a stored session goes stale when
MEGA expires it or the user logs out elsewhere, and handing a dead session to a
command would fail later, further from the cause. It is proven with one
authenticated call before it is trusted.
"""

from __future__ import annotations

import pytest

from megabasterd_cli.commands import cloud_cmd
from megabasterd_cli.core.auth import MegaSession

PASSPHRASE = "vault-passphrase"
ACCOUNT = "user@example.com"


class _Api:
    def __init__(self, alive: bool = True):
        self.alive = alive
        self.session_set_to: str | None = None
        self.requests: list[dict] = []

    def set_session(self, sid):
        self.session_set_to = sid

    def request(self, payload, extra_params=None):
        self.requests.append(payload)
        if not self.alive:
            raise RuntimeError("session expired")
        return {"u": "handle"}

    def close(self):
        pass


class _Client:
    """Only what `_restore_session` / `_remember_session` touch."""

    def __init__(self, api):
        self.api = api
        self.session: MegaSession | None = None
        self._cache_cleared = False

    def invalidate_cache(self):
        self._cache_cleared = True

    def load_session(self, path, passphrase):
        return cloud_cmd.MegaClient.load_session(path, passphrase)

    def save_session(self, path, passphrase):
        return cloud_cmd.MegaClient.save_session(self, path, passphrase)


@pytest.fixture()
def data_dir(tmp_path, monkeypatch):
    monkeypatch.setattr("megabasterd_cli.config.session_dir", lambda: tmp_path / "sessions")
    return tmp_path


def _session() -> MegaSession:
    return MegaSession(
        sid="stored-sid",
        master_key=bytes(range(16)),
        rsa_private_key=None,
        user_handle="handle",
        email=ACCOUNT,
    )


def test_a_stored_session_is_reused_without_logging_in(data_dir):
    saver = _Client(_Api())
    saver.session = _session()
    cloud_cmd._remember_session(saver, ACCOUNT, PASSPHRASE)

    fresh = _Client(_Api())
    assert cloud_cmd._restore_session(fresh, ACCOUNT, PASSPHRASE) is True
    assert fresh.session is not None and fresh.session.sid == "stored-sid"
    assert fresh.api.session_set_to == "stored-sid"


def test_the_session_file_never_carries_the_account_address(data_dir):
    saver = _Client(_Api())
    saver.session = _session()
    cloud_cmd._remember_session(saver, ACCOUNT, PASSPHRASE)

    written = list((data_dir / "sessions").iterdir())
    assert len(written) == 1
    assert "user" not in written[0].name and "example" not in written[0].name
    # Encrypted at rest: the sid must not be readable in the file.
    assert b"stored-sid" not in written[0].read_bytes()


def test_a_stale_session_falls_back_to_a_real_login(data_dir):
    """The whole point: a dead sid must not be handed on as if it worked."""
    saver = _Client(_Api())
    saver.session = _session()
    cloud_cmd._remember_session(saver, ACCOUNT, PASSPHRASE)

    fresh = _Client(_Api(alive=False))  # MEGA rejects the stored sid
    assert cloud_cmd._restore_session(fresh, ACCOUNT, PASSPHRASE) is False
    assert fresh.session is None, "a rejected session must not stay on the client"
    assert fresh._cache_cleared


def test_a_wrong_passphrase_just_logs_in_again(data_dir):
    saver = _Client(_Api())
    saver.session = _session()
    cloud_cmd._remember_session(saver, ACCOUNT, PASSPHRASE)

    fresh = _Client(_Api())
    assert cloud_cmd._restore_session(fresh, ACCOUNT, "not-the-passphrase") is False
    assert fresh.session is None


def test_no_stored_session_is_not_an_error(data_dir):
    fresh = _Client(_Api())
    assert cloud_cmd._restore_session(fresh, "nobody@example.com", PASSPHRASE) is False


def test_storing_a_session_never_breaks_the_command(data_dir, monkeypatch):
    """A read-only data dir costs you the cache, not the login."""

    def boom(*_a, **_k):
        raise OSError("read-only")

    saver = _Client(_Api())
    saver.session = _session()
    monkeypatch.setattr("megabasterd_cli.config.session_dir", boom)
    cloud_cmd._remember_session(saver, ACCOUNT, PASSPHRASE)  # must not raise
