"""Resource cleanup must survive every way a login or logout can fail.

The happy path and the `MegaError` path were already covered. What was not:
`logout()` performs a remote `sml` call first, and only `MegaError` was
suppressed - so a `Timeout`, `ConnectionError`, `HTTPError`, a malformed JSON
body, or a crypto error escaped BEFORE any local cleanup ran, leaking the very
session `logout()` exists to release.

`account add --verify` had the mirror-image bug: `logout()` sat inside the
`try`, after `login()`, so a failed verification never reached it at all.

Every assertion here is behavioral - it checks that the transport was actually
closed, never that the source contains the word "close".
"""

from __future__ import annotations

import contextlib
import json

import pytest
import requests

from megabasterd_cli.core.api import MegaAPIClient
from megabasterd_cli.core.errors import MegaError


class _TrackedSession(requests.Session):
    instances: list[_TrackedSession] = []

    def __init__(self) -> None:
        super().__init__()
        self.closed = False
        _TrackedSession.instances.append(self)

    def close(self) -> None:
        self.closed = True
        super().close()


@pytest.fixture
def sessions(monkeypatch):
    _TrackedSession.instances = []
    monkeypatch.setattr("megabasterd_cli.core.api.requests.Session", _TrackedSession)
    yield _TrackedSession.instances
    _TrackedSession.instances = []


def assert_all_released(sessions) -> None:
    assert sessions, "nothing opened a session - the test proves nothing"
    leaked = [s for s in sessions if not s.closed]
    assert not leaked, f"{len(leaked)} of {len(sessions)} HTTP sessions leaked"


def _json_error() -> Exception:
    """The exception `requests` raises for a non-JSON body."""
    try:
        json.loads("<html>not json</html>")
    except ValueError as exc:
        return requests.exceptions.JSONDecodeError(str(exc), "<html>", 0)
    raise AssertionError("unreachable")


# Every distinct way the remote logout call can blow up.
REMOTE_FAILURES = [
    pytest.param(MegaError(message="rejected"), id="MegaError"),
    pytest.param(requests.Timeout("timed out"), id="Timeout"),
    pytest.param(requests.ConnectionError("refused"), id="ConnectionError"),
    pytest.param(requests.HTTPError("500 Server Error"), id="HTTPError"),
    pytest.param(_json_error(), id="JSONDecodeError"),
    pytest.param(ValueError("malformed login response"), id="malformed-response"),
    pytest.param(TypeError("crypto/base64 error"), id="crypto-error"),
]


@pytest.mark.parametrize("failure", REMOTE_FAILURES)
def test_logout_releases_the_transport_however_the_remote_call_fails(sessions, failure):
    """Local cleanup is not conditional on the server cooperating."""
    from megabasterd_cli.core.client import MegaClient, MegaSession

    api = MegaAPIClient()
    api.set_session("sid-value")
    client = MegaClient(api=api)
    client.session = MegaSession(
        sid="sid-value",
        master_key=b"\x01" * 16,
        rsa_private_key=b"\x02" * 8,
        user_handle="uh",
        email="user@example.invalid",
    )

    def _raise(*args, **kwargs):
        raise failure

    api.request = _raise  # type: ignore[method-assign]

    # Whether the failure propagates is a policy choice. What is NOT
    # negotiable is that the transport and local state are cleared either way.
    with contextlib.suppress(Exception):
        client.logout()

    assert_all_released(sessions)
    assert api.session_id is None, "the session ID survived a failed logout"
    assert client.session is None, "local session state survived a failed logout"


def test_double_logout_and_double_close_are_safe(sessions):
    from megabasterd_cli.core.client import MegaClient

    client = MegaClient(api=MegaAPIClient())
    client.logout()
    client.logout()
    client.close()
    client.api.close()

    assert_all_released(sessions)


def test_a_shared_sid_worker_closes_only_its_own_transport(sessions):
    """Parallel workers clone the api; one worker's close must not kill others."""
    base = MegaAPIClient()
    base.set_session("shared-sid")
    worker_a = base.clone()
    worker_b = base.clone()

    worker_a.close()

    assert worker_a._session.closed
    assert not worker_b._session.closed, "one worker's close hit another's transport"
    assert not base._session.closed, "a worker's close hit the base client"
    assert worker_b.session_id == "shared-sid", "the shared sid was invalidated"

    worker_b.close()
    base.close()
    assert_all_released(sessions)


# ---------------------------------------------------------------------------
# `account add --verify`
# ---------------------------------------------------------------------------


def _run_account_add(monkeypatch, tmp_path, login_effect):
    from click.testing import CliRunner

    from megabasterd_cli.commands import account_cmd as module
    from megabasterd_cli.config import Config
    from megabasterd_cli.core.client import MegaClient

    monkeypatch.setattr(MegaClient, "login", login_effect)
    monkeypatch.setattr(module, "confirm", lambda *a, **kw: False)
    monkeypatch.setattr(module, "ask_password", lambda *a, **kw: "pw")

    return CliRunner().invoke(
        module.account_add,
        ["user@example.invalid", "--password", "pw", "--vault-passphrase", "vp"],
        obj={"config": Config(download_path=str(tmp_path)), "json_mode": False},
        catch_exceptions=True,
    )


def test_account_add_verify_releases_the_session_when_login_fails(sessions, tmp_path, monkeypatch):
    """`logout()` sat after `login()` inside the try, so this never reached it."""

    def _fail(self, *a, **kw):
        raise MegaError(message="bad credentials")

    _run_account_add(monkeypatch, tmp_path, _fail)

    assert_all_released(sessions)


def test_account_add_verify_releases_the_session_on_a_non_mega_error(
    sessions, tmp_path, monkeypatch
):
    """A transport failure is not a `MegaError` and skipped the handler entirely."""

    def _fail(self, *a, **kw):
        raise requests.Timeout("timed out")

    _run_account_add(monkeypatch, tmp_path, _fail)

    assert_all_released(sessions)


def test_account_add_verify_releases_the_session_on_mfa_interrupt(sessions, tmp_path, monkeypatch):
    """Ctrl+C at the 2FA prompt must still release the socket, and propagate."""

    def _interrupt(self, *a, **kw):
        raise KeyboardInterrupt()

    result = _run_account_add(monkeypatch, tmp_path, _interrupt)

    assert_all_released(sessions)
    # Click turns an interrupt into Abort -> SystemExit(1). What matters is
    # that the cleanup did not swallow it into a success.
    assert result.exit_code != 0, "the interrupt was swallowed by the cleanup"


def test_account_add_verify_releases_the_session_on_success(sessions, tmp_path, monkeypatch):
    _run_account_add(monkeypatch, tmp_path, lambda self, *a, **kw: None)

    assert_all_released(sessions)
