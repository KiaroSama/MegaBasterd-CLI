"""Every command path must release the HTTP session it opened.

A `MegaAPIClient` owns a `requests.Session`, which owns a connection pool
holding real sockets and TLS state. Commands that returned early - or simply
finished - left those sockets to the garbage collector, and `logout()` looked
like the cleanup call but only invalidated the server-side session ID.

Three call sites had already noticed and written `logout()` immediately
followed by `api.close()`; the ten cloud commands and `share` had not, which
is the giveaway that the fix belongs in `logout()` rather than in each caller.
"""

from __future__ import annotations

import pytest
import requests
from click.testing import CliRunner

from megabasterd_cli.config import Config
from megabasterd_cli.core.api import MegaAPIClient
from megabasterd_cli.core.errors import MegaError


class _TrackedSession(requests.Session):
    """A real Session that records whether anyone closed it."""

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
    """Track every HTTP session opened by `MegaAPIClient` during one test."""
    _TrackedSession.instances = []
    monkeypatch.setattr("megabasterd_cli.core.api.requests.Session", _TrackedSession)
    yield _TrackedSession.instances
    _TrackedSession.instances = []


def assert_all_released(sessions) -> None:
    assert sessions, "the code under test never opened a session - the test proves nothing"
    leaked = [s for s in sessions if not s.closed]
    assert not leaked, f"{len(leaked)} of {len(sessions)} HTTP sessions were never closed"


# ---------------------------------------------------------------------------
# The root cause: logout() released the session ID but not the socket
# ---------------------------------------------------------------------------


def test_logout_releases_the_http_session(sessions):
    """`logout()` is the documented end-of-life call; it must free the socket."""
    from megabasterd_cli.core.client import MegaClient

    client = MegaClient(api=MegaAPIClient())
    client.logout()

    assert_all_released(sessions)


def test_logout_still_invalidates_the_session_id(sessions):
    """Releasing the socket must not turn logout into a no-op."""
    from megabasterd_cli.core.client import MegaClient

    api = MegaAPIClient()
    api.set_session("sid-value")
    client = MegaClient(api=api)
    client.logout()

    assert api.session_id is None
    assert client.session is None


def test_close_is_idempotent(sessions):
    """Three call sites already do `logout()` then `api.close()`."""
    from megabasterd_cli.core.client import MegaClient

    client = MegaClient(api=MegaAPIClient())
    client.logout()
    client.api.close()
    client.api.close()

    assert_all_released(sessions)


# ---------------------------------------------------------------------------
# Command paths
# ---------------------------------------------------------------------------


def _config(tmp_path) -> Config:
    return Config(download_path=str(tmp_path))


def _invoke(command, args, tmp_path, **obj):
    runner = CliRunner()
    context = {"config": _config(tmp_path), "json_mode": False}
    context.update(obj)
    return runner.invoke(command, args, obj=context, catch_exceptions=False)


def test_info_releases_the_session_on_a_lookup_failure(sessions, tmp_path, monkeypatch):
    """`mb info` opened a client and returned through any of a dozen paths."""
    from megabasterd_cli.commands.info_cmd import info_cmd

    monkeypatch.setattr(
        MegaAPIClient,
        "get_public_file_info",
        lambda self, public_id: (_ for _ in ()).throw(MegaError(message="boom")),
    )
    _invoke(info_cmd, ["https://mega.nz/file/ABCDEFGH#" + "k" * 43], tmp_path)

    assert_all_released(sessions)


def test_info_releases_the_session_on_the_success_path(sessions, tmp_path, monkeypatch):
    from megabasterd_cli.commands.info_cmd import info_cmd

    monkeypatch.setattr(
        MegaAPIClient,
        "get_public_file_info",
        lambda self, public_id: {"s": 1024, "at": ""},
    )
    _invoke(info_cmd, ["https://mega.nz/file/ABCDEFGH"], tmp_path)

    assert_all_released(sessions)


def test_info_releases_the_session_on_an_early_return(sessions, tmp_path, monkeypatch):
    """The `no key` branch returns before the table is printed."""
    from megabasterd_cli.commands.info_cmd import info_cmd

    monkeypatch.setattr(
        MegaAPIClient,
        "get_public_folder_listing",
        lambda self, public_id: {"f": []},
    )
    _invoke(info_cmd, ["https://mega.nz/folder/ABCDEFGH#" + "k" * 22], tmp_path)

    assert_all_released(sessions)


def _stub_vault(monkeypatch, module: str):
    """Make `_client()`-style helpers reach login without a real vault."""
    from megabasterd_cli.accounts.manager import AccountManager

    class _Account:
        email = "user@example.invalid"

    monkeypatch.setattr(AccountManager, "unlock", lambda self, passphrase: None)
    monkeypatch.setattr(AccountManager, "get_account", lambda self, account_id: _Account())
    monkeypatch.setattr(AccountManager, "get_password", lambda self, account_id: "pw")
    monkeypatch.setattr(f"{module}.ask_password", lambda *a, **kw: "passphrase")


def test_cloud_command_releases_the_session_when_login_fails(sessions, tmp_path, monkeypatch):
    """`_client()` built the api, then let the login exception escape."""
    from megabasterd_cli.commands import cloud_cmd as module
    from megabasterd_cli.core.client import MegaClient

    _stub_vault(monkeypatch, "megabasterd_cli.commands.cloud_cmd")
    monkeypatch.setattr(
        "megabasterd_cli.accounts.manager.resolve_account_id",
        lambda mgr, default, account: "account-1",
    )
    monkeypatch.setattr(
        MegaClient,
        "login",
        lambda self, *a, **kw: (_ for _ in ()).throw(MegaError(message="bad password")),
    )
    _invoke(module.ls_cmd, [], tmp_path)

    assert_all_released(sessions)


def test_cloud_command_releases_the_session_on_success(sessions, tmp_path, monkeypatch):
    from megabasterd_cli.commands import cloud_cmd as module
    from megabasterd_cli.core.client import MegaClient

    _stub_vault(monkeypatch, "megabasterd_cli.commands.cloud_cmd")
    monkeypatch.setattr(
        "megabasterd_cli.accounts.manager.resolve_account_id",
        lambda mgr, default, account: "account-1",
    )
    monkeypatch.setattr(MegaClient, "login", lambda self, *a, **kw: None)
    monkeypatch.setattr(MegaClient, "list_files", lambda self: [])
    monkeypatch.setattr(MegaClient, "find_root", lambda self: "root")
    _invoke(module.ls_cmd, [], tmp_path)

    assert_all_released(sessions)


def test_share_releases_the_session_when_login_fails(sessions, tmp_path, monkeypatch):
    """`share` printed the error and returned, skipping its own finally."""
    from megabasterd_cli.commands import share_cmd as module
    from megabasterd_cli.core.client import MegaClient

    _stub_vault(monkeypatch, "megabasterd_cli.commands.share_cmd")
    monkeypatch.setattr(
        "megabasterd_cli.accounts.manager.resolve_account_id",
        lambda mgr, default, account: "account-1",
    )
    monkeypatch.setattr(
        MegaClient,
        "login",
        lambda self, *a, **kw: (_ for _ in ()).throw(MegaError(message="bad password")),
    )
    _invoke(module.share_cmd, ["some-handle"], tmp_path)

    assert_all_released(sessions)


def test_stream_releases_the_session_when_setup_fails(sessions, tmp_path, monkeypatch):
    """A failed `set_source` closed the socket server but not the api."""
    from megabasterd_cli.commands import stream_cmd as module
    from megabasterd_cli.streaming.server import StreamingServer

    monkeypatch.setattr(
        StreamingServer,
        "set_source",
        lambda self, url, password=None: (_ for _ in ()).throw(MegaError(message="nope")),
    )
    _invoke(module.stream, ["https://mega.nz/file/ABCDEFGH#" + "k" * 43], tmp_path)

    assert_all_released(sessions)


def test_no_command_module_relies_on_logout_plus_a_forgotten_close():
    """Guard the invariant, not just today's call sites.

    Any `finally: client.logout()` is now sufficient. This asserts the
    property that made it sufficient, so a future refactor of `logout()`
    cannot quietly reintroduce the leak in eleven places at once.
    """
    import inspect

    from megabasterd_cli.core.client import MegaClient

    source = inspect.getsource(MegaClient.logout)
    assert "close" in source, "logout() must release the HTTP session"


@pytest.mark.parametrize(
    "name",
    ["ls_cmd", "mkdir_cmd", "rm_cmd", "mv_cmd", "rename_cmd", "search_cmd", "import_cmd"],
)
def test_every_cloud_command_releases_in_a_finally(name):
    """The cloud commands all share `_client()`; none may skip the release."""
    import inspect

    from megabasterd_cli.commands import cloud_cmd

    command = getattr(cloud_cmd, name)
    source = inspect.getsource(command.callback)
    assert "finally" in source and "logout()" in source, f"{name} can leak its session"
