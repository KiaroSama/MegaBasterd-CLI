"""Mutating API requests are never blindly replayed.

The generic retry wrapped EVERY request, so a `complete_upload` / `create_folder`
/ `delete_node` / `move_node` that the server had already committed was sent
again after an ambiguous timeout - registering duplicate nodes, importing twice,
or moving twice.

Policy now: read-only actions keep bounded retries; mutations retry only when
the failure is provably pre-commit (RateLimitError = server declined,
ConnectTimeout = never connected). Anything ambiguous raises
AmbiguousMutationError.
"""

from __future__ import annotations

import json as _json

import pytest
import requests

from megabasterd_cli.core.api import (
    READ_ONLY_ACTIONS,
    AmbiguousMutationError,
    MegaAPIClient,
    is_mutating,
)
from megabasterd_cli.core.errors import RateLimitError


@pytest.fixture(autouse=True)
def _no_backoff_sleeps(monkeypatch):
    """Exercise the retry POLICY, not tenacity's wall-clock backoff."""
    from tenacity import wait_none

    from megabasterd_cli.core import api as api_module

    monkeypatch.setattr(api_module, "RETRY_WAIT", wait_none())


class _Recorder:
    """Stands in for requests.Session, counting what actually goes out."""

    def __init__(self, behavior):
        self.sent: list = []
        self._behavior = behavior
        self.headers = {}
        self.proxies = {}

    def post(self, url, json=None, timeout=None, headers=None, proxies=None, stream=False):
        self.sent.append(json)
        return self._behavior(len(self.sent))

    def close(self):
        return None


class _Response:
    status_code = 200
    headers: dict = {}
    encoding = "utf-8"

    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def iter_content(self, chunk_size=None):
        # The client streams the body and bounds it while reading.
        yield _json.dumps(self._payload).encode()

    def close(self):
        return None


def _client(behavior) -> MegaAPIClient:
    client = MegaAPIClient(timeout=1)
    client._session = _Recorder(behavior)
    client.set_session("fake-sid")
    return client


COMPLETE_UPLOAD = {"a": "p", "t": "parent", "n": [{"h": "tok", "t": 0, "a": "x", "k": "y"}]}
CREATE_FOLDER = {"a": "p", "t": "parent", "n": [{"h": "xxxxxxxx", "t": 1, "a": "x", "k": "y"}]}
DELETE_NODE = {"a": "d", "n": "handle"}
MOVE_NODE = {"a": "m", "n": "handle", "t": "newparent"}
RENAME_NODE = {"a": "a", "n": "handle", "attr": "x", "key": "y"}
EXPORT_NODE = {"a": "l", "n": "handle"}
IMPORT_NODE = {"a": "p", "t": "parent", "n": [{"h": "src", "t": 0, "a": "x", "k": "y"}]}
LOGOUT = {"a": "sml"}
REQUEST_UPLOAD = {"a": "u", "s": 1024}

MUTATIONS = {
    "complete_upload": COMPLETE_UPLOAD,
    "create_folder": CREATE_FOLDER,
    "delete_node": DELETE_NODE,
    "move_node": MOVE_NODE,
    "rename_node": RENAME_NODE,
    "export_node": EXPORT_NODE,
    "import_node": IMPORT_NODE,
    "logout": LOGOUT,
    "request_upload": REQUEST_UPLOAD,
}
READS = {
    "user_info": {"a": "ug"},
    "quota": {"a": "uq", "strg": 1},
    "download_url": {"a": "g", "g": 1, "p": "id"},
    "listing": {"a": "f", "c": 1},
}


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("command", MUTATIONS.values(), ids=list(MUTATIONS))
def test_mutations_are_classified_as_mutating(command):
    assert is_mutating(command)


@pytest.mark.parametrize("command", READS.values(), ids=list(READS))
def test_reads_are_classified_as_read_only(command):
    assert not is_mutating(command)


def test_unknown_actions_default_to_mutating():
    """Fail-safe: a newly added command cannot inherit unsafe retries."""
    assert is_mutating({"a": "brand_new_command"})
    assert is_mutating({"no_action_key": 1})
    assert is_mutating("not even a dict")


def test_a_batch_is_mutating_if_any_command_mutates():
    assert is_mutating([{"a": "ug"}, DELETE_NODE])
    assert not is_mutating([{"a": "ug"}, {"a": "uq"}])


def test_read_only_set_does_not_accidentally_contain_writers():
    for forbidden in ("p", "d", "m", "a", "l", "u", "sml"):
        assert forbidden not in READ_ONLY_ACTIONS


# ---------------------------------------------------------------------------
# The core defect: committed-then-timed-out must not be replayed.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("command", MUTATIONS.values(), ids=list(MUTATIONS))
def test_committed_mutation_is_not_sent_twice_after_a_read_timeout(command):
    """The server applied it; the response never arrived."""

    def behavior(attempt):
        raise requests.ReadTimeout("response lost after the server committed")

    client = _client(behavior)
    with pytest.raises(AmbiguousMutationError):
        client.request(command)
    assert len(client._session.sent) == 1, (
        f"the mutation was sent {len(client._session.sent)} times; "
        "an ambiguous timeout must never be replayed"
    )


@pytest.mark.parametrize("command", MUTATIONS.values(), ids=list(MUTATIONS))
def test_mid_flight_connection_drop_is_not_replayed(command):
    def behavior(attempt):
        raise requests.ConnectionError("connection reset while in flight")

    client = _client(behavior)
    with pytest.raises(AmbiguousMutationError):
        client.request(command)
    assert len(client._session.sent) == 1


def test_ambiguous_error_names_the_action_without_leaking_the_payload():
    def behavior(attempt):
        raise requests.ReadTimeout("gone")

    client = _client(behavior)
    with pytest.raises(AmbiguousMutationError) as caught:
        client.request(DELETE_NODE)
    message = str(caught.value)
    assert "d" in message
    assert "handle" not in message, "the request payload must not be echoed"


# ---------------------------------------------------------------------------
# Provably pre-commit failures still retry.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("command", MUTATIONS.values(), ids=list(MUTATIONS))
def test_connect_timeout_is_retried_for_mutations(command):
    """Never connected, so the request was never sent: replay is safe."""

    def behavior(attempt):
        if attempt == 1:
            raise requests.ConnectTimeout("could not connect")
        return _Response([{"ok": True}])

    client = _client(behavior)
    assert client.request(command) == {"ok": True}
    assert len(client._session.sent) == 2


@pytest.mark.parametrize("command", MUTATIONS.values(), ids=list(MUTATIONS))
def test_rate_limit_is_retried_for_mutations(command):
    """ERATELIMIT/-4 means the server DECLINED to process it: nothing committed."""
    calls = {"n": 0}

    def behavior(attempt):
        calls["n"] += 1
        if calls["n"] == 1:
            return _Response(-4)  # ERATELIMIT
        return _Response([{"ok": True}])

    client = _client(behavior)
    assert client.request(command) == {"ok": True}
    assert len(client._session.sent) == 2


def test_rate_limit_eventually_gives_up_without_looping_forever():
    def behavior(attempt):
        return _Response(-4)

    client = _client(behavior)
    with pytest.raises(RateLimitError):
        client.request(DELETE_NODE)
    assert len(client._session.sent) == 5, "bounded retries, unchanged"


# ---------------------------------------------------------------------------
# Read-only requests keep their bounded retries.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("command", READS.values(), ids=list(READS))
def test_read_only_requests_still_retry_on_timeout(command):
    def behavior(attempt):
        if attempt < 3:
            raise requests.ReadTimeout("flaky network")
        return _Response([{"ok": True}])

    client = _client(behavior)
    assert client.request(command) == {"ok": True}
    assert len(client._session.sent) == 3


@pytest.mark.parametrize("command", READS.values(), ids=list(READS))
def test_read_only_requests_retry_on_connection_error(command):
    def behavior(attempt):
        if attempt < 2:
            raise requests.ConnectionError("dropped")
        return _Response([{"ok": True}])

    client = _client(behavior)
    assert client.request(command) == {"ok": True}
    assert len(client._session.sent) == 2


def test_read_only_retries_remain_bounded():
    def behavior(attempt):
        raise requests.ReadTimeout("always down")

    client = _client(behavior)
    with pytest.raises(requests.ReadTimeout):
        client.request({"a": "ug"})
    assert len(client._session.sent) == 5


def test_successful_mutation_is_sent_exactly_once():
    def behavior(attempt):
        return _Response([{"handle": "new"}])

    client = _client(behavior)
    assert client.request(CREATE_FOLDER) == {"handle": "new"}
    assert len(client._session.sent) == 1
