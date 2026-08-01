"""Regression tests for streaming authentication (Priority 3).

Non-loopback binds must require a token; loopback stays unauthenticated.
"""

from __future__ import annotations

import http.client
import threading

import pytest

from megabasterd_cli.streaming.server import StreamingServer, is_loopback_host


class _FakeSource:
    mimetype = "application/octet-stream"
    size = 10
    filename = "f.bin"


@pytest.mark.parametrize(
    "host,expected",
    [
        ("127.0.0.1", True),
        ("127.0.0.5", True),
        ("::1", True),
        ("[::1]", True),
        ("localhost", True),
        ("0.0.0.0", False),
        ("::", False),
        ("192.168.1.10", False),
        ("example.com", False),
        ("", False),
    ],
)
def test_is_loopback_host(host: str, expected: bool) -> None:
    assert is_loopback_host(host) is expected


def _serve(server: StreamingServer) -> threading.Thread:
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return t


def _head(port: int, path: str = "/", headers: dict | None = None) -> int:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request("HEAD", path, headers=headers or {})
        return conn.getresponse().status
    finally:
        conn.close()


def test_loopback_requires_no_token() -> None:
    server = StreamingServer(api=object(), host="127.0.0.1", port=0, auth_token=None)
    server.source = _FakeSource()
    _serve(server)
    try:
        port = server.server_address[1]
        assert _head(port) == 200
    finally:
        server.shutdown()
        server.server_close()


def test_token_required_when_set() -> None:
    server = StreamingServer(api=object(), host="127.0.0.1", port=0, auth_token="s3cret-token")
    server.source = _FakeSource()
    _serve(server)
    try:
        port = server.server_address[1]
        # Bearer is the primary method and always works.
        assert _head(port, "/") == 401
        assert _head(port, "/", {"Authorization": "Bearer s3cret-token"}) == 200
        assert _head(port, "/", {"Authorization": "Bearer nope"}) == 401
        assert _head(port, "/", {"Authorization": "Basic s3cret-token"}) == 401
        # Query token is rejected by default (allow_query_token off).
        assert _head(port, "/?token=s3cret-token") == 401
        assert _head(port, "/?access_token=s3cret-token") == 401
    finally:
        server.shutdown()
        server.server_close()


def test_query_token_opt_in() -> None:
    server = StreamingServer(
        api=object(),
        host="127.0.0.1",
        port=0,
        auth_token="qtok",
        allow_query_token=True,
    )
    server.source = _FakeSource()
    _serve(server)
    try:
        port = server.server_address[1]
        assert _head(port, "/?token=qtok") == 200
        assert _head(port, "/?token=wrong") == 401
        # Bearer still works when query tokens are enabled.
        assert _head(port, "/", {"Authorization": "Bearer qtok"}) == 200
    finally:
        server.shutdown()
        server.server_close()


def test_get_range_requires_token() -> None:
    server = StreamingServer(api=object(), host="127.0.0.1", port=0, auth_token="rtok")
    server.source = _FakeSource()
    _serve(server)
    try:
        port = server.server_address[1]
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            conn.request("GET", "/", headers={"Range": "bytes=0-3"})
            assert conn.getresponse().status == 401
        finally:
            conn.close()
    finally:
        server.shutdown()
        server.server_close()


def test_query_token_not_logged(caplog) -> None:
    import logging

    server = StreamingServer(
        api=object(),
        host="127.0.0.1",
        port=0,
        auth_token="leaky-token",
        allow_query_token=True,
    )
    server.source = _FakeSource()
    _serve(server)
    try:
        port = server.server_address[1]
        with caplog.at_level(logging.DEBUG, logger="megabasterd_cli.streaming.server"):
            assert _head(port, "/?token=leaky-token") == 200
        assert "leaky-token" not in caplog.text
    finally:
        server.shutdown()
        server.server_close()


# ---------------------------------------------------------------------------
# The guard belongs to the server, not to the one command that remembers it
# ---------------------------------------------------------------------------
#
# `stream_cmd` generated a token for any non-loopback bind, and the server's own
# docstring said one was "Required for non-loopback binds" - but nothing in
# `StreamingServer` enforced it. Any other caller (the launcher, a library
# consumer, the next command) got an unauthenticated public HTTP server serving
# decrypted MEGA content, and the promise in the comment was simply false.
#
# This repo has been bitten five separate times by a rule that lived in one
# caller while a sibling surface drifted away from it (the styler's brackets,
# the batch hook vs `queue run`, the MPI reader for privk vs csid, `logout()` in
# six teardowns, launcher vs CLI). The fix is always the same shape: put the
# rule where every caller has to go through it.


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.10", "example.com"])
def test_a_public_bind_without_a_token_is_refused(host: str) -> None:
    """Constructing it must fail - and fail BEFORE the socket is bound."""
    with pytest.raises(ValueError, match="token"):
        StreamingServer(api=object(), host=host, port=0, auth_token=None)


@pytest.mark.parametrize("blank", ["", "   "])
def test_a_blank_token_does_not_satisfy_the_guard(blank: str) -> None:
    """`_check_auth` treats a falsy token as "no authentication at all"."""
    with pytest.raises(ValueError, match="token"):
        StreamingServer(api=object(), host="0.0.0.0", port=0, auth_token=blank)


def test_a_public_bind_with_a_token_is_allowed() -> None:
    server = StreamingServer(api=object(), host="0.0.0.0", port=0, auth_token="a-real-token")
    try:
        assert server.auth_token == "a-real-token"
    finally:
        server.server_close()


def test_loopback_without_a_token_is_still_allowed() -> None:
    """The convenience the guard must not cost: localhost stays open."""
    server = StreamingServer(api=object(), host="127.0.0.1", port=0, auth_token=None)
    try:
        assert server.auth_token is None
    finally:
        server.server_close()


def test_the_refusal_leaves_no_listening_socket_behind() -> None:
    """Raising after super().__init__() would leak a bound, unguarded port."""
    import socket

    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    taken = probe.getsockname()[1]
    probe.close()

    with pytest.raises(ValueError, match="token"):
        StreamingServer(api=object(), host="0.0.0.0", port=taken, auth_token=None)

    # If the refused construction had bound first, this rebind would fail.
    again = socket.socket()
    again.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        again.bind(("0.0.0.0", taken))
    finally:
        again.close()
