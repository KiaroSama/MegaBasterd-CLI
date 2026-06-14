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
