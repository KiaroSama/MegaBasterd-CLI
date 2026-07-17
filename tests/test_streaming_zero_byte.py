"""Zero-byte streaming: valid GET/HEAD, no invalid upstream range fetch."""

from __future__ import annotations

import http.client
from types import SimpleNamespace

import pytest

import megabasterd_cli.streaming.server as server_module
from megabasterd_cli.streaming.server import StreamingServer


@pytest.fixture()
def zero_byte_server(monkeypatch):
    def upstream_forbidden(*args, **kwargs):
        raise AssertionError("an empty file must never trigger an upstream fetch")

    monkeypatch.setattr(server_module.requests, "get", upstream_forbidden)
    server = StreamingServer(api=None, host="127.0.0.1", port=0)
    server.source = SimpleNamespace(
        size=0,
        mimetype="text/plain",
        filename="empty.txt",
        current_cdn_url=lambda: "https://example.invalid/cdn",
    )
    thread = server.serve_forever_in_thread()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _request(server, method, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
    try:
        conn.request(method, "/", headers=headers or {})
        resp = conn.getresponse()
        body = resp.read()
        return resp, body
    finally:
        conn.close()


def test_get_empty_file_returns_200_and_zero_length(zero_byte_server):
    resp, body = _request(zero_byte_server, "GET")
    assert resp.status == 200
    assert resp.getheader("Content-Length") == "0"
    assert body == b""


def test_head_empty_file_returns_zero_length(zero_byte_server):
    resp, body = _request(zero_byte_server, "HEAD")
    assert resp.status == 200
    assert resp.getheader("Content-Length") == "0"
    assert body == b""


def test_range_on_empty_file_is_416_not_invalid_upstream(zero_byte_server):
    resp, _body = _request(zero_byte_server, "GET", headers={"Range": "bytes=0-"})
    assert resp.status == 416
    assert resp.getheader("Content-Range") == "bytes */0"
