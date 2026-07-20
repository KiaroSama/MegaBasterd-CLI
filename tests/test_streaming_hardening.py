"""Regression tests for streaming server hardening (B10 / P1-11).

Every network assertion below is bounded by a hard client-side timeout, so a
regression FAILS the suite instead of hanging CI.

Covered defects:
  (a) unbounded concurrency - one unbounded thread per connection;
  (b) no socket timeouts - client sockets were fully blocking;
  (c) slowloris - `rfile.readline()` blocked forever on a half-open request;
  (d) the streamed byte count was never compared with the promised
      Content-Length, so a short upstream body was served as a complete file;
  (f) an IPv6 bind was impossible and the banner produced `http://::1:8080/`;
  (g) a wildcard bind advertised `http://0.0.0.0:8080/`, which nothing can dial;
  (h) upstream exception strings (CDN URL, proxy user:pass@) reached the client.
"""

from __future__ import annotations

import http.client
import logging
import socket
import threading
import time

import pytest
import requests

from megabasterd_cli.streaming import server as srv
from megabasterd_cli.streaming.server import StreamingServer

# These drive the `stream` command, and `stream_cmd` resolves its port with
# `port or cfg.streaming_port` - so `--port 0` is falsy and every one of them
# binds the SAME configured port rather than an ephemeral one. Sequentially
# that is fine; on two xdist workers at once it is EADDRINUSE. One worker.
pytestmark = pytest.mark.xdist_group("streaming_cli_port")

# Any single blocking client call must finish well inside this.
HARD_TIMEOUT = 10.0


class _FakeSource:
    """Stand-in for a resolved _StreamSource with a null AES key."""

    mimetype = "application/octet-stream"
    filename = "f.bin"
    aes_key = b"\x00" * 16
    nonce = b"\x00" * 8

    def __init__(self, size: int = 4096):
        self.size = size

    def current_cdn_url(self) -> str:
        return "https://cdn.invalid/dl/CDNSECRET"

    def refresh_cdn_url(self) -> str:
        return self.current_cdn_url()


def _start(**kwargs) -> StreamingServer:
    kwargs.setdefault("host", "127.0.0.1")
    kwargs.setdefault("port", 0)
    server = StreamingServer(api=object(), **kwargs)
    server.source = _FakeSource()
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _addr(server: StreamingServer) -> tuple[str, int]:
    return server.server_address[0], server.server_address[1]


def _half_open(server: StreamingServer) -> socket.socket:
    """A connection that starts a request line and never finishes it."""
    sock = socket.create_connection(_addr(server), timeout=HARD_TIMEOUT)
    sock.sendall(b"GET / HTTP")
    return sock


def _status(server: StreamingServer, method: str = "HEAD") -> int:
    host, port = _addr(server)
    conn = http.client.HTTPConnection(host, port, timeout=HARD_TIMEOUT)
    try:
        conn.request(method, "/")
        return conn.getresponse().status
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# (a) bounded concurrency
# ---------------------------------------------------------------------------


def test_connections_beyond_the_cap_are_rejected_with_503():
    """One unbounded thread per connection is a trivial resource exhaustion."""
    server = _start(max_connections=2, header_timeout=HARD_TIMEOUT)
    held = []
    try:
        held = [_half_open(server) for _ in range(2)]
        time.sleep(0.4)  # let the accept loop hand both to handler threads
        assert _status(server) == 503, "the connection cap is not enforced"
    finally:
        for sock in held:
            sock.close()
        server.shutdown()
        server.server_close()


def test_capacity_returns_once_stalled_connections_are_reaped():
    server = _start(max_connections=2, header_timeout=0.5)
    held = []
    try:
        held = [_half_open(server) for _ in range(4)]
        time.sleep(1.5)  # well past the header budget
        assert _status(server) == 200, "reaped slots were never released"
    finally:
        for sock in held:
            sock.close()
        server.shutdown()
        server.server_close()


# ---------------------------------------------------------------------------
# (b) + (c) timeouts and slowloris
# ---------------------------------------------------------------------------


def test_a_half_open_request_is_dropped_within_the_header_budget():
    server = _start(header_timeout=0.5)
    sock = _half_open(server)
    try:
        started = time.monotonic()
        data = sock.recv(4096)  # blocks until the server gives up on us
        elapsed = time.monotonic() - started
    except TimeoutError:  # pragma: no cover - this IS the regression
        pytest.fail("the server never dropped a half-open connection")
    finally:
        sock.close()
        server.shutdown()
        server.server_close()

    assert data == b"" or data.startswith(b"HTTP/1."), data[:40]
    assert elapsed < 5.0, f"half-open connection held for {elapsed:.1f}s"


def test_a_dribbling_client_cannot_hold_a_connection_open_forever():
    """The real slowloris: bytes arrive just often enough to beat a per-read
    timeout, so only a TOTAL header deadline can end it."""
    server = _start(header_timeout=0.6)
    sock = socket.create_connection(_addr(server), timeout=HARD_TIMEOUT)
    try:
        started = time.monotonic()
        dropped = False
        for _ in range(20):  # 20 * 0.2s = 4s of dribbling
            try:
                sock.sendall(b"X")
            except OSError:
                dropped = True
                break
            time.sleep(0.2)
            sock.settimeout(0.01)
            try:
                if sock.recv(4096) == b"":
                    dropped = True
                    break
            except (TimeoutError, BlockingIOError):
                pass
            except OSError:
                dropped = True
                break
            finally:
                sock.settimeout(HARD_TIMEOUT)
        elapsed = time.monotonic() - started
    finally:
        sock.close()
        server.shutdown()
        server.server_close()

    assert dropped, "a dribbling client held the connection for the whole loop"
    assert elapsed < 5.0, f"dribbling client survived {elapsed:.1f}s"


# Must comfortably exceed the loopback send+receive buffers, or the kernel
# swallows the whole body and the handler never actually blocks on the write.
_STALL_SIZE = 128 * 1024 * 1024


class _EndlessResponse:
    """A full-size body, so the handler's writes block on a client that stalls."""

    status_code = 200
    headers = {"Content-Length": str(_STALL_SIZE)}

    def iter_content(self, chunk_size=65536):
        for _ in range(_STALL_SIZE // chunk_size):
            yield b"\x00" * chunk_size

    def close(self):
        pass


def test_a_client_that_stops_reading_cannot_pin_a_handler_forever(monkeypatch):
    """The write leg needs a timeout too: with none, a stalled reader owns a
    thread (and, now, a connection slot) for good."""
    # The two phases must not race each other. `handler_timeout` has to be
    # comfortably longer than the phase-1 settle, or the timeout under test
    # fires BEFORE we check that the slot is held and phase 1 reads 200 - which
    # is what happened on the slower Windows runners when both were 0.5s.
    settle = 0.5
    handler_timeout = 3.0
    assert handler_timeout > settle * 3, "phase 1 must not race the timeout"
    assert handler_timeout * 2 < HARD_TIMEOUT, "phase 2 must outlast the timeout"

    server = _start(max_connections=1, handler_timeout=handler_timeout, header_timeout=2.0)
    server.source = _FakeSource(_STALL_SIZE)
    monkeypatch.setattr(srv.requests, "get", lambda url, **kw: _EndlessResponse())
    stalled = socket.create_connection(_addr(server), timeout=HARD_TIMEOUT)
    try:
        stalled.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        time.sleep(settle)  # the handler is now blocked writing into a full buffer
        assert _status(server) == 503, "the single slot is not held as expected"

        deadline = time.monotonic() + HARD_TIMEOUT
        while time.monotonic() < deadline:
            try:
                if _status(server) == 200:
                    break
            except (ConnectionResetError, ConnectionAbortedError):
                pass  # refused outright: still saturated, keep waiting
            time.sleep(0.2)
        else:  # pragma: no cover - this IS the regression
            pytest.fail("a stalled reader pinned the handler forever")
    finally:
        stalled.close()
        server.shutdown()
        server.server_close()


# ---------------------------------------------------------------------------
# (d) the streamed byte count must match the promised Content-Length
# ---------------------------------------------------------------------------


class _ShortResponse:
    """Headers promise the full range; the body stops early."""

    def __init__(self, declared: int, body: bytes):
        self.status_code = 206
        self.headers = {
            "Content-Range": f"bytes 0-{declared - 1}/{declared}",
            "Content-Length": str(declared),
        }
        self._body = body
        self.closed = False

    def iter_content(self, chunk_size=65536):
        yield self._body

    def close(self):
        self.closed = True


def test_a_short_upstream_body_is_never_served_as_a_complete_file(monkeypatch, caplog):
    server = _start()
    monkeypatch.setattr(srv.requests, "get", lambda url, **kw: _ShortResponse(4096, b"\x00" * 1000))
    host, port = _addr(server)
    conn = http.client.HTTPConnection(host, port, timeout=HARD_TIMEOUT)
    try:
        with caplog.at_level(logging.ERROR, logger="megabasterd_cli.streaming.server"):
            conn.request("GET", "/")
            resp = conn.getresponse()
            assert resp.getheader("Content-Length") == "4096"
            with pytest.raises((http.client.IncompleteRead, ConnectionError)):
                body = resp.read()
                pytest.fail(f"served {len(body)} bytes as a complete 4096-byte file")
    except TimeoutError:  # pragma: no cover - regression: no abort, no close
        pytest.fail("the truncated response neither completed nor aborted")
    finally:
        conn.close()
        server.shutdown()
        server.server_close()

    assert "4096" in caplog.text and "1000" in caplog.text, caplog.text


# ---------------------------------------------------------------------------
# (h) upstream errors must not leak the CDN URL or proxy credentials
# ---------------------------------------------------------------------------


SECRETS = ("hunter2", "CDNSECRET", "spy:hunter2")
LEAKY = (
    "HTTPSConnectionPool(host='cdn.invalid', port=443): Max retries exceeded "
    "with url: /dl/CDNSECRET (Caused by ProxyError('Cannot connect to proxy',"
    " NewConnectionError('http://spy:hunter2@proxy.invalid:8080')))"
)


def _raw_response(server: StreamingServer) -> bytes:
    host, port = _addr(server)
    sock = socket.create_connection((host, port), timeout=HARD_TIMEOUT)
    try:
        sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        chunks = []
        while True:
            block = sock.recv(65536)
            if not block:
                break
            chunks.append(block)
        return b"".join(chunks)
    finally:
        sock.close()


def test_upstream_request_failure_does_not_leak_the_proxy_or_cdn_url(monkeypatch):
    server = _start()

    def boom(url, **kwargs):
        raise requests.ConnectionError(LEAKY)

    monkeypatch.setattr(srv.requests, "get", boom)
    try:
        raw = _raw_response(server)
    finally:
        server.shutdown()
        server.server_close()

    assert b"502" in raw.split(b"\r\n", 1)[0], raw[:80]
    for secret in SECRETS:
        assert secret.encode() not in raw, f"{secret!r} leaked to the client"


def test_cdn_refresh_failure_does_not_leak(monkeypatch):
    server = _start()

    class _Expired:
        status_code = 403
        headers: dict = {}

        def close(self):
            pass

    def blow_up():
        raise RuntimeError(LEAKY)

    server.source.refresh_cdn_url = blow_up  # type: ignore[method-assign]
    monkeypatch.setattr(srv.requests, "get", lambda url, **kw: _Expired())
    try:
        raw = _raw_response(server)
    finally:
        server.shutdown()
        server.server_close()

    for secret in SECRETS:
        assert secret.encode() not in raw, f"{secret!r} leaked to the client"


def test_proxy_required_error_does_not_leak(monkeypatch):
    from megabasterd_cli.proxy.selector import ProxyRequiredError, ProxySelector

    class _Refusing(ProxySelector):
        def select(self):
            raise ProxyRequiredError(LEAKY)

    server = _start(selector=_Refusing(force=True))
    try:
        raw = _raw_response(server)
    finally:
        server.shutdown()
        server.server_close()

    for secret in SECRETS:
        assert secret.encode() not in raw, f"{secret!r} leaked to the client"


# ---------------------------------------------------------------------------
# (f) IPv6
# ---------------------------------------------------------------------------


def test_an_ipv6_host_actually_binds_and_serves():
    server = StreamingServer(api=object(), host="::1", port=0)
    server.source = _FakeSource()
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        assert server.socket.family == socket.AF_INET6
        port = server.server_address[1]
        conn = http.client.HTTPConnection("::1", port, timeout=HARD_TIMEOUT)
        try:
            conn.request("HEAD", "/")
            assert conn.getresponse().status == 200
        finally:
            conn.close()
    finally:
        server.shutdown()
        server.server_close()


def test_a_bracketed_ipv6_host_binds_too():
    server = StreamingServer(api=object(), host="[::1]", port=0)
    try:
        assert server.socket.family == socket.AF_INET6
    finally:
        server.server_close()


# ---------------------------------------------------------------------------
# (f) + (g) the banner must print a dialable URL
# ---------------------------------------------------------------------------


def _banner(monkeypatch, tmp_path, host: str) -> str:
    from click.testing import CliRunner

    from megabasterd_cli.commands import stream_cmd as module
    from megabasterd_cli.config import Config

    monkeypatch.setattr(StreamingServer, "set_source", lambda self, url, password=None: None)
    monkeypatch.setattr(
        StreamingServer,
        "serve_forever",
        lambda self, *a, **kw: (_ for _ in ()).throw(KeyboardInterrupt()),
    )
    result = CliRunner().invoke(
        module.stream,
        ["https://mega.nz/file/ABCDEFGH#" + "k" * 43, "--port", "0", "-H", host],
        obj={"config": Config(download_path=str(tmp_path)), "json_mode": False},
        catch_exceptions=False,
    )
    return result.output


def test_ipv6_banner_is_bracketed(monkeypatch, tmp_path):
    output = _banner(monkeypatch, tmp_path, "::1")

    assert "http://::1:" not in output, "unbracketed IPv6 URL is not dialable"
    assert "http://[::1]:" in output, output


def test_wildcard_bind_advertises_a_dialable_address(monkeypatch, tmp_path):
    output = _banner(monkeypatch, tmp_path, "0.0.0.0")

    assert "http://0.0.0.0:" not in output, "0.0.0.0 is not a dialable address"
    assert "http://127.0.0.1:" in output, output


def test_ipv6_wildcard_bind_advertises_a_dialable_address(monkeypatch, tmp_path):
    output = _banner(monkeypatch, tmp_path, "::")

    assert "http://::" not in output
    assert "http://[::1]:" in output, output
