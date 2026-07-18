"""Regression tests: `mb proxy serve` must stop instead of hanging (P1-12).

Every wait here is bounded and the whole module runs under a faulthandler
watchdog, so a regression that reintroduces an unbounded `recv()` fails the
test instead of blocking CI forever.
"""

from __future__ import annotations

import base64
import contextlib
import faulthandler
import socket
import time

import pytest

from megabasterd_cli.proxy import connect_proxy
from megabasterd_cli.proxy.connect_proxy import MegaConnectProxy

PASSWORD = "test-password"
# Every blocking wait in these tests. Generous enough for a loaded CI box,
# short enough that a hang is reported as a failure quickly.
BUDGET = 10.0
# Last-resort process watchdog: if a socket op somehow blocks past this, dump
# every stack and abort rather than hang the suite.
HARD_TIMEOUT = 90.0


@pytest.fixture(autouse=True)
def _watchdog():
    faulthandler.dump_traceback_later(HARD_TIMEOUT, exit=True)
    yield
    faulthandler.cancel_dump_traceback_later()


@pytest.fixture
def fake_upstream(monkeypatch):
    """Replace outbound connects with a socketpair end that never speaks.

    The tunnel then has a permanently silent upstream, which is exactly the
    state that used to block `pipe()` forever.
    """
    ends: list[socket.socket] = []
    far_ends: list[socket.socket] = []

    def _create_connection(address, timeout=None, *args, **kwargs):
        near, far = socket.socketpair()
        ends.extend((near, far))
        far.settimeout(BUDGET)
        far_ends.append(far)
        return near

    monkeypatch.setattr(connect_proxy.socket, "create_connection", _create_connection)
    yield far_ends
    for sock in ends:
        with contextlib.suppress(OSError):
            sock.close()


@pytest.fixture
def serve():
    """Start a proxy on an ephemeral port; always stop it at teardown."""
    started: list[MegaConnectProxy] = []

    def _start(**kwargs) -> tuple[MegaConnectProxy, int]:
        proxy = MegaConnectProxy(password=PASSWORD, port=0, **kwargs)
        proxy.start()
        started.append(proxy)
        assert proxy._server is not None
        return proxy, proxy._server.getsockname()[1]

    yield _start
    for proxy in started:
        with contextlib.suppress(OSError):
            proxy.stop()


def _connect(port: int) -> socket.socket:
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(BUDGET)
    client.connect(("127.0.0.1", port))
    return client


def _open_tunnel(port: int) -> socket.socket:
    """Complete a CONNECT handshake and return the client end of the tunnel."""
    client = _connect(port)
    creds = base64.b64encode(f"u:{PASSWORD}".encode()).decode("ascii")
    client.sendall(
        f"CONNECT g.api.mega.nz:443 HTTP/1.1\r\n"
        f"Proxy-Authorization: Basic {creds}\r\n\r\n".encode()
    )
    assert b"200" in client.recv(4096)
    return client


def test_tunnel_still_forwards_bytes_both_ways(serve, fake_upstream) -> None:
    """The bounded-wait rewrite must not break plain forwarding."""
    _proxy, port = serve()
    client = _open_tunnel(port)
    try:
        upstream = fake_upstream[0]
        client.sendall(b"ping")
        assert upstream.recv(4096) == b"ping"
        upstream.sendall(b"pong")
        assert client.recv(4096) == b"pong"
    finally:
        client.close()


def test_stop_terminates_in_flight_tunnels(serve, fake_upstream) -> None:
    """stop() must unblock workers parked in a tunnel, not just close the listener.

    ThreadPoolExecutor workers are non-daemon and joined at interpreter exit,
    so one worker stuck in an unbounded recv() hangs the whole process.
    """
    proxy, port = serve()
    pool = proxy._pool
    assert pool is not None
    client = _open_tunnel(port)
    try:
        workers = list(pool._threads)
        assert workers, "the tunnel should be running on a pool worker"
        started = time.monotonic()
        proxy.stop()
        assert time.monotonic() - started < BUDGET, "stop() did not return promptly"
        for thread in workers:
            thread.join(timeout=BUDGET)
            assert not thread.is_alive(), "worker still blocked in the tunnel after stop()"
    finally:
        client.close()


def test_idle_tunnel_is_dropped(serve, fake_upstream, monkeypatch) -> None:
    """A tunnel that carries no bytes must not hold a worker forever."""
    monkeypatch.setattr(connect_proxy, "TUNNEL_IDLE_TIMEOUT_SECONDS", 0.5)
    _proxy, port = serve()
    client = _open_tunnel(port)
    try:
        assert client.recv(4096) == b"", "the idle tunnel was never closed"
    finally:
        client.close()


def test_tunnel_lifetime_is_capped(serve, fake_upstream, monkeypatch) -> None:
    """Even a busy tunnel is bounded, so a worker cannot be pinned indefinitely."""
    monkeypatch.setattr(connect_proxy, "TUNNEL_IDLE_TIMEOUT_SECONDS", 3600)
    monkeypatch.setattr(connect_proxy, "TUNNEL_MAX_LIFETIME_SECONDS", 0.5)
    _proxy, port = serve()
    client = _open_tunnel(port)
    try:
        assert client.recv(4096) == b"", "the tunnel outlived its lifetime cap"
    finally:
        client.close()


def test_header_read_has_a_total_deadline(serve, monkeypatch) -> None:
    """Slowloris: a drip-feeding client must not hold a worker per-recv forever."""
    monkeypatch.setattr(connect_proxy, "HEADER_READ_DEADLINE_SECONDS", 0.5)
    _proxy, port = serve()
    client = _connect(port)
    try:
        client.sendall(b"CONNECT g.api.mega.nz:443 HTTP/1.1\r\n")  # never terminated
        assert client.recv(4096) == b"", "the header read never hit its deadline"
    finally:
        client.close()
