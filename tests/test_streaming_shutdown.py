"""Ctrl+C must stop the stream server promptly and release everything.

`mb stream` runs `serve_forever()` on the main thread and cleans up when
KeyboardInterrupt unwinds it. Two things can go wrong there, and only one is
the obvious one:

* calling `BaseServer.shutdown()` from the very thread that runs
  `serve_forever()` is a documented deadlock;
* `ThreadingHTTPServer.server_close()` joins outstanding handler threads, and
  a streaming handler stays alive as long as its client keeps reading - so a
  single connected player can hold the CLI hostage after Ctrl+C.

These tests are behavioral: they measure that cleanup actually completes and
that the socket is immediately rebindable, rather than inspecting source.
"""

from __future__ import annotations

import socket
import threading
import time

import pytest

from megabasterd_cli.streaming.server import StreamingServer

# These drive the `stream` command, and `stream_cmd` resolves its port with
# `port or cfg.streaming_port` - so `--port 0` is falsy and every one of them
# binds the SAME configured port rather than an ephemeral one. Sequentially
# that is fine; on two xdist workers at once it is EADDRINUSE. One worker.
pytestmark = pytest.mark.xdist_group("streaming_cli_port")

CLEANUP_BUDGET = 10.0  # seconds; a deadlock blows straight past this


def _server() -> StreamingServer:
    return StreamingServer(api=None, host="127.0.0.1", port=0, selector=None)


def _rebind(host: str, port: int) -> bool:
    """True when the address is free again."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        probe.close()


def test_shutdown_from_another_thread_returns_promptly():
    server = _server()
    serving = threading.Thread(target=server.serve_forever, daemon=True)
    serving.start()
    try:
        started = time.monotonic()
        server.shutdown()
        elapsed = time.monotonic() - started
    finally:
        server.server_close()

    assert elapsed < CLEANUP_BUDGET, f"shutdown() took {elapsed:.1f}s"
    serving.join(timeout=CLEANUP_BUDGET)
    assert not serving.is_alive()


def test_the_socket_is_rebindable_immediately_after_cleanup():
    """A stale listening socket makes the next `mb stream` fail on the port."""
    server = _server()
    host, port = server.server_address[0], server.server_address[1]
    serving = threading.Thread(target=server.serve_forever, daemon=True)
    serving.start()
    server.shutdown()
    server.server_close()

    assert _rebind(host, port), f"{host}:{port} still held after server_close()"


def test_cleanup_completes_while_a_client_is_still_connected():
    """The realistic Ctrl+C: a player is mid-stream when the operator quits.

    `server_close()` joins handler threads. If a streaming handler is blocked
    writing to a client that has stopped reading, that join never returns and
    Ctrl+C hangs the CLI with the port still held.
    """
    server = _server()
    host, port = server.server_address[0], server.server_address[1]
    serving = threading.Thread(target=server.serve_forever, daemon=True)
    serving.start()

    client = socket.create_connection((host, port), timeout=CLEANUP_BUDGET)
    try:
        # Send a request and then deliberately stop reading the response.
        client.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        time.sleep(0.2)

        done = threading.Event()

        def _cleanup() -> None:
            server.shutdown()
            server.server_close()
            done.set()

        threading.Thread(target=_cleanup, daemon=True).start()
        finished = done.wait(timeout=CLEANUP_BUDGET)
    finally:
        client.close()

    assert finished, (
        "cleanup did not finish while a client was connected - Ctrl+C would "
        "hang the CLI with the listening port still held"
    )
    assert _rebind(host, port), "port still held after cleanup"


def test_cleanup_runs_even_if_serve_forever_raises():
    """A non-KeyboardInterrupt failure must still release the socket."""
    server = _server()
    host, port = server.server_address[0], server.server_address[1]

    def _boom() -> None:
        raise RuntimeError("selector exploded")

    server.serve_forever = _boom  # type: ignore[method-assign]

    with pytest.raises(RuntimeError):
        try:
            server.serve_forever()
        finally:
            server.server_close()

    assert _rebind(host, port)


# ---------------------------------------------------------------------------
# The command's own Ctrl+C path
# ---------------------------------------------------------------------------


def test_ctrl_c_releases_the_port_and_the_api_session(tmp_path, monkeypatch):
    """Drive `mb stream` and interrupt it the way an operator does.

    Behavioral, not source inspection: the command must return, the upstream
    HTTP session must be closed, and the listening port must be free.
    """
    from click.testing import CliRunner

    from megabasterd_cli.commands import stream_cmd as module
    from megabasterd_cli.config import Config

    captured: dict = {}
    real_init = StreamingServer.__init__

    def _record(self, *args, **kwargs):
        real_init(self, *args, **kwargs)
        captured["address"] = self.server_address

    closed: list = []

    monkeypatch.setattr(StreamingServer, "__init__", _record)
    monkeypatch.setattr(StreamingServer, "set_source", lambda self, url, password=None: None)
    monkeypatch.setattr(
        StreamingServer,
        "serve_forever",
        lambda self, *a, **kw: (_ for _ in ()).throw(KeyboardInterrupt()),
    )
    monkeypatch.setattr(
        "megabasterd_cli.core.api.MegaAPIClient.close",
        lambda self: closed.append(self),
    )

    started = time.monotonic()
    CliRunner().invoke(
        module.stream,
        ["https://mega.nz/file/ABCDEFGH#" + "k" * 43, "--port", "0"],
        obj={"config": Config(download_path=str(tmp_path)), "json_mode": False},
        catch_exceptions=False,
    )
    elapsed = time.monotonic() - started

    assert elapsed < CLEANUP_BUDGET, f"Ctrl+C took {elapsed:.1f}s to unwind"
    assert closed, "the upstream API session was not closed on Ctrl+C"
    host, port = captured["address"][0], captured["address"][1]
    assert _rebind(host, port), "the listening port was not released on Ctrl+C"
