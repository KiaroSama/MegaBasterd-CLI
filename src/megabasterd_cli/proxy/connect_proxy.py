"""Local HTTPS CONNECT proxy that tunnels traffic to mega.nz.

Direct port of the original `MegaProxyServer` (CONNECT-tunnel pattern). Other
applications can be configured to use `http://localhost:<port>` as an HTTPS
proxy; this server validates a Basic-Auth password and only forwards
CONNECT requests to `*.mega.nz` (or `mega.co.nz`) on port 443.
"""

from __future__ import annotations

import base64
import contextlib
import hmac
import logging
import platform
import re
import select
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor

log = logging.getLogger(__name__)


MAX_HEADER_LINE_LEN = 8192
MAX_PROXY_THREADS = 64
CONNECT_TUNNEL_JOIN_TIMEOUT_SECONDS = 30
# Total budget for reading a request head, however many recv() calls it takes.
# A per-recv timeout alone lets a client drip one byte per timeout window and
# pin a worker until the size cap is reached (slowloris).
HEADER_READ_DEADLINE_SECONDS = 30
# How long a tunnel may sit with no bytes in either direction before it is
# dropped, and the hard cap on a single tunnel's total life. Both bound how
# long one client can hold a worker out of the pool.
TUNNEL_IDLE_TIMEOUT_SECONDS = 300
TUNNEL_MAX_LIFETIME_SECONDS = 3600
# recv() timeout inside the tunnel loop. Blocking forever means neither the
# idle/lifetime deadlines nor the stop Event can ever be observed, so the
# socket wakes up this often to check them.
TUNNEL_POLL_SECONDS = 1.0
ALLOWED_HOST_RE = re.compile(r"^(.+\.)?mega(?:\.co)?\.nz$", re.IGNORECASE)
CONNECT_RE = re.compile(
    r"^CONNECT\s+(?P<host>[A-Za-z0-9.\-]+):(?P<port>\d+)\s+HTTP/(?P<ver>1\.[01])\s*$"
)
# Plain-HTTP forward request: `GET http://<host>[:<port>]/<path> HTTP/1.x`.
# Needed because MEGA's CDN serves file chunks over http://, not https://.
HTTP_FORWARD_RE = re.compile(
    r"^(?P<method>GET|HEAD|POST|PUT|OPTIONS|DELETE)\s+"
    r"http://(?P<host>[A-Za-z0-9.\-]+)(?::(?P<port>\d+))?(?P<path>/\S*)\s+"
    r"HTTP/(?P<ver>1\.[01])\s*$",
    re.IGNORECASE,
)
AUTH_RE = re.compile(r"^Proxy-Authorization:\s*Basic\s+(?P<creds>\S+)\s*$", re.IGNORECASE)


def check_destination(host: str, port: int, is_connect: bool, allow_any_port: bool) -> str | None:
    """Return None if the destination is allowed, else a short rejection reason.

    The same host allow-list and port policy apply to every forwarding mode
    (CONNECT tunnels and absolute-form HTTP requests). Unless `allow_any_port`
    is set, CONNECT is limited to 443 (HTTPS) and plain-HTTP forwarding to
    80/443, so an allowed MEGA host cannot be reached on an arbitrary port.
    """
    if not ALLOWED_HOST_RE.match(host):
        return "Forbidden host"
    if not allow_any_port:
        allowed = {443} if is_connect else {80, 443}
        if port not in allowed:
            return "Forbidden port"
    return None


class _ProxyHandler:
    def __init__(
        self,
        password: str,
        allow_any_port: bool = False,
        server_stop: threading.Event | None = None,
    ):
        self.password = password
        self.allow_any_port = allow_any_port
        # Set when the server is shutting down: every tunnel loop watches it so
        # a stop() is observed within one TUNNEL_POLL_SECONDS even if the peer
        # socket is still open.
        self.server_stop = server_stop or threading.Event()

    def handle(self, client_sock: socket.socket, addr: tuple[str, int]) -> None:
        try:
            client_sock.settimeout(HEADER_READ_DEADLINE_SECONDS)
            request_line, headers, body_tail = self._read_headers(client_sock)
            if not request_line:
                return

            connect_m = CONNECT_RE.match(request_line)
            http_m = None if connect_m else HTTP_FORWARD_RE.match(request_line)
            if not connect_m and not http_m:
                self._reply(client_sock, 400, "Bad Request")
                return

            if connect_m:
                host = connect_m.group("host")
                port = int(connect_m.group("port"))
            else:
                host = http_m.group("host")
                port = int(http_m.group("port") or "80")

            reason = check_destination(host, port, bool(connect_m), self.allow_any_port)
            if reason:
                self._reply(client_sock, 403, reason)
                return

            # Authorization
            if not self._check_auth(headers):
                time.sleep(0.25)
                client_sock.sendall(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                    b'Proxy-Authenticate: Basic realm="megabasterd-cli"\r\n'
                    b"Content-Length: 0\r\nConnection: close\r\n\r\n"
                )
                return

            try:
                upstream = socket.create_connection((host, port), timeout=15)
            except OSError as exc:
                log.warning("Upstream connect failed: %s", exc)
                self._reply(client_sock, 502, "Bad Gateway")
                return

            if connect_m:
                # HTTPS CONNECT: just open a tunnel and shovel bytes both ways.
                self._reply(client_sock, 200, "Connection Established")
                self._tunnel(client_sock, upstream)
                return

            # Plain HTTP forwarding: rewrite the request line to be origin-form
            # (path only, not absolute URL), strip the Proxy-Authorization
            # header, then forward the request + any pipelined body bytes and
            # stream the response back unchanged.
            method = http_m.group("method").upper()
            path = http_m.group("path")
            version = http_m.group("ver")
            rewritten_lines = [f"{method} {path} HTTP/{version}"]
            for line in headers:
                if AUTH_RE.match(line):
                    continue
                # Strip hop-by-hop Connection/Proxy-Connection headers.
                if re.match(r"^(Proxy-Connection|Connection):", line, re.IGNORECASE):
                    continue
                rewritten_lines.append(line)
            rewritten = ("\r\n".join(rewritten_lines) + "\r\n\r\n").encode("latin-1")

            try:
                upstream.sendall(rewritten)
                if body_tail:
                    upstream.sendall(body_tail)
                self._tunnel(client_sock, upstream)
            except OSError as exc:
                log.debug("HTTP forward failed: %s", exc)
        except Exception as exc:  # noqa: BLE001
            log.debug("Proxy handler error from %s: %s", addr, exc)
        finally:
            with contextlib.suppress(OSError):
                client_sock.close()

    def _check_auth(self, headers: list[str]) -> bool:
        for line in headers:
            m_auth = AUTH_RE.match(line)
            if not m_auth:
                continue
            try:
                decoded = base64.b64decode(m_auth.group("creds")).decode("utf-8")
            except Exception:  # noqa: BLE001
                continue
            if ":" in decoded:
                _user, supplied = decoded.split(":", 1)
                if hmac.compare_digest(supplied, self.password):
                    return True
        return False

    @staticmethod
    def _read_headers(sock: socket.socket) -> tuple[str, list[str], bytes]:
        """Return (request_line, header_lines, leftover_body_bytes).

        The third element is any bytes that came in the same recv after the
        \\r\\n\\r\\n terminator (e.g. the start of a POST body). The caller is
        responsible for forwarding those if applicable.

        The whole head must arrive within HEADER_READ_DEADLINE_SECONDS. The
        timeout shrinks with every recv so a client that keeps the connection
        barely alive (one byte per window) is cut off at the deadline instead
        of holding a pool worker until the size cap is reached.
        """
        deadline = time.monotonic() + HEADER_READ_DEADLINE_SECONDS
        data = b""
        while b"\r\n\r\n" not in data:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return "", [], b""
            sock.settimeout(remaining)
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                return "", [], b""
            if not chunk:
                break
            data += chunk
            if len(data) > MAX_HEADER_LINE_LEN * 50:
                return "", [], b""
        head, sep, tail = data.partition(b"\r\n\r\n")
        if not sep:
            return "", [], b""
        lines = head.split(b"\r\n")
        request_line = lines[0].decode("latin-1", errors="replace") if lines else ""
        headers = [ln.decode("latin-1", errors="replace") for ln in lines[1:] if ln]
        return request_line, headers, tail

    @staticmethod
    def _reply(sock: socket.socket, code: int, message: str) -> None:
        sock.sendall(
            f"HTTP/1.1 {code} {message}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode(
                "ascii"
            )
        )

    def _tunnel(self, client: socket.socket, upstream: socket.socket) -> None:
        """Shovel bytes both ways until idle, expired, closed, or stopped.

        The wait for readable data is bounded by `select`, not by a blocking
        recv(): a blocking recv could observe neither the stop Event nor the
        deadlines, so `stop()` left the worker parked forever and the process
        hung at interpreter exit (ThreadPoolExecutor joins its workers there).
        The sockets themselves stay in blocking mode so `sendall` still cannot
        time out half-way through a chunk on a slow peer.
        """
        client.settimeout(None)
        upstream.settimeout(None)
        stop = threading.Event()
        expires_at = time.monotonic() + TUNNEL_MAX_LIFETIME_SECONDS

        def pipe(src: socket.socket, dst: socket.socket) -> None:
            last_byte_at = time.monotonic()
            try:
                while not stop.is_set() and not self.server_stop.is_set():
                    now = time.monotonic()
                    if now >= expires_at:
                        log.debug("Tunnel closed: lifetime cap reached")
                        break
                    if now - last_byte_at >= TUNNEL_IDLE_TIMEOUT_SECONDS:
                        log.debug("Tunnel closed: idle timeout")
                        break
                    readable, _w, _x = select.select([src], [], [], TUNNEL_POLL_SECONDS)
                    if not readable:
                        continue  # nothing yet: re-check the deadlines and stop
                    data = src.recv(65536)
                    if not data:
                        break
                    last_byte_at = time.monotonic()
                    dst.sendall(data)
            # ValueError: stop() closed the socket under us, so its fileno is
            # already -1 by the time select() looks at it.
            except (OSError, ValueError):
                pass
            finally:
                stop.set()
                for s in (src, dst):
                    with contextlib.suppress(OSError):
                        s.shutdown(socket.SHUT_RDWR)

        t = threading.Thread(target=pipe, args=(upstream, client), daemon=True)
        t.start()
        pipe(client, upstream)
        t.join(timeout=CONNECT_TUNNEL_JOIN_TIMEOUT_SECONDS)
        upstream.close()


class MegaConnectProxy:
    """Threaded loopback CONNECT proxy bound to 127.0.0.1."""

    def __init__(
        self,
        password: str,
        host: str = "127.0.0.1",
        port: int = 9999,
        allow_any_port: bool = False,
    ):
        self.host = host
        self.port = port
        self.password = password
        self.allow_any_port = allow_any_port
        self._server: socket.socket | None = None
        self._pool: ThreadPoolExecutor | None = None
        self._stop = threading.Event()
        # Every accepted socket, so stop() can close them all. Without this the
        # listener closed while accepted connections kept their worker parked.
        self._active: set[socket.socket] = set()
        self._active_lock = threading.Lock()

    def start(self) -> None:
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if platform.system() == "Windows" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self._server.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
            self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if len(self.password) < 8:
            log.warning("CONNECT proxy password is short; use at least 8 characters")
        self._server.bind((self.host, self.port))
        self._server.listen(50)
        pool = self._pool = ThreadPoolExecutor(max_workers=MAX_PROXY_THREADS)
        server = self._server
        handler = _ProxyHandler(
            self.password,
            allow_any_port=self.allow_any_port,
            server_stop=self._stop,
        )

        def _accept_loop() -> None:
            # `pool`/`server` are captured locally: stop() clears the attributes
            # concurrently, and a half-torn-down attribute must not be used.
            try:
                while not self._stop.is_set():
                    try:
                        sock, addr = server.accept()
                    except OSError:
                        break
                    with self._active_lock:
                        self._active.add(sock)
                    pool.submit(self._serve, handler, sock, addr)
            finally:
                pool.shutdown(wait=False)

        threading.Thread(target=_accept_loop, daemon=True).start()
        log.info("MEGA CONNECT proxy listening on %s:%d", self.host, self.port)

    def _serve(self, handler: _ProxyHandler, sock: socket.socket, addr: tuple[str, int]) -> None:
        try:
            handler.handle(sock, addr)
        finally:
            with self._active_lock:
                self._active.discard(sock)

    def stop(self) -> None:
        """Stop listening AND terminate everything already accepted.

        Closing only the listener left in-flight tunnels running; their pool
        workers are joined at interpreter exit, so `mb proxy serve` hung on
        Ctrl-C instead of exiting. Shutting the accepted sockets down makes the
        blocked reads return, and `cancel_futures` drops the ones not started.
        """
        self._stop.set()
        if self._server:
            with contextlib.suppress(OSError):
                self._server.close()
            self._server = None
        with self._active_lock:
            active, self._active = list(self._active), set()
        for sock in active:
            # shutdown() first: it wakes a peer blocked in select()/recv() even
            # when another thread still holds the same socket object.
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)
            with contextlib.suppress(OSError):
                sock.close()
        if self._pool:
            self._pool.shutdown(wait=False, cancel_futures=True)
            self._pool = None
