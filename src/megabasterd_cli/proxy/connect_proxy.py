"""Local HTTPS CONNECT proxy that tunnels traffic to mega.nz.

Direct port of the original `MegaProxyServer` (CONNECT-tunnel pattern). Other
applications can be configured to use `http://localhost:<port>` as an HTTPS
proxy; this server validates a Basic-Auth password and only forwards
CONNECT requests to `*.mega.nz` (or `mega.co.nz`) on port 443.
"""

from __future__ import annotations

import base64
import logging
import re
import socket
import threading
from concurrent.futures import ThreadPoolExecutor

log = logging.getLogger(__name__)


MAX_HEADER_LINE_LEN = 8192
MAX_PROXY_THREADS = 64
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


class _ProxyHandler:
    def __init__(self, password: str, allow_any_port: bool = False):
        self.password = password
        self.allow_any_port = allow_any_port

    def handle(self, client_sock: socket.socket, addr: tuple[str, int]) -> None:
        try:
            client_sock.settimeout(30)
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

            if not ALLOWED_HOST_RE.match(host):
                self._reply(client_sock, 403, "Forbidden host")
                return
            if connect_m and port != 443 and not self.allow_any_port:
                self._reply(client_sock, 403, "Forbidden port")
                return

            # Authorization
            if not self._check_auth(headers):
                client_sock.sendall(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                    b"Proxy-Authenticate: Basic realm=\"megabasterd-cli\"\r\n"
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
            try:
                client_sock.close()
            except OSError:
                pass

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
                if supplied == self.password:
                    return True
        return False

    @staticmethod
    def _read_headers(sock: socket.socket) -> tuple[str, list[str], bytes]:
        """Return (request_line, header_lines, leftover_body_bytes).

        The third element is any bytes that came in the same recv after the
        \\r\\n\\r\\n terminator (e.g. the start of a POST body). The caller is
        responsible for forwarding those if applicable.
        """
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(4096)
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
            f"HTTP/1.1 {code} {message}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode("ascii")
        )

    @staticmethod
    def _tunnel(client: socket.socket, upstream: socket.socket) -> None:
        client.settimeout(None)
        upstream.settimeout(None)
        stop = threading.Event()

        def pipe(src: socket.socket, dst: socket.socket) -> None:
            try:
                while not stop.is_set():
                    data = src.recv(65536)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                stop.set()
                for s in (src, dst):
                    try:
                        s.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

        t = threading.Thread(target=pipe, args=(upstream, client), daemon=True)
        t.start()
        pipe(client, upstream)
        t.join(timeout=5)
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

    def start(self) -> None:
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((self.host, self.port))
        self._server.listen(50)
        self._pool = ThreadPoolExecutor(max_workers=MAX_PROXY_THREADS)
        handler = _ProxyHandler(self.password, allow_any_port=self.allow_any_port)

        def _accept_loop() -> None:
            try:
                while not self._stop.is_set():
                    try:
                        sock, addr = self._server.accept()
                    except OSError:
                        break
                    self._pool.submit(handler.handle, sock, addr)
            finally:
                if self._pool:
                    self._pool.shutdown(wait=False)

        threading.Thread(target=_accept_loop, daemon=True).start()
        log.info("MEGA CONNECT proxy listening on %s:%d", self.host, self.port)

    def stop(self) -> None:
        self._stop.set()
        if self._server:
            try:
                self._server.close()
            except OSError:
                pass
            self._server = None
        if self._pool:
            self._pool.shutdown(wait=False)
            self._pool = None
