"""Local HTTP server that streams MEGA files with HTTP Range support.

The server resolves the MEGA link once on startup and then proxies each incoming
HTTP Range request through:
1. Compute the CTR counter for the start of the requested range
2. Issue a Range request to MEGA's CDN
3. Decrypt the stream on the fly with AES-CTR
4. Pipe decrypted bytes to the client

This lets media players seek to arbitrary positions without downloading the
entire file first.
"""

from __future__ import annotations

import contextlib
import hmac
import io
import ipaddress
import logging
import mimetypes
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable
from urllib.parse import parse_qs, quote, urlsplit

import requests

from ..core.crypto import (
    b64_url_decode,
    decrypt_attributes,
    make_ctr_cipher,
    str_to_a32,
    unpack_file_key,
)
from ..core.links import parse_link
from ..core.range_validation import RangeNotHonoredError, validate_range_response
from ..proxy.selector import ProxyRequiredError, ProxySelector
from ..utils.helpers import sanitize_filename
from ..utils.redaction import redact_text

log = logging.getLogger(__name__)

URL_EXPIRY_STATUS = {403, 410, 509}

# Defaults for the three resource bounds. A media player opens a handful of
# parallel Range connections, so the cap is generous while still finite.
DEFAULT_MAX_CONNECTIONS = 16
# Inner bound: a single peer may hold at most this many of the global slots, so
# one hostile address can never own the whole pool. Browsers cap themselves at
# 6 connections per host and players open fewer, so 8 leaves normal playback
# untouched while still keeping half the pool available to everyone else.
DEFAULT_MAX_CONNECTIONS_PER_CLIENT = 8
DEFAULT_HANDLER_TIMEOUT = 60.0  # per socket operation, once a request is parsed
DEFAULT_HEADER_TIMEOUT = 15.0  # TOTAL budget for one request line + headers
_REJECT_LINGER = 0.3  # graceful-close budget for a refused connection
_MAX_REJECT_THREADS = 4  # capped: a refusal must never become its own thread bomb

_OVER_CAPACITY_BODY = b"Too many active connections"
_OVER_CAPACITY_RESPONSE = (
    b"HTTP/1.1 503 Service Unavailable\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n"
    b"Content-Length: " + str(len(_OVER_CAPACITY_BODY)).encode() + b"\r\n"
    b"Retry-After: 5\r\n"
    b"Connection: close\r\n"
    b"\r\n" + _OVER_CAPACITY_BODY
)


class ShortUpstreamBodyError(RuntimeError):
    """The CDN delivered fewer bytes than the range it acknowledged.

    The client has already been promised ``Content-Length``, so the only
    honest signal left is to abort the connection instead of letting a
    truncated file look complete.
    """


def address_family_for_host(host: str) -> int:
    """Pick AF_INET6 for an IPv6 literal, AF_INET for everything else.

    Without this the server hardcoded AF_INET and an IPv6 bind was impossible.
    Hostnames keep the historical AF_INET behaviour.
    """
    try:
        return (
            socket.AF_INET6
            if ipaddress.ip_address(host.strip().strip("[]")).version == 6
            else socket.AF_INET
        )
    except ValueError:
        return socket.AF_INET


def is_loopback_host(host: str) -> bool:
    """Return True only for loopback binds (127.0.0.0/8, ::1, localhost).

    Wildcard binds ("0.0.0.0", "::"), LAN addresses, and hostnames are treated
    as non-loopback so the caller can require authentication for them.
    """
    if not host:
        return False
    candidate = host.strip().lower()
    if candidate in ("localhost", "localhost.localdomain"):
        return True
    candidate = candidate.strip("[]")
    try:
        return ipaddress.ip_address(candidate).is_loopback
    except ValueError:
        return False


def _strip_query(value: str) -> str:
    """Drop any query string from a request-line/path so tokens never reach logs."""
    return value.split("?", 1)[0] if "?" in value else value


def _content_disposition(filename: str) -> str:
    """Build a safe Content-Disposition value for an untrusted MEGA filename."""
    cleaned = filename.replace("\r", "_").replace("\n", "_").replace("\\", "_")
    ascii_name = cleaned.encode("ascii", errors="ignore").decode("ascii") or "download"
    ascii_name = ascii_name.replace('"', r"\"")
    return f'inline; filename="{ascii_name}"; filename*=UTF-8\'\'{quote(cleaned, safe="")}'


class _StreamSource:
    """Resolved MEGA file ready to be streamed."""

    def __init__(
        self,
        url: str,
        api,
        password: str | None = None,
        selector=None,  # ProxySelector | None
    ):
        from ..core.crypto import a32_to_bytes, aes_key_wrap_decrypt, bytes_to_a32
        from ..core.link_services import (
            get_megacrypter_download_url,
            get_megacrypter_info,
            resolve_megacrypter_link,
        )
        from ..core.links import LinkType, resolve_encrypted_container_link, resolve_password_link

        self._cdn_url_lock = threading.Lock()
        self._resolver: Callable[[], str] | None = None

        parsed = parse_link(url)
        # Unwrap any container/password/MegaCrypter wrappers down to a normal
        # FILE or FILE_IN_FOLDER link.
        if parsed.type == LinkType.PASSWORD_PROTECTED:
            if not password:
                raise RuntimeError("Stream source is password-protected; pass --password")
            parsed = resolve_password_link(parsed, password)
        elif parsed.type == LinkType.ENCRYPTED_CONTAINER:
            parsed = resolve_encrypted_container_link(parsed)
        elif parsed.type == LinkType.MEGACRYPTER:
            try:
                parsed = resolve_megacrypter_link(parsed, password=password, selector=selector)
            except ValueError as exc:
                mc_info = get_megacrypter_info(parsed, password=password, selector=selector)
                if not mc_info.key or mc_info.size is None:
                    raise RuntimeError("MegaCrypter metadata is missing key or size") from exc
                self.cdn_url = get_megacrypter_download_url(
                    parsed,
                    info=mc_info,
                    password=password,
                    selector=selector,
                )
                self._resolver = lambda: get_megacrypter_download_url(
                    parsed,
                    info=mc_info,
                    password=password,
                    selector=selector,
                )
                self.size = mc_info.size
                self.aes_key, self.nonce, _ = unpack_file_key(str_to_a32(mc_info.key))
                self.filename = sanitize_filename(
                    mc_info.name or parsed.crypter_token or "megacrypter"
                )
                self.mimetype = mimetypes.guess_type(self.filename)[0] or "application/octet-stream"
                return
        if parsed.type not in (LinkType.FILE, LinkType.FILE_IN_FOLDER):
            raise RuntimeError(f"Stream source must be a file link, got {parsed.type}")

        if parsed.type == LinkType.FILE_IN_FOLDER:
            # The link points to a node inside a public folder share. The
            # folder key wraps each node's key separately; we must:
            #   1. Fetch the folder listing
            #   2. Locate the file node by handle (parsed.subpath)
            #   3. Decrypt its wrapped key with the folder key
            #   4. Request the CDN URL for that specific node in the folder context
            folder_id = parsed.public_id
            file_handle = parsed.subpath
            folder_key = a32_to_bytes(str_to_a32(parsed.key))
            listing = api.get_public_folder_listing(folder_id)
            file_raw = next(
                (n for n in listing.get("f", []) if n.get("h") == file_handle and n.get("t") == 0),
                None,
            )
            if file_raw is None:
                raise RuntimeError(f"File {file_handle!r} not found in folder share")

            raw_k = file_raw.get("k", "")
            _, wrapped = raw_k.split(":", 1) if ":" in raw_k else ("", raw_k)
            key_bytes = aes_key_wrap_decrypt(b64_url_decode(wrapped), folder_key)
            key_a32 = bytes_to_a32(key_bytes[:32])

            info = api.request(
                {"a": "g", "g": 1, "n": file_handle},
                extra_params={"n": folder_id},
            )
            if "g" not in info:
                raise RuntimeError(f"No CDN URL returned for folder-file: {info}")

            def _resolver() -> str:
                fresh = api.request(
                    {"a": "g", "g": 1, "n": file_handle},
                    extra_params={"n": folder_id},
                )
                if "g" not in fresh:
                    raise RuntimeError(f"No refreshed CDN URL returned for {file_handle}: {fresh}")
                return fresh["g"]

            self._resolver = _resolver
            # The attribute blob lives on the listing node, not the get response.
            encrypted_attrs = b64_url_decode(file_raw.get("a", "") or "")
        else:
            info = api.get_public_file_info(parsed.public_id)
            if "g" not in info:
                raise RuntimeError(f"No CDN URL returned: {info}")

            def _resolver() -> str:
                fresh = api.get_public_file_info(parsed.public_id)
                if "g" not in fresh:
                    raise RuntimeError(
                        f"No refreshed CDN URL returned for {parsed.public_id}: {fresh}"
                    )
                return fresh["g"]

            self._resolver = _resolver
            key_a32 = str_to_a32(parsed.key)
            encrypted_attrs = b64_url_decode(info.get("at", "") or "")

        self.cdn_url: str = info["g"]
        self.size: int = int(info["s"])
        self.aes_key, self.nonce, _ = unpack_file_key(key_a32)
        attrs = decrypt_attributes(encrypted_attrs, self.aes_key) or {}
        self.filename = sanitize_filename(attrs.get("n") or parsed.public_id)
        self.mimetype = mimetypes.guess_type(self.filename)[0] or "application/octet-stream"

    def current_cdn_url(self) -> str:
        with self._cdn_url_lock:
            return self.cdn_url

    def refresh_cdn_url(self) -> str:
        if self._resolver is None:
            raise RuntimeError("CDN URL expired and no resolver is available")
        fresh = self._resolver()
        with self._cdn_url_lock:
            self.cdn_url = fresh
            return self.cdn_url


class _DeadlineRawIO(io.RawIOBase):
    """Raw socket reader whose every `recv` is bounded by a total deadline.

    A per-operation socket timeout cannot stop a slowloris on its own: one
    `rfile.readline()` loops over many `recv` calls internally, and each
    dribbled byte renews the timeout. Bounding the socket at the RAW level
    means the shrinking remainder of the budget applies to every recv, so
    the request line + headers can never outlive it however slowly they
    trickle in.
    """

    def __init__(self, handler: _StreamingRequestHandler):
        self._handler = handler

    def readable(self) -> bool:
        return True

    def readinto(self, buffer):  # type: ignore[override]
        handler = self._handler
        deadline = handler.header_deadline
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("header read deadline exceeded")
            handler.connection.settimeout(remaining)
        return handler.connection.recv_into(buffer)


class _StreamingRequestHandler(BaseHTTPRequestHandler):
    server: StreamingServer  # type: ignore[assignment]

    # socketserver only calls settimeout() when this is non-None, so leaving it
    # at None (the base default) made every client socket fully blocking.
    timeout = DEFAULT_HANDLER_TIMEOUT
    header_deadline: float | None = None

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(self.server.handler_timeout)
        self.rfile.close()  # only decrefs the socket's io refs, never the fd
        self.rfile = io.BufferedReader(_DeadlineRawIO(self))  # type: ignore[assignment]

    def handle_one_request(self) -> None:
        self.header_deadline = time.monotonic() + self.server.header_timeout
        try:
            # TimeoutError from the deadline reader is socket.timeout's alias,
            # which the base implementation already turns into a clean close.
            super().handle_one_request()
        finally:
            self.header_deadline = None

    def parse_request(self) -> bool:
        parsed = bool(super().parse_request())
        # Headers are in: hand the socket back its plain per-operation timeout
        # so a long body write is not cut short by the shrinking header budget.
        self.header_deadline = None
        with contextlib.suppress(OSError):  # the socket may already be torn down
            self.connection.settimeout(self.server.handler_timeout)
        return parsed

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        # Never log the raw request path: it may carry a ?token= access token.
        # We log only method + path (query stripped) at debug level.
        try:
            safe_args = tuple(_strip_query(a) if isinstance(a, str) else a for a in args)
        except Exception:  # noqa: BLE001
            safe_args = args
        log.debug("HTTP: " + format, *safe_args)

    def _check_auth(self) -> bool:
        """Validate the access token when the server requires one.

        The primary method is ``Authorization: Bearer <token>``. A ``?token=``
        query parameter is accepted ONLY when the server was started with
        ``allow_query_token=True`` (off by default), because query strings leak
        into logs, history, and referrers. Comparison is constant-time.
        Loopback servers run without a token (returns True).
        """
        token = self.server.auth_token
        if not token:
            return True
        supplied: str | None = None
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            supplied = auth_header[len("Bearer ") :].strip()
        if supplied is None and self.server.allow_query_token:
            query = parse_qs(urlsplit(self.path).query)
            values = query.get("token") or query.get("access_token")
            if values:
                supplied = values[0]
        if supplied is None:
            return False
        return hmac.compare_digest(supplied, token)

    def _reject_unauthorized(self) -> None:
        # No file content is served; do not echo the expected token.
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Bearer realm="megabasterd-cli"')
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_HEAD(self) -> None:  # noqa: N802
        if not self._check_auth():
            self._reject_unauthorized()
            return
        source = self.server.source
        if not source:
            self.send_error(503, "No source configured")
            return
        self.send_response(200)
        self.send_header("Content-Type", source.mimetype)
        self.send_header("Content-Length", str(source.size))
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("Content-Disposition", _content_disposition(source.filename))
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        if not self._check_auth():
            self._reject_unauthorized()
            return
        source = self.server.source
        if not source:
            self.send_error(503, "No source configured")
            return

        if source.size == 0:
            # Empty file: never issue an invalid upstream `bytes=0--1` fetch.
            if self.headers.get("Range"):
                self.send_response(416)
                self.send_header("Content-Range", "bytes */0")
                self.send_header("Accept-Ranges", "bytes")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", source.mimetype)
            self.send_header("Content-Length", "0")
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("Content-Disposition", _content_disposition(source.filename))
            self.end_headers()
            return

        try:
            start, end, is_partial = self._parse_range(source.size)
        except ValueError:
            self.send_error(400, "Malformed Range")
            return
        except IndexError:
            self.send_response(416)
            self.send_header("Content-Range", f"bytes */{source.size}")
            self.send_header("Accept-Ranges", "bytes")
            self.end_headers()
            return
        length = end - start + 1

        # Align CTR counter on 16-byte boundary
        block_start = (start // 16) * 16
        block_skip = start - block_start

        resp = self._open_upstream(source, block_start, end)
        if resp is None:
            return

        cipher = make_ctr_cipher(
            source.aes_key,
            source.nonce,
            initial_value=block_start // 16,
        )

        if is_partial:
            self.send_response(206)
            self.send_header("Content-Range", f"bytes {start}-{end}/{source.size}")
        else:
            self.send_response(200)
        self.send_header("Content-Type", source.mimetype)
        self.send_header("Content-Length", str(length))
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("Content-Disposition", _content_disposition(source.filename))
        self.end_headers()

        try:
            self._pump(resp, cipher, block_skip, length, start, end)
        except (BrokenPipeError, ConnectionResetError):
            log.debug("Client disconnected")
        except ShortUpstreamBodyError as exc:
            # The promised Content-Length is already on the wire, so the status
            # cannot be changed. Dropping the connection makes the client raise
            # an incomplete-read error instead of accepting a truncated file.
            self.close_connection = True
            log.error("Truncated stream for %s: %s", redact_text(source.filename), exc)
        finally:
            resp.close()

    def _pump(
        self,
        resp: requests.Response,
        cipher,
        block_skip: int,
        length: int,
        start: int,
        end: int,
    ) -> None:
        """Decrypt the upstream body to the client, verifying the byte count.

        The old loop simply ended when the upstream body ran out, so a short
        response was served as a complete file under the full Content-Length.
        """
        sent = 0
        for block in resp.iter_content(chunk_size=65536):
            if not block:
                continue
            decrypted = cipher.decrypt(block)
            if block_skip:
                decrypted = decrypted[block_skip:]
                block_skip = 0
            if sent + len(decrypted) > length:
                decrypted = decrypted[: length - sent]
            if not decrypted:
                continue
            self.wfile.write(decrypted)
            sent += len(decrypted)
            if sent >= length:
                break
        if sent != length:
            raise ShortUpstreamBodyError(
                f"upstream delivered {sent} of {length} promised bytes for range {start}-{end}"
            )

    def _parse_range(self, size: int) -> tuple[int, int, bool]:
        range_header = self.headers.get("Range", "")
        if not range_header:
            return 0, size - 1, False
        if not range_header.startswith("bytes="):
            raise ValueError("Unsupported range unit")
        spec = range_header.split("=", 1)[1]
        if "," in spec:
            raise ValueError("Multiple ranges are not supported")
        left, sep, right = spec.partition("-")
        if not sep:
            raise ValueError("Malformed range")
        if left:
            start = int(left)
            end = int(right) if right else size - 1
        else:
            suffix_len = int(right)
            if suffix_len <= 0:
                raise IndexError("Unsatisfiable range")
            start = max(0, size - suffix_len)
            end = size - 1
        if start < 0 or end < start or start >= size:
            raise IndexError("Unsatisfiable range")
        return start, min(end, size - 1), True

    def _send_upstream_error(self, code: int, reason: str, detail: object) -> None:
        """Answer an upstream failure without echoing the exception string.

        `requests` embeds the full URL in its exception text: the ephemeral
        MEGA CDN URL, and for a ProxyError the proxy URL *including*
        `user:pass@`. The client gets a fixed reason (also redacted, and free
        of CR/LF so it cannot split the response); the detail stays in the
        server log, redacted there too.
        """
        log.error("%s: %s", reason, redact_text(str(detail)))
        self.send_error(code, redact_text(reason))

    def _open_upstream(
        self, source: _StreamSource, start: int, end: int
    ) -> requests.Response | None:
        """Open a validated upstream range, or send a 502 and return None.

        Two guarantees for the caller, which decrypts the body with an
        AES-CTR counter derived from `start`:
          * the request is proxied whenever force mode demands it (the
            selector raises before any socket is opened, and a proxy failure
            never falls back to a direct retry);
          * the response really is the requested byte range, so plaintext can
            never silently correspond to a different offset.
        """
        selector = self.server.selector
        for attempt in range(2):
            try:
                request_proxies, picked = selector.select()
            except ProxyRequiredError as exc:
                self._send_upstream_error(502, "Upstream proxy unavailable", exc)
                return None
            try:
                resp = requests.get(
                    source.current_cdn_url(),
                    headers={"Range": f"bytes={start}-{end}"},
                    stream=True,
                    timeout=60,
                    proxies=request_proxies,
                )
            except requests.RequestException as e:
                selector.report_failure(picked)
                self._send_upstream_error(502, "Upstream request failed", e)
                return None
            if resp.status_code in URL_EXPIRY_STATUS and attempt == 0:
                resp.close()
                try:
                    source.refresh_cdn_url()
                except Exception as exc:  # noqa: BLE001
                    self._send_upstream_error(502, "CDN URL refresh failed", exc)
                    return None
                continue
            if resp.status_code not in (200, 206):
                status = resp.status_code
                resp.close()
                selector.report_failure(picked)
                self._send_upstream_error(502, f"Upstream HTTP {status}", status)
                return None
            try:
                validate_range_response(resp.status_code, resp.headers, start, end, source.size)
            except RangeNotHonoredError as exc:
                resp.close()
                selector.report_failure(picked)
                # Never serve a body that does not match the CTR counter.
                self._send_upstream_error(502, "Upstream ignored the requested range", exc)
                return None
            selector.report_success(picked)
            return resp
        self.send_error(502, "Upstream CDN URL expired")
        return None


class StreamingServer(ThreadingHTTPServer):
    """Threaded HTTP server with a single configured MEGA source."""

    def __init__(
        self,
        api,
        host: str = "127.0.0.1",
        port: int = 8080,
        selector=None,  # ProxySelector | None
        auth_token: str | None = None,
        allow_query_token: bool = False,
        max_connections: int = DEFAULT_MAX_CONNECTIONS,
        max_connections_per_client: int = DEFAULT_MAX_CONNECTIONS_PER_CLIENT,
        handler_timeout: float = DEFAULT_HANDLER_TIMEOUT,
        header_timeout: float = DEFAULT_HEADER_TIMEOUT,
    ):
        # Must be set before super().__init__(): that is where the socket is
        # created. AF_INET was hardcoded, so an IPv6 bind could never work.
        self.address_family = address_family_for_host(host)
        super().__init__((host.strip().strip("[]"), port), _StreamingRequestHandler)
        self.api = api
        self.source: _StreamSource | None = None
        # One unbounded thread per connection was a trivial DoS. Past the cap
        # a connection is answered with 503 and closed instead of queued.
        self.max_connections = max_connections
        self._slots = threading.BoundedSemaphore(max_connections)
        self._reject_slots = threading.BoundedSemaphore(_MAX_REJECT_THREADS)
        # The global cap alone still lets one address take every slot, which
        # starves every other client. This inner cap keeps one peer to a share
        # of the pool. The map holds one entry per LIVE connection and the key
        # is dropped at zero, so it is bounded by max_connections, not by the
        # number of addresses ever seen.
        self.max_connections_per_client = max_connections_per_client
        self._peer_lock = threading.Lock()
        self._peer_counts: dict[str, int] = {}
        # Client sockets were fully blocking: socketserver only calls
        # settimeout() when the handler's `timeout` attribute is non-None.
        self.handler_timeout = handler_timeout
        self.header_timeout = header_timeout
        # Every upstream request selects its proxies here, so force mode is
        # enforced on the CDN path too (it used to pass proxies=None).
        self.selector = selector if selector is not None else ProxySelector()
        # When set, every request (GET/HEAD, including Range) must present this
        # token. Required for non-loopback binds; None means no authentication.
        self.auth_token = auth_token
        # Bearer header is always accepted; query-string tokens only when this
        # is explicitly enabled (they leak into logs/history).
        self.allow_query_token = allow_query_token

    def _acquire_peer(self, client_address) -> bool:
        """Claim one per-address slot, or return False when that peer is full."""
        peer = client_address[0] if client_address else ""
        with self._peer_lock:
            held = self._peer_counts.get(peer, 0)
            if held >= self.max_connections_per_client:
                return False
            self._peer_counts[peer] = held + 1
        return True

    def _release_peer(self, client_address) -> None:
        """Give the slot back and forget the address once it holds none.

        Dropping the key at zero is what keeps the map bounded, and is also why
        every exit path must reach here: a count left behind would lock that
        client out permanently, which is worse than the exhaustion it prevents.
        """
        peer = client_address[0] if client_address else ""
        with self._peer_lock:
            remaining = self._peer_counts.get(peer, 0) - 1
            if remaining > 0:
                self._peer_counts[peer] = remaining
            else:
                self._peer_counts.pop(peer, None)

    def process_request(self, request, client_address) -> None:
        """Serve only while a global and a per-address slot are free."""
        if not self._slots.acquire(blocking=False):
            self._reject_over_capacity(request, f"global cap of {self.max_connections}")
            return
        if not self._acquire_peer(client_address):
            self._slots.release()
            self._reject_over_capacity(
                request, f"per-client cap of {self.max_connections_per_client}"
            )
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            # The handler thread never started, so its finally never runs.
            self._release_peer(client_address)
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            # Covers every handler exit: normal, timeout, and exception.
            self._release_peer(client_address)
            self._slots.release()

    def _reject_over_capacity(self, request, reason: str) -> None:
        """Refuse a connection without ever blocking the accept loop.

        Once the cap is reached the refusal becomes the hot path (a flood hits
        it on every connection), so it may not linger here. It is handed to a
        small, capped pool of short-lived closers instead; past that the socket
        is dropped outright, which is the right answer deep in a flood.
        """
        log.warning("Streaming %s reached; rejecting connection", reason)
        if not self._reject_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            threading.Thread(target=self._refuse, args=(request,), daemon=True).start()
        except RuntimeError:  # out of threads: drop rather than leak the slot
            self._reject_slots.release()
            self.shutdown_request(request)

    def _refuse(self, request) -> None:
        """Write the 503 and close gracefully.

        Closing while the peer's request bytes are still unread makes the OS
        answer with an RST, which discards the 503 the client has not read
        yet - so the refusal has to linger briefly for the peer's FIN.
        """
        try:
            request.settimeout(_REJECT_LINGER)
            request.sendall(_OVER_CAPACITY_RESPONSE)
            request.shutdown(socket.SHUT_WR)
            deadline = time.monotonic() + _REJECT_LINGER
            while time.monotonic() < deadline and request.recv(65536):
                pass  # drain until FIN so the close is graceful, never forever
        except OSError:
            pass  # peer went away; nothing left to deliver
        finally:
            self.shutdown_request(request)
            self._reject_slots.release()

    def set_source(self, url: str, password: str | None = None) -> None:
        self.source = _StreamSource(url, self.api, password=password, selector=self.selector)

    def serve_forever_in_thread(self) -> threading.Thread:
        t = threading.Thread(target=self.serve_forever, daemon=True)
        t.start()
        return t
