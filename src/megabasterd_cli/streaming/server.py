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

import hmac
import ipaddress
import logging
import mimetypes
import re
import threading
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
from ..proxy.selector import ProxyRequiredError, ProxySelector
from ..utils.helpers import sanitize_filename

log = logging.getLogger(__name__)

URL_EXPIRY_STATUS = {403, 410, 509}


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


class RangeNotHonoredError(Exception):
    """The upstream response does not match the requested byte range."""


# `bytes <start>-<end>/<total>`; a `*` in either position is not acceptable
# for a range we are about to decrypt at a specific counter.
_CONTENT_RANGE_RE = re.compile(r"^bytes\s+(\d+)\s*-\s*(\d+)\s*/\s*(\d+|\*)$", re.IGNORECASE)


def validate_range_response(status: int, headers, start: int, end: int, size: int) -> None:
    """Raise RangeNotHonored unless the body is exactly bytes `start`..`end`.

    A nonzero range decrypted with a nonzero AES-CTR counter is only correct
    if the server actually honored the range. A proxy or CDN that ignores
    `Range` and replies 200 with the whole body from byte 0 would otherwise
    produce garbage plaintext that looks like a successful stream.

    HTTP 200 is accepted for one case only: the request covers the whole file,
    where the counter starts at zero anyway.
    """
    wants_whole_file = start == 0 and end == size - 1
    if status == 200:
        if wants_whole_file:
            return
        raise RangeNotHonoredError(
            f"HTTP 200 (full body) for a partial request of bytes {start}-{end}"
        )
    if status != 206:
        raise RangeNotHonoredError(f"expected HTTP 206 for bytes {start}-{end}, got {status}")
    raw = headers.get("Content-Range")
    if not raw:
        raise RangeNotHonoredError("206 response without a Content-Range header")
    match = _CONTENT_RANGE_RE.match(str(raw).strip())
    if match is None:
        raise RangeNotHonoredError(f"unparsable Content-Range {raw!r}")
    got_start, got_end, total = int(match.group(1)), int(match.group(2)), match.group(3)
    if got_start != start or got_end != end:
        raise RangeNotHonoredError(
            f"Content-Range covers {got_start}-{got_end}, requested {start}-{end}"
        )
    if total != "*" and int(total) != size:
        raise RangeNotHonoredError(f"Content-Range total {total} does not match file size {size}")
    declared = headers.get("Content-Length")
    if declared is not None:
        try:
            declared_len = int(declared)
        except (TypeError, ValueError):
            raise RangeNotHonoredError(f"unparsable Content-Length {declared!r}") from None
        if declared_len != end - start + 1:
            raise RangeNotHonoredError(
                f"Content-Length {declared_len} does not match the {end - start + 1}-byte range"
            )


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
        from ..core.links import (
            LinkType,
            get_megacrypter_download_url,
            get_megacrypter_info,
            resolve_encrypted_container_link,
            resolve_megacrypter_link,
            resolve_password_link,
        )

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


class _StreamingRequestHandler(BaseHTTPRequestHandler):
    server: StreamingServer  # type: ignore[assignment]

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
        except (BrokenPipeError, ConnectionResetError):
            log.debug("Client disconnected")
        finally:
            resp.close()

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
                self.send_error(502, f"Upstream error: {exc}")
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
                self.send_error(502, f"Upstream error: {e}")
                return None
            if resp.status_code in URL_EXPIRY_STATUS and attempt == 0:
                resp.close()
                try:
                    source.refresh_cdn_url()
                except Exception as exc:  # noqa: BLE001
                    self.send_error(502, f"CDN URL refresh failed: {exc}")
                    return None
                continue
            if resp.status_code not in (200, 206):
                status = resp.status_code
                resp.close()
                selector.report_failure(picked)
                self.send_error(502, f"Upstream HTTP {status}")
                return None
            try:
                validate_range_response(resp.status_code, resp.headers, start, end, source.size)
            except RangeNotHonoredError as exc:
                resp.close()
                selector.report_failure(picked)
                # Never serve a body that does not match the CTR counter.
                self.send_error(502, f"Upstream ignored the requested range: {exc}")
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
    ):
        super().__init__((host, port), _StreamingRequestHandler)
        self.api = api
        self.source: _StreamSource | None = None
        # Every upstream request selects its proxies here, so force mode is
        # enforced on the CDN path too (it used to pass proxies=None).
        self.selector = selector if selector is not None else ProxySelector()
        # When set, every request (GET/HEAD, including Range) must present this
        # token. Required for non-loopback binds; None means no authentication.
        self.auth_token = auth_token
        # Bearer header is always accepted; query-string tokens only when this
        # is explicitly enabled (they leak into logs/history).
        self.allow_query_token = allow_query_token

    def set_source(self, url: str, password: str | None = None) -> None:
        self.source = _StreamSource(url, self.api, password=password, selector=self.selector)

    def serve_forever_in_thread(self) -> threading.Thread:
        t = threading.Thread(target=self.serve_forever, daemon=True)
        t.start()
        return t
