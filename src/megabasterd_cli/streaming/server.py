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

import logging
import mimetypes
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

import requests

from ..core.crypto import (
    b64_url_decode,
    decrypt_attributes,
    make_ctr_cipher,
    str_to_a32,
    unpack_file_key,
)
from ..core.links import parse_link
from ..utils.helpers import sanitize_filename

log = logging.getLogger(__name__)


class _StreamSource:
    """Resolved MEGA file ready to be streamed."""

    def __init__(self, url: str, api, password: str | None = None):
        from ..core.crypto import a32_to_bytes, aes_key_wrap_decrypt, bytes_to_a32
        from ..core.links import (
            LinkType,
            get_megacrypter_download_url,
            get_megacrypter_info,
            resolve_encrypted_container_link,
            resolve_megacrypter_link,
            resolve_password_link,
        )

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
                parsed = resolve_megacrypter_link(parsed, password=password)
            except ValueError:
                mc_info = get_megacrypter_info(parsed, password=password)
                if not mc_info.key or mc_info.size is None:
                    raise RuntimeError("MegaCrypter metadata is missing key or size")
                self.cdn_url = get_megacrypter_download_url(parsed, info=mc_info, password=password)
                self.size = mc_info.size
                self.aes_key, self.nonce, _ = unpack_file_key(str_to_a32(mc_info.key))
                self.filename = sanitize_filename(mc_info.name or parsed.crypter_token or "megacrypter")
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
                (n for n in listing.get("f", [])
                 if n.get("h") == file_handle and n.get("t") == 0),
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
            # The attribute blob lives on the listing node, not the get response.
            encrypted_attrs = b64_url_decode(file_raw.get("a", "") or "")
        else:
            info = api.get_public_file_info(parsed.public_id)
            if "g" not in info:
                raise RuntimeError(f"No CDN URL returned: {info}")
            key_a32 = str_to_a32(parsed.key)
            encrypted_attrs = b64_url_decode(info["at"])

        self.cdn_url: str = info["g"]
        self.size: int = int(info["s"])
        self.aes_key, self.nonce, _ = unpack_file_key(key_a32)
        attrs = decrypt_attributes(encrypted_attrs, self.aes_key) or {}
        self.filename = sanitize_filename(attrs.get("n") or parsed.public_id)
        self.mimetype = mimetypes.guess_type(self.filename)[0] or "application/octet-stream"


class _StreamingRequestHandler(BaseHTTPRequestHandler):
    server: "StreamingServer"  # type: ignore[assignment]

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        log.debug("HTTP: " + format, *args)

    def do_HEAD(self) -> None:  # noqa: N802
        source = self.server.source
        if not source:
            self.send_error(503, "No source configured")
            return
        self.send_response(200)
        self.send_header("Content-Type", source.mimetype)
        self.send_header("Content-Length", str(source.size))
        self.send_header("Accept-Ranges", "bytes")
        self.send_header(
            "Content-Disposition", f'inline; filename="{source.filename}"',
        )
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        source = self.server.source
        if not source:
            self.send_error(503, "No source configured")
            return

        # Parse Range header
        range_header = self.headers.get("Range", "")
        start, end = 0, source.size - 1
        is_partial = False
        if range_header.startswith("bytes="):
            try:
                spec = range_header.split("=", 1)[1].split("-", 1)
                if spec[0]:
                    start = int(spec[0])
                if spec[1]:
                    end = int(spec[1])
                is_partial = True
            except (IndexError, ValueError):
                self.send_error(400, "Malformed Range")
                return
        start = max(0, min(start, source.size - 1))
        end = max(start, min(end, source.size - 1))
        length = end - start + 1

        # Align CTR counter on 16-byte boundary
        block_start = (start // 16) * 16
        block_skip = start - block_start

        try:
            resp = requests.get(
                source.cdn_url,
                headers={"Range": f"bytes={block_start}-{end}"},
                stream=True, timeout=60,
                proxies=self.server.proxies,
            )
        except requests.RequestException as e:
            self.send_error(502, f"Upstream error: {e}")
            return
        if resp.status_code not in (200, 206):
            self.send_error(502, f"Upstream HTTP {resp.status_code}")
            return

        cipher = make_ctr_cipher(
            source.aes_key, source.nonce, initial_value=block_start // 16,
        )

        if is_partial:
            self.send_response(206)
            self.send_header("Content-Range", f"bytes {start}-{end}/{source.size}")
        else:
            self.send_response(200)
        self.send_header("Content-Type", source.mimetype)
        self.send_header("Content-Length", str(length))
        self.send_header("Accept-Ranges", "bytes")
        self.send_header(
            "Content-Disposition", f'inline; filename="{source.filename}"',
        )
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


class StreamingServer(ThreadingHTTPServer):
    """Threaded HTTP server with a single configured MEGA source."""

    def __init__(
        self,
        api,
        host: str = "127.0.0.1",
        port: int = 8080,
        proxies: dict[str, str] | None = None,
    ):
        super().__init__((host, port), _StreamingRequestHandler)
        self.api = api
        self.source: _StreamSource | None = None
        self.proxies = proxies

    def set_source(self, url: str, password: str | None = None) -> None:
        self.source = _StreamSource(url, self.api, password=password)

    def serve_forever_in_thread(self) -> threading.Thread:
        t = threading.Thread(target=self.serve_forever, daemon=True)
        t.start()
        return t
