"""Multi-threaded MEGA file uploader.

Uploading a file to MEGA:
1. Request an upload URL slot from the API (gives a base URL).
2. Generate a random 16-byte AES key and 8-byte nonce for the file.
3. Split the local file into MEGA-style chunks.
4. Encrypt each chunk with AES-CTR, compute its CBC-MAC, and POST it to
   `<upload_url>/<chunk_offset>` in parallel.
5. The final chunk's response contains the completion token.
6. Combine chunk MACs into the file MAC, build the 32-byte file key, encrypt
   attributes (filename), wrap the key with the master key, and call `a:p`
   to create the node.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import requests
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from .chunks import Chunk, chunk_mac, combine_chunk_macs, condense_mac, iter_chunks
from .crypto import (
    a32_to_bytes,
    aes_key_wrap_encrypt,
    b64_url_encode,
    encrypt_attributes,
    make_ctr_cipher,
    ctr_offset_to_counter,
    pack_file_key,
)
from .errors import TransferError
from .state import TransferState, clear_state, load_state, save_state
from ..utils.helpers import sanitize_filename
from ..utils.speed import make_limiter

log = logging.getLogger(__name__)


@dataclass
class UploadProgress:
    bytes_done: int
    total_bytes: int
    chunks_done: int
    total_chunks: int
    speed_bps: float


@dataclass
class UploadResult:
    file_handle: str
    name: str
    size: int
    elapsed_seconds: float
    public_link: str | None = None


class MegaUploader:
    """Multi-threaded uploader for one file."""

    def __init__(
        self,
        client,  # MegaClient
        max_workers: int = 4,
        speed_limit_kbps: float = 0,
        timeout: int = 60,
        proxies: dict[str, str] | None = None,
        proxy_pool=None,  # SmartProxyPool | None
        force_proxy: bool = False,
    ):
        if client.session is None:
            raise RuntimeError("Uploader requires an authenticated MegaClient")
        self.client = client
        self.api = client.api
        self.max_workers = max(1, max_workers)
        self.timeout = timeout
        self.proxies = proxies
        self.proxy_pool = proxy_pool
        self.force_proxy = force_proxy
        self.limiter = make_limiter(speed_limit_kbps)
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._bytes_done = 0
        self._chunks_done = 0
        self._start_time = 0.0
        self._completion_token: bytes | None = None

    def _proxies_for_request(self) -> tuple[dict[str, str] | None, str | None]:
        """Same precedence as MegaDownloader: pool, then static, then force/direct."""
        if self.proxy_pool is not None:
            entry = self.proxy_pool.pick()
            if entry is not None:
                proxy_url = entry.url
                return {"http": proxy_url, "https": proxy_url}, proxy_url
        if self.proxies:
            return self.proxies, None
        if self.force_proxy:
            raise TransferError(
                message="force_smart_proxy is on but no proxy is available "
                        "(pool empty, no --proxy)"
            )
        return None, None

    def stop(self) -> None:
        self._stop_event.set()

    def upload_file(
        self,
        source: Path,
        target_handle: str | None = None,
        rename_to: str | None = None,
        on_progress: Callable[[UploadProgress], None] | None = None,
    ) -> UploadResult:
        """Upload `source` into the user's MEGA tree under `target_handle`.

        If `target_handle` is None, uploads into the user's root.
        """
        if not source.is_file():
            raise FileNotFoundError(f"Not a file: {source}")
        file_size = source.stat().st_size
        upload_name = sanitize_filename(rename_to or source.name)
        target = target_handle or self.client.find_root()
        if not target:
            raise TransferError(message="No upload target available")

        # Generate file encryption material first; if resuming, this is overridden
        aes_key = os.urandom(16)
        nonce = os.urandom(8)
        upload_url: str | None = None

        # State for resume
        state_path = source.with_suffix(source.suffix + ".upload")
        state = load_state(state_path)
        if state is not None and state.total_size == file_size:
            try:
                aes_key = bytes.fromhex(state.metadata["aes_key"])
                nonce = bytes.fromhex(state.metadata["nonce"])
                upload_url = state.metadata["upload_url"]
            except (KeyError, ValueError):
                state = None

        if state is None:
            # Request a fresh upload slot
            upload_info = self.api.request_upload(file_size)
            upload_url = upload_info["p"]
            state = TransferState(
                transfer_type="upload",
                source=str(source),
                destination=str(state_path),
                total_size=file_size,
                metadata={
                    "upload_url": upload_url,
                    "aes_key": aes_key.hex(),
                    "nonce": nonce.hex(),
                },
            )

        all_chunks = list(iter_chunks(file_size))
        pending = [c for c in all_chunks if not state.is_chunk_done(c.index)]

        self._bytes_done = sum(c.size for c in all_chunks if state.is_chunk_done(c.index))
        self._chunks_done = len(all_chunks) - len(pending)
        self._start_time = time.monotonic()
        self._stop_event.clear()
        self._completion_token = None

        log.info(
            "Uploading %s (%d bytes, %d chunks, %d already done)",
            source.name, file_size, len(all_chunks), self._chunks_done,
        )

        # Spawn uploader workers
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = []
            for chunk in pending:
                if self._stop_event.is_set():
                    break
                fut = pool.submit(
                    self._upload_chunk, upload_url, source, chunk, aes_key, nonce, state,
                    len(all_chunks),
                )
                futures.append((chunk, fut))

            for chunk, fut in futures:
                try:
                    fut.result()
                except Exception as e:
                    self._stop_event.set()
                    raise TransferError(message=f"Upload chunk {chunk.index} failed: {e}") from e
                if on_progress:
                    elapsed = time.monotonic() - self._start_time
                    speed = self._bytes_done / elapsed if elapsed > 0 else 0
                    on_progress(UploadProgress(
                        bytes_done=self._bytes_done,
                        total_bytes=file_size,
                        chunks_done=self._chunks_done,
                        total_chunks=len(all_chunks),
                        speed_bps=speed,
                    ))

        if self._completion_token is None:
            raise TransferError(message="Upload finished without a completion token")

        # Build file MAC and wrapped key
        chunk_macs = [state.get_chunk_mac(c.index) for c in all_chunks]
        if any(m is None for m in chunk_macs):
            raise TransferError(message="Missing chunk MAC after upload")
        file_mac = combine_chunk_macs(chunk_macs, aes_key)
        mac_iv = condense_mac(file_mac)
        file_key_a32 = pack_file_key(aes_key, nonce, mac_iv)

        # Encrypt attributes (filename, with AES-CBC) and wrap the 32-byte
        # file key with the master key (KEY-WRAP mode, not chained CBC).
        encrypted_attrs = encrypt_attributes({"n": upload_name}, aes_key)
        wrapped_key = aes_key_wrap_encrypt(
            a32_to_bytes(file_key_a32), self.client.session.master_key,
        )

        # Register the new node
        result = self.api.complete_upload(
            target_handle=target,
            upload_token=b64_url_encode(self._completion_token),
            encrypted_attrs=b64_url_encode(encrypted_attrs),
            wrapped_key=b64_url_encode(wrapped_key),
        )

        nodes = result.get("f", []) if isinstance(result, dict) else []
        file_handle = nodes[0]["h"] if nodes else self._completion_token.hex()
        clear_state(state_path)

        elapsed = time.monotonic() - self._start_time
        return UploadResult(
            file_handle=file_handle, name=upload_name, size=file_size,
            elapsed_seconds=elapsed,
        )

    def upload_directory(
        self,
        source_dir: Path,
        target_handle: str | None = None,
        on_progress: Callable[[UploadProgress], None] | None = None,
        on_file_done: Callable[[UploadResult, Path], None] | None = None,
    ) -> list[UploadResult]:
        """Upload an entire local directory tree, preserving structure.

        Creates remote folders as needed and uploads each file in place.
        """
        if not source_dir.is_dir():
            raise FileNotFoundError(f"Not a directory: {source_dir}")

        base_parent = target_handle or self.client.find_root()
        if not base_parent:
            raise TransferError(message="No target folder available")

        # Map local Path → remote handle
        handle_for: dict[Path, str] = {source_dir: base_parent}
        # Create the root remote folder
        root_handle = self.client.mkdir(source_dir.name, parent_handle=base_parent)
        handle_for[source_dir] = root_handle

        results: list[UploadResult] = []
        for local_path in sorted(source_dir.rglob("*")):
            try:
                if local_path.is_dir():
                    parent_remote = handle_for.get(local_path.parent, root_handle)
                    handle_for[local_path] = self.client.mkdir(
                        local_path.name, parent_handle=parent_remote
                    )
                elif local_path.is_file():
                    parent_remote = handle_for.get(local_path.parent, root_handle)
                    result = self.upload_file(
                        local_path,
                        target_handle=parent_remote,
                        on_progress=on_progress,
                    )
                    results.append(result)
                    if on_file_done:
                        on_file_done(result, local_path)
            except Exception as exc:  # noqa: BLE001
                log.error("Failed to upload %s: %s", local_path, exc)

        return results

    @retry(
        retry=retry_if_exception_type((requests.ConnectionError, requests.Timeout, TransferError)),
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=2, min=2, max=30),
        reraise=True,
    )
    def _upload_chunk(
        self,
        upload_url: str,
        source: Path,
        chunk: Chunk,
        aes_key: bytes,
        nonce: bytes,
        state: TransferState,
        total_chunks: int,
    ) -> None:
        """Read, encrypt, POST one chunk."""
        if self._stop_event.is_set():
            return

        with open(source, "rb") as f:
            f.seek(chunk.offset)
            plaintext = f.read(chunk.size)
        if len(plaintext) != chunk.size:
            raise TransferError(
                message=f"Local chunk {chunk.index} short read"
            )

        # Compute MAC on plaintext
        mac = chunk_mac(plaintext, aes_key, nonce)

        # Encrypt with AES-CTR
        cipher = make_ctr_cipher(
            aes_key, nonce, initial_value=ctr_offset_to_counter(chunk.offset),
        )
        encrypted = cipher.encrypt(plaintext)

        self.limiter.consume(len(encrypted))

        put_url = f"{upload_url}/{chunk.offset}"
        request_proxies, picked_proxy = self._proxies_for_request()
        try:
            resp = requests.post(
                put_url, data=encrypted, timeout=self.timeout,
                proxies=request_proxies,
            )
        except (requests.ConnectionError, requests.Timeout):
            if picked_proxy and self.proxy_pool is not None:
                self.proxy_pool.report_failure(picked_proxy)
            raise
        if resp.status_code != 200:
            if picked_proxy and self.proxy_pool is not None:
                self.proxy_pool.report_failure(picked_proxy)
            raise TransferError(
                message=f"Upload chunk {chunk.index} HTTP {resp.status_code}"
            )
        if picked_proxy and self.proxy_pool is not None:
            self.proxy_pool.report_success(picked_proxy)

        # The MEGA upload endpoint returns a non-empty body ONLY for the
        # chunk that contains the last byte of the file — this is the
        # completion token used to finalise the upload. Save it whenever
        # we see a non-empty body, regardless of which worker finishes
        # last; otherwise a race between the offset-final chunk and any
        # earlier chunk causes the token to be dropped.
        body = resp.content
        with self._lock:
            state.mark_chunk_done(chunk.index, mac)
            self._bytes_done += chunk.size
            self._chunks_done += 1
            if body:
                self._completion_token = body
            if self._chunks_done % 8 == 0:
                save_state(state)
