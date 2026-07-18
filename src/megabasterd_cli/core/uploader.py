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

import hashlib
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

from ..utils.helpers import sanitize_filename
from ..utils.speed import RollingSpeedMeter, make_limiter
from .chunks import Chunk, chunk_mac, combine_chunk_macs, condense_mac, iter_chunks
from .crypto import (
    a32_to_bytes,
    aes_key_wrap_encrypt,
    b64_url_encode,
    ctr_offset_to_counter,
    encrypt_attributes,
    make_ctr_cipher,
    pack_file_key,
)
from .errors import TransferError
from .state import TransferState, clear_state, load_state, save_state, snapshot_state

log = logging.getLogger(__name__)

UPLOAD_URL_EXPIRY_STATUS = {403, 404, 410, 509}

# Versioned identity of the local source file stored in upload resume state.
# v2 uses a FULL streaming SHA-256 of the content plus path/size/mtime_ns and
# the platform file id, so resume/finalization detects any byte change
# anywhere in the file. v1 (a sampled head/middle/tail fingerprint) is never
# treated as a strict identity: v1 or missing identities restart fresh.
SOURCE_IDENTITY_VERSION = 2
_HASH_BLOCK = 1024 * 1024  # Streaming hash block size (bounded memory).
_HASH_LOG_THRESHOLD = 256 * 1024 * 1024  # Log hashing cost above this size.


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


class UploadUrlExpiredError(Exception):
    """Raised when an upload slot is no longer usable and must be refreshed."""


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
        limiter=None,  # Shared TokenBucket/NoOpLimiter for aggregate command caps
        auto_resume: bool = True,
        user_agent: str | None = None,
    ):
        from .api import default_user_agent

        if client.session is None:
            raise RuntimeError("Uploader requires an authenticated MegaClient")
        self.client = client
        self.api = client.api
        self.max_workers = max(1, max_workers)
        self.timeout = timeout
        self.proxies = proxies
        self.proxy_pool = proxy_pool
        self.force_proxy = force_proxy
        # A supplied limiter is shared across every parallel upload of one
        # command, making `speed_limit_kbps` an aggregate cap.
        self.limiter = limiter if limiter is not None else make_limiter(speed_limit_kbps)
        self.auto_resume = auto_resume
        self.user_agent = user_agent or default_user_agent()
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._bytes_done = 0
        self._chunks_done = 0
        self._start_time = 0.0
        # Rolling window meter, mirroring the downloader: reports the CURRENT
        # rate; the first sample is the resumed-bytes baseline, so resumed
        # chunks never inflate the reported speed.
        self._speed_meter = RollingSpeedMeter(window=5.0)
        self._completion_token: bytes | None = None
        self.last_directory_failures: list[str] = []

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

    def _reset_per_file_state(self) -> None:
        """Clear every per-file mutable field so a prior file (failed, canceled,
        or completed) cannot leak state into the next `upload_file()`."""
        self._stop_event.clear()
        with self._lock:
            self._bytes_done = 0
            self._chunks_done = 0
            self._completion_token = None
            self._speed_meter = RollingSpeedMeter(window=5.0)

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
        # Reset ALL per-file mutable state at the safe start of every upload,
        # BEFORE hashing. `upload_directory(keep_going=True)` reuses one
        # uploader for every file, so a previous file that set `_stop_event`
        # (or left a completion token / progress counters) must never poison
        # the next file — e.g. hashing the next source would otherwise abort
        # immediately with "canceled while hashing". `stop()` still cancels
        # the file that is currently active.
        self._reset_per_file_state()
        # Operation clock starts here, once, and is never reset by upload-slot
        # refreshes/retries; the result elapsed covers every phase including
        # finalization.
        op_start = time.monotonic()
        self._start_time = op_start
        file_size = source.stat().st_size
        upload_name = sanitize_filename(rename_to or source.name)
        target = target_handle or self.client.find_root()
        if not target:
            raise TransferError(message="No upload target available")

        # Generate file encryption material first; if resuming, this is overridden
        aes_key = os.urandom(16)
        nonce = os.urandom(8)
        upload_url: str | None = None

        source_identity = self._source_identity(source, self._stop_event)

        if file_size == 0:
            # Zero-byte files have no chunks and therefore no chunk-response
            # completion token; MEGA's protocol uses a POST to `<url>/0` with
            # an empty body instead. The captured source identity is
            # revalidated before the remote node is registered.
            return self._upload_empty_file(
                source, upload_name, target, aes_key, nonce, on_progress, op_start, source_identity
            )

        # State for resume
        state_path = self._upload_state_destination(source)
        state = load_state(state_path) if self.auto_resume else None
        if state is not None and not self._is_resumable_upload_state(
            state, source, file_size, source_identity
        ):
            log.warning(
                "The local file %s changed since the interrupted upload "
                "(or the state predates source-identity tracking); the stale "
                "upload state cannot be reused and the upload restarts fresh.",
                source,
            )
            clear_state(state_path)
            state = None
        if state is not None:
            try:
                aes_key = bytes.fromhex(state.metadata["aes_key"])
                nonce = bytes.fromhex(state.metadata["nonce"])
                if len(aes_key) != 16 or len(nonce) != 8:
                    raise ValueError("Invalid upload encryption material in state file")
                upload_url = state.metadata["upload_url"]
                token_hex = state.metadata.get("completion_token")
                self._completion_token = bytes.fromhex(token_hex) if token_hex else None
            except (KeyError, ValueError):
                clear_state(state_path)
                state = None

        if state is None:
            # Request a fresh upload slot
            upload_info = self.api.request_upload(file_size)
            upload_url = upload_info["p"]
            self._completion_token = None
            state = TransferState(
                transfer_type="upload",
                source=str(source),
                destination=str(state_path),
                total_size=file_size,
                metadata={
                    "upload_url": upload_url,
                    "aes_key": aes_key.hex(),
                    "nonce": nonce.hex(),
                    "source_identity": source_identity,
                },
            )

        all_chunks = list(iter_chunks(file_size))
        refreshed_upload_url = False

        log.info(
            "Uploading %s (%d bytes, %d chunks, %d already done)",
            source.name,
            file_size,
            len(all_chunks),
            sum(1 for c in all_chunks if state.is_chunk_done(c.index)),
        )

        # Progress ticker, mirroring the downloader: report on a steady clock
        # instead of once per completed future in submission order (which
        # arrives in late bursts), with the rolling meter's CURRENT rate (the
        # old ``bytes_done / total_elapsed`` was a lifetime average whose
        # pre-seeded resumed bytes wildly overstated speed after resume).
        progress_stop = threading.Event()

        def _emit_progress() -> None:
            if on_progress is None:
                return
            with self._lock:
                bytes_done, chunks_done = self._bytes_done, self._chunks_done
            on_progress(
                UploadProgress(
                    bytes_done=bytes_done,
                    total_bytes=file_size,
                    chunks_done=chunks_done,
                    total_chunks=len(all_chunks),
                    speed_bps=self._speed_meter.current(),
                )
            )

        def _progress_loop() -> None:
            while not progress_stop.wait(0.5):
                try:
                    _emit_progress()
                except Exception:
                    log.debug("Upload progress callback raised", exc_info=True)

        reporter: threading.Thread | None = None
        if on_progress:
            reporter = threading.Thread(
                target=_progress_loop, name="mega-upload-progress", daemon=True
            )
            reporter.start()

        try:
            while True:
                pending = [c for c in all_chunks if not state.is_chunk_done(c.index)]
                self._bytes_done = sum(c.size for c in all_chunks if state.is_chunk_done(c.index))
                self._chunks_done = len(all_chunks) - len(pending)
                self._stop_event.clear()
                # Fresh meter per attempt; the baseline sample is the resumed
                # byte count, so speed measures only NEW bytes this session.
                self._speed_meter = RollingSpeedMeter(window=5.0)
                self._speed_meter.update(self._bytes_done)

                try:
                    # Spawn uploader workers
                    with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
                        futures = []
                        for chunk in pending:
                            if self._stop_event.is_set():
                                break
                            fut = pool.submit(
                                self._upload_chunk,
                                upload_url,
                                source,
                                chunk,
                                aes_key,
                                nonce,
                                state,
                                len(all_chunks),
                            )
                            futures.append((chunk, fut))

                        for chunk, fut in futures:
                            try:
                                fut.result()
                            except UploadUrlExpiredError:
                                self._stop_event.set()
                                raise
                            except Exception as e:
                                self._stop_event.set()
                                with self._lock:
                                    state_to_save = snapshot_state(state)
                                save_state(state_to_save)
                                raise TransferError(
                                    message=f"Upload chunk {chunk.index} failed: {e}"
                                ) from e
                    break
                except UploadUrlExpiredError as exc:
                    if refreshed_upload_url:
                        with self._lock:
                            state_to_save = snapshot_state(state)
                        save_state(state_to_save)
                        raise TransferError(
                            message=(
                                "Upload URL expired after refresh. Delete the upload state file "
                                f"and retry if the problem repeats: {state_path}"
                            )
                        ) from exc
                    refreshed_upload_url = True
                    upload_info = self.api.request_upload(file_size)
                    upload_url = upload_info["p"]
                    state.metadata["upload_url"] = upload_url
                    state.metadata.pop("completion_token", None)
                    state.completed_chunks.clear()
                    state.chunk_macs.clear()
                    self._completion_token = None
                    with self._lock:
                        state_to_save = snapshot_state(state)
                    save_state(state_to_save)
                    log.info("Upload URL expired; requested a fresh upload slot")
                    continue
        finally:
            progress_stop.set()
            if reporter is not None:
                reporter.join(timeout=2.0)

        if on_progress:
            # Final synchronous report so the consumer sees 100% of the bytes.
            try:
                _emit_progress()
            except Exception:
                log.debug("Final upload progress callback raised", exc_info=True)

        if self._completion_token is None:
            raise TransferError(message="Upload finished without a completion token")

        # Re-check the source identity before finalization: if the local file
        # was modified/replaced during the transfer, the uploaded chunks are a
        # mix of old and new content and must never be registered. The full
        # streaming hash detects a change to ANY byte of the file.
        try:
            current_identity = self._source_identity(source, self._stop_event)
        except OSError as exc:
            clear_state(state_path)
            raise TransferError(
                message=f"Local file disappeared during upload: {source} ({exc})"
            ) from exc
        if not self._identities_match(source_identity, current_identity):
            clear_state(state_path)
            raise TransferError(
                message=(
                    f"The local file changed while it was being uploaded: {source}. "
                    "The partial upload was discarded; retry to upload the new content."
                )
            )

        # Build file MAC and wrapped key
        chunk_macs = [state.get_chunk_mac(c.index) for c in all_chunks]
        if any(m is None for m in chunk_macs):
            raise TransferError(message="Missing chunk MAC after upload")
        file_mac = combine_chunk_macs(chunk_macs, aes_key)
        mac_iv = condense_mac(file_mac)
        file_handle = self._register_node(
            upload_name, target, aes_key, nonce, mac_iv, self._completion_token
        )
        clear_state(state_path)

        return UploadResult(
            file_handle=file_handle,
            name=upload_name,
            size=file_size,
            elapsed_seconds=time.monotonic() - op_start,
        )

    def _register_node(
        self,
        upload_name: str,
        target: str,
        aes_key: bytes,
        nonce: bytes,
        mac_iv: list[int],
        completion_token: bytes,
    ) -> str:
        """Encrypt attributes, wrap the file key, and register the new node."""
        file_key_a32 = pack_file_key(aes_key, nonce, mac_iv)

        # Encrypt attributes (filename, with AES-CBC) and wrap the 32-byte
        # file key with the master key (KEY-WRAP mode, not chained CBC).
        encrypted_attrs = encrypt_attributes({"n": upload_name}, aes_key)
        wrapped_key = aes_key_wrap_encrypt(
            a32_to_bytes(file_key_a32),
            self.client.session.master_key,
        )

        result = self.api.complete_upload(
            target_handle=target,
            upload_token=b64_url_encode(completion_token),
            encrypted_attrs=b64_url_encode(encrypted_attrs),
            wrapped_key=b64_url_encode(wrapped_key),
        )
        self.client.invalidate_cache()

        nodes = result.get("f", []) if isinstance(result, dict) else []
        return nodes[0]["h"] if nodes else completion_token.hex()

    def _upload_empty_file(
        self,
        source: Path,
        upload_name: str,
        target: str,
        aes_key: bytes,
        nonce: bytes,
        on_progress: Callable[[UploadProgress], None] | None,
        op_start: float,
        source_identity: dict,
    ) -> UploadResult:
        """Upload a zero-byte file.

        MEGA still requires an upload slot; the completion token comes from a
        single POST of an empty body to `<upload_url>/0` (the same convention
        mega.py and the SDKs use). The file MAC of an empty file condenses to
        [0, 0] because there are no chunk MACs to combine. The source identity
        captured at start is revalidated after the completion token arrives
        and before the node is registered, so a file that changed, grew, was
        replaced, or disappeared mid-flight is never registered.
        """
        upload_info = self.api.request_upload(0)
        upload_url = upload_info["p"]
        token: bytes | None = None
        for attempt in range(2):
            request_proxies, picked_proxy = self._proxies_for_request()
            try:
                resp = requests.post(
                    f"{upload_url}/0",
                    data=b"",
                    timeout=self.timeout,
                    proxies=request_proxies,
                    headers={"User-Agent": self.user_agent},
                )
            except (requests.ConnectionError, requests.Timeout):
                if picked_proxy and self.proxy_pool is not None:
                    self.proxy_pool.report_failure(picked_proxy)
                raise
            status, body = resp.status_code, resp.content
            resp.close()
            if status in UPLOAD_URL_EXPIRY_STATUS and attempt == 0:
                upload_info = self.api.request_upload(0)
                upload_url = upload_info["p"]
                continue
            if status != 200:
                if picked_proxy and self.proxy_pool is not None:
                    self.proxy_pool.report_failure(picked_proxy)
                raise TransferError(message=f"Zero-byte upload HTTP {status}")
            if picked_proxy and self.proxy_pool is not None:
                self.proxy_pool.report_success(picked_proxy)
            token = body
            break
        if not token:
            raise TransferError(message="Zero-byte upload returned no completion token")

        # Revalidate the source AFTER the completion token and BEFORE node
        # registration: never register a node for a file that changed.
        try:
            current_identity = self._source_identity(source, self._stop_event)
        except OSError as exc:
            raise TransferError(
                message=f"Local file disappeared during zero-byte upload: {source} ({exc})"
            ) from exc
        if current_identity.get("size") != 0 or not self._identities_match(
            source_identity, current_identity
        ):
            raise TransferError(
                message=(
                    f"The local file changed while it was being uploaded: {source}. "
                    "The zero-byte upload was not registered; retry to upload the new content."
                )
            )

        mac_iv = condense_mac(combine_chunk_macs([], aes_key))
        file_handle = self._register_node(upload_name, target, aes_key, nonce, mac_iv, token)

        if on_progress:
            try:
                on_progress(
                    UploadProgress(
                        bytes_done=0, total_bytes=0, chunks_done=0, total_chunks=0, speed_bps=0.0
                    )
                )
            except Exception:
                log.debug("Zero-byte upload progress callback raised", exc_info=True)

        return UploadResult(
            file_handle=file_handle,
            name=upload_name,
            size=0,
            elapsed_seconds=time.monotonic() - op_start,
        )

    @staticmethod
    def _upload_state_destination(source: Path) -> Path:
        from ..config import data_dir

        identity = f"{source.resolve()}|{source.stat().st_size}".encode("utf-8", errors="replace")
        digest = hashlib.sha256(identity).hexdigest()[:24]
        return data_dir() / "upload-state" / f"{sanitize_filename(source.name)}.{digest}.upload"

    @staticmethod
    def _file_sha256(source: Path, size: int, stop_event: threading.Event | None = None) -> str:
        """Full streaming SHA-256 of the file content in bounded memory.

        Reads fixed-size blocks (never the whole file), stays responsive to
        `stop()` cancellation, and logs the cost for very large files so the
        hashing phase is visible.
        """
        if size >= _HASH_LOG_THRESHOLD:
            log.info(
                "Computing full-file hash of %s (%d bytes) for resume identity...",
                source.name,
                size,
            )
        h = hashlib.sha256()
        with open(source, "rb") as f:
            while True:
                if stop_event is not None and stop_event.is_set():
                    raise TransferError(message="Upload canceled while hashing the source file")
                block = f.read(_HASH_BLOCK)
                if not block:
                    break
                h.update(block)
        return h.hexdigest()

    @classmethod
    def _source_identity(cls, source: Path, stop_event: threading.Event | None = None) -> dict:
        """Snapshot the properties that must be unchanged to resume/finalize."""
        st = source.stat()
        identity: dict = {
            "v": SOURCE_IDENTITY_VERSION,
            "path": str(source.resolve()),
            "size": st.st_size,
            "mtime_ns": st.st_mtime_ns,
            "sha256": cls._file_sha256(source, st.st_size, stop_event),
        }
        # Platform file identity (inode / NTFS file index) when available.
        if getattr(st, "st_ino", 0):
            identity["file_id"] = f"{getattr(st, 'st_dev', 0)}:{st.st_ino}"
        return identity

    @staticmethod
    def _identities_match(recorded: dict | None, current: dict) -> bool:
        if not isinstance(recorded, dict):
            return False
        if recorded.get("v") != SOURCE_IDENTITY_VERSION:
            # v1 sampled fingerprints (or unknown versions) are NOT a strict
            # identity; never treat them as proof of an unchanged file.
            return False
        for field in ("path", "size", "mtime_ns", "sha256"):
            if recorded.get(field) != current.get(field):
                return False
        # Compare the platform file id only when both sides recorded one.
        recorded_id, current_id = recorded.get("file_id"), current.get("file_id")
        return not (recorded_id and current_id and recorded_id != current_id)

    def _is_resumable_upload_state(
        self, state: TransferState, source: Path, file_size: int, identity: dict
    ) -> bool:
        """Resume only when the state provably belongs to this exact file."""
        if state.transfer_type != "upload":
            return False
        if state.total_size != file_size or state.source != str(source):
            return False
        return self._identities_match((state.metadata or {}).get("source_identity"), identity)

    def upload_directory(
        self,
        source_dir: Path,
        target_handle: str | None = None,
        on_progress: Callable[[UploadProgress], None] | None = None,
        on_file_done: Callable[[UploadResult, Path], None] | None = None,
        keep_going: bool = False,
        on_manifest: Callable[[list[tuple[Path, int]]], None] | None = None,
        on_file_progress: Callable[[Path, UploadProgress], None] | None = None,
    ) -> list[UploadResult]:
        """Upload an entire local directory tree, preserving structure.

        Creates remote folders as needed and uploads each file in place.
        `on_manifest` receives the complete `(path, size)` file list before any
        byte is uploaded; `on_file_progress` identifies which file a progress
        report belongs to. Remote directory creation is not part of the byte
        totals.
        """
        self.last_directory_failures = []
        if not source_dir.is_dir():
            raise FileNotFoundError(f"Not a directory: {source_dir}")

        # Complete file manifest first: total files and bytes are known before
        # any upload starts.
        entries = sorted(source_dir.rglob("*"))
        if on_manifest:
            on_manifest([(p, p.stat().st_size) for p in entries if p.is_file()])

        base_parent = target_handle or self.client.find_root()
        if not base_parent:
            raise TransferError(message="No target folder available")

        # Map local Path → remote handle
        handle_for: dict[Path, str] = {source_dir: base_parent}
        # Create the root remote folder
        root_handle = self.client.mkdir(source_dir.name, parent_handle=base_parent)
        handle_for[source_dir] = root_handle

        results: list[UploadResult] = []
        failures: list[str] = []
        failed_dirs: set[Path] = set()
        for local_path in entries:
            if any(parent in failed_dirs for parent in local_path.parents):
                failures.append(f"{local_path}: parent folder creation failed")
                continue
            try:
                if local_path.is_dir():
                    parent_remote = handle_for.get(local_path.parent, root_handle)
                    handle_for[local_path] = self.client.mkdir(
                        local_path.name, parent_handle=parent_remote
                    )
                elif local_path.is_file():
                    parent_remote = handle_for.get(local_path.parent, root_handle)

                    def _file_progress(p: UploadProgress, fp: Path = local_path) -> None:
                        if on_file_progress:
                            on_file_progress(fp, p)
                        if on_progress:
                            on_progress(p)

                    result = self.upload_file(
                        local_path,
                        target_handle=parent_remote,
                        on_progress=(_file_progress if (on_file_progress or on_progress) else None),
                    )
                    results.append(result)
                    if on_file_done:
                        on_file_done(result, local_path)
            except Exception as exc:  # noqa: BLE001
                log.error("Failed to upload %s: %s", local_path, exc)
                failures.append(f"{local_path}: {exc}")
                if local_path.is_dir():
                    failed_dirs.add(local_path)

        self.last_directory_failures = list(failures)
        if failures and not keep_going:
            sample = "; ".join(failures[:3])
            more = "" if len(failures) <= 3 else f"; and {len(failures) - 3} more"
            raise TransferError(message=f"{len(failures)} upload item(s) failed: {sample}{more}")

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
            raise TransferError(message=f"Local chunk {chunk.index} short read")

        # Compute MAC on plaintext
        mac = chunk_mac(plaintext, aes_key, nonce)

        # Encrypt with AES-CTR
        cipher = make_ctr_cipher(
            aes_key,
            nonce,
            initial_value=ctr_offset_to_counter(chunk.offset),
        )
        encrypted = cipher.encrypt(plaintext)

        self.limiter.consume(len(encrypted))

        put_url = f"{upload_url}/{chunk.offset}"
        request_proxies, picked_proxy = self._proxies_for_request()
        try:
            resp = requests.post(
                put_url,
                data=encrypted,
                timeout=self.timeout,
                proxies=request_proxies,
                headers={"User-Agent": self.user_agent},
            )
        except (requests.ConnectionError, requests.Timeout):
            if picked_proxy and self.proxy_pool is not None:
                self.proxy_pool.report_failure(picked_proxy)
            raise
        if resp.status_code in UPLOAD_URL_EXPIRY_STATUS:
            resp.close()
            raise UploadUrlExpiredError(f"Upload URL expired on chunk {chunk.index}")
        if resp.status_code != 200:
            if picked_proxy and self.proxy_pool is not None:
                self.proxy_pool.report_failure(picked_proxy)
            resp.close()
            raise TransferError(message=f"Upload chunk {chunk.index} HTTP {resp.status_code}")
        if picked_proxy and self.proxy_pool is not None:
            self.proxy_pool.report_success(picked_proxy)

        # The MEGA upload endpoint returns a non-empty body ONLY for the
        # chunk that contains the last byte of the file — this is the
        # completion token used to finalise the upload. Save it whenever
        # we see a non-empty body, regardless of which worker finishes
        # last; otherwise a race between the offset-final chunk and any
        # earlier chunk causes the token to be dropped.
        body = resp.content
        resp.close()
        with self._lock:
            state.mark_chunk_done(chunk.index, mac)
            self._bytes_done += chunk.size
            self._chunks_done += 1
            bytes_done_now = self._bytes_done
            if body:
                self._completion_token = body
                state.metadata["completion_token"] = body.hex()
            should_save = self._chunks_done % 8 == 0 or bool(body)
            state_to_save = snapshot_state(state) if should_save else None
        # Feed the rolling meter outside the state lock (it has its own).
        self._speed_meter.update(bytes_done_now)
        if should_save:
            save_state(state_to_save)
