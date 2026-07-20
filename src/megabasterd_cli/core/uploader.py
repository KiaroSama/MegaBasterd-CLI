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

import contextlib
import logging
import os
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

import requests

from ..proxy.selector import ProxySelector
from ..utils.helpers import sanitize_filename
from ..utils.speed import RollingSpeedMeter, make_limiter
from . import upload_identity as _identity
from . import upload_transport as _transport
from . import upload_tree as _tree
from .chunks import combine_chunk_macs, condense_mac, iter_chunks
from .crypto import (
    a32_to_bytes,
    aes_key_wrap_encrypt,
    b64_url_encode,
    encrypt_attributes,
    pack_file_key,
)
from .errors import MegaError, TransferError
from .progress_ticker import progress_ticker
from .responses import _expect_field, _expect_mapping
from .state import TransferState, clear_state, load_state, save_state, snapshot_state

log = logging.getLogger(__name__)

# --- Re-exports -----------------------------------------------------------
# This module stays THE entry point for uploads: every name that was ever
# importable from it still is, so existing imports and monkeypatch targets
# (including `uploader.requests`) keep working after the responsibility split.
walk_upload_entries = _tree.walk_upload_entries

UPLOAD_URL_EXPIRY_STATUS = _transport.UPLOAD_URL_EXPIRY_STATUS
MAX_UPLOAD_RESPONSE_BYTES = _transport.MAX_UPLOAD_RESPONSE_BYTES
UploadUrlExpiredError = _transport.UploadUrlExpiredError
_read_bounded_body = _transport.read_bounded_body
SOURCE_IDENTITY_VERSION = _identity.SOURCE_IDENTITY_VERSION
_HASH_BLOCK = _identity._HASH_BLOCK
_HASH_LOG_THRESHOLD = _identity._HASH_LOG_THRESHOLD


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


class UploadInProgressError(TransferError):
    """Another live process already owns this source's upload slot.

    Two processes uploading the same local file resolve to the SAME resume
    state and therefore to the same MEGA upload slot: they would trade
    `upload_url` values and completion tokens, and the last writer would win.
    Refusing is the safe policy - the user can retry once the other run ends.
    """


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
        limiter=None,  # Shared TokenBucket for aggregate command caps
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
        """Per-request proxy decision, delegated to the shared selector."""
        return ProxySelector(
            pool=self.proxy_pool, static=self.proxies, force=self.force_proxy
        ).select()

    def stop(self) -> None:
        self._stop_event.set()

    def _request_upload_url(self, size: int) -> str:
        """Request an upload slot and return its base URL, shape-checked.

        Every upload path (fresh slot, expiry refresh, zero-byte slot,
        zero-byte refresh) used to read `upload_info["p"]` unguarded, so a
        malformed or hostile `a:u` answer escaped as a raw `KeyError: 'p'` /
        `TypeError` and reached the user as `Error: 'p'`. Validating once,
        here, covers all four - the same discipline `core/responses.py`
        applies with these helpers and `core/api.py` applies in `_parse_body`.
        """
        what = "upload slot request"
        url = _expect_field(_expect_mapping(self.api.request_upload(size), what), "p", str, what)
        if not url:
            raise MegaError(message=f"Malformed MEGA response for {what}: 'p' is empty")
        return str(url)

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

        Holds a WHOLE-TRANSFER lease on the source for the duration: see
        `_upload_lease`. Without it two processes uploading the same file share
        one resume state and one upload slot.
        """
        if not source.is_file():
            raise FileNotFoundError(f"Not a file: {source}")
        with self._upload_lease(source):
            return self._upload_file_locked(source, target_handle, rename_to, on_progress)

    @contextlib.contextmanager
    def _upload_lease(self, source: Path):
        """Own this source's upload for the whole transfer, across processes.

        The lease is an advisory lock on a sidecar beside the resume state, so
        the OS releases it if this process dies - a crashed owner never blocks
        a later retry, and no stale-lease heuristic is needed. A second LIVE
        process is refused rather than allowed to interleave slot refreshes and
        completion tokens with ours.

        The sidecar file is never unlinked: removing it would let a third
        process create a new inode and acquire a second, independent lease on
        the same source (the same race fixed for destination claims).
        """
        from ..utils.filelock import FileLock, FileLockError

        state_path = self._upload_state_destination(source)
        lease = FileLock(Path(str(state_path) + ".uplock"))
        try:
            lease.acquire(timeout=0)  # try-lock: do not queue behind another run
        except FileLockError as exc:
            raise UploadInProgressError(
                message=(
                    f"Another upload of {source.name} is already running in this or "
                    "another process. Wait for it to finish, or upload a copy under "
                    "a different name."
                )
            ) from exc
        except OSError as exc:
            raise TransferError(
                message=f"Could not take the upload lease for {source.name}: {exc}"
            ) from exc
        try:
            yield
        finally:
            lease.release()

    def _upload_file_locked(
        self,
        source: Path,
        target_handle: str | None = None,
        rename_to: str | None = None,
        on_progress: Callable[[UploadProgress], None] | None = None,
    ) -> UploadResult:
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
            # `bytes.fromhex` raises TypeError - NOT ValueError - when the
            # value is a JSON number, so a poisoned state file used to escape
            # this self-heal entirely and break every later retry. State-level
            # validation now rejects such a file at load; TypeError stays here
            # as the belt to that pair of braces.
            except (KeyError, TypeError, ValueError):
                clear_state(state_path)
                state = None

        if state is None:
            # The branch above clears the state it rejected, but this one is
            # also reached when `load_state` returned None with the file still
            # on disk (an unsupported format version, or bytes that could not
            # be preserved for quarantine). Its `revision` would then outrank
            # every snapshot of the fresh state below and silently block them.
            clear_state(state_path)
            # Request a fresh upload slot
            upload_url = self._request_upload_url(file_size)
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

        # Either the resumed state supplied a slot or the branch above just
        # requested one; stating it once here saves every later use from
        # re-proving it.
        assert upload_url is not None

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

        with progress_ticker(_emit_progress if on_progress else None, "mega-upload-progress"):
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
                    upload_url = self._request_upload_url(file_size)
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
        complete_macs = [m for m in chunk_macs if m is not None]
        if len(complete_macs) != len(chunk_macs):
            raise TransferError(message="Missing chunk MAC after upload")
        file_mac = combine_chunk_macs(complete_macs, aes_key)
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

        # Never fabricate a handle out of the completion token: the caller
        # would clear the resume state and report success for a node that may
        # never have been created. Raising keeps the state on disk so the
        # upload can be resumed instead of silently lost.
        nodes = result.get("f") if isinstance(result, dict) else None
        node = nodes[0] if isinstance(nodes, list) and nodes else None
        handle = node.get("h") if isinstance(node, dict) else None
        if not isinstance(handle, str) or not handle:
            raise TransferError(
                message=(
                    "Upload completion returned no usable node handle for "
                    f"{upload_name}; the resume state was kept so the upload can be retried."
                )
            )
        return handle

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
        upload_url = self._request_upload_url(0)
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
                    stream=True,
                )
            except (requests.ConnectionError, requests.Timeout):
                if picked_proxy and self.proxy_pool is not None:
                    self.proxy_pool.report_failure(picked_proxy)
                raise
            try:
                status = resp.status_code
                body = _read_bounded_body(resp) if status == 200 else b""
            finally:
                resp.close()
            if status in UPLOAD_URL_EXPIRY_STATUS and attempt == 0:
                upload_url = self._request_upload_url(0)
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

    # --- Source identity / resume-state addressing ------------------------
    # Real implementations live in `upload_identity`; these thin static
    # delegates keep `MegaUploader._source_identity(...)` and friends working
    # for every existing caller and test.
    _upload_state_destination = staticmethod(_identity.upload_state_destination)
    _file_sha256 = staticmethod(_identity.file_sha256)
    _source_identity = staticmethod(_identity.source_identity)
    _identities_match = staticmethod(_identity.identities_match)
    _is_resumable_upload_state = staticmethod(_identity.is_resumable_upload_state)

    # --- Directory walking / whole-tree upload ----------------------------
    upload_directory = _tree.upload_directory

    # --- Chunk transport ---------------------------------------------------
    # Assigned (not wrapped) so the tenacity decorator stays reachable as
    # `MegaUploader._upload_chunk.retry_with(...)`, which tests rely on.
    _upload_chunk = _transport.upload_chunk
