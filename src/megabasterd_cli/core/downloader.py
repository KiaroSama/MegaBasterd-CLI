"""Multi-threaded MEGA file downloader with resume and integrity checking.

The downloader:
1. Resolves a public link (or owned file handle) to a CDN URL and file key.
2. Splits the file into MEGA-style variable-size chunks.
3. Spawns `max_workers` threads that pull chunks in parallel using HTTP Range.
4. Each thread decrypts its chunk with AES-CTR, computes the chunk CBC-MAC,
   writes the plaintext to the destination file with `pwrite`, and records
   completion in the state file.
5. After all chunks complete, the per-chunk MACs are combined into the file
   MAC and verified against the MAC embedded in the file key.

CDN URLs returned by MEGA are time-limited. If a chunk request fails with one
of the "URL expired" responses (403, 410, 509), the downloader transparently
re-fetches a fresh URL via the supplied resolver and retries.

This module is the entry point and owns the orchestration: quota recovery, CDN
URL generation state, the destination claim, the worker pool, and the
completion gate. The pieces it drives live next door and are re-exported here
so the public surface is unchanged:

* `download_source`    - link -> CDN URL, key, destination, refresh resolver
* `download_transport` - one chunk over the wire (guards, decrypt, write, MAC)
* `download_verify`    - declared-size refusal, resume-state match, file MAC
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

import requests
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

from ..proxy.selector import ProxySelector
from ..utils.helpers import available_disk_space, claim_destination, release_destination
from ..utils.speed import RollingSpeedMeter, make_limiter
from .chunks import Chunk, iter_chunks
from .download_source import ResolvedSource, resolve_download_source
from .download_transport import URL_EXPIRY_STATUS, CdnUrlExpired, fetch_chunk
from .download_verify import (
    DeclaredSizeError,
    InsufficientDiskSpaceError,
    _validate_declared_size,
    is_usable_download_state,
    verify_file_integrity,
)
from .errors import (
    IntegrityError,
    QuotaError,
    RetryableTransferError,
    TransferCancelled,
    TransferError,
)
from .progress_ticker import progress_ticker
from .range_validation import validate_range_response
from .state import (
    TransferState,
    clear_state,
    load_state,
    save_state,
    snapshot_state,
    state_path_for,
)

log = logging.getLogger(__name__)

__all__ = [
    "CdnUrlExpired",
    "DeclaredSizeError",
    "DownloadProgress",
    "DownloadResult",
    "InsufficientDiskSpaceError",
    "MegaDownloader",
    "ResolvedSource",
    "URL_EXPIRY_STATUS",
    "validate_range_response",
]


@dataclass
class DownloadProgress:
    """Progress info passed to the progress callback."""

    bytes_done: int
    total_bytes: int
    chunks_done: int
    total_chunks: int
    speed_bps: float


@dataclass
class DownloadResult:
    """Outcome of a completed download."""

    path: Path
    size: int
    elapsed_seconds: float
    integrity_ok: bool


def _is_transient_chunk_failure(exc: BaseException) -> bool:
    """An ALLOWLIST: retry only what a later attempt can plausibly survive.

    Two iterations of this predicate were denylists. The first matched the
    `TransferError` BASE class, so every deterministic refusal that subclasses
    it was replayed eight times with exponential backoff. The second excluded
    `NonRetryableTransferError` and then still matched the base - better, but
    it kept the wrong default: anything new is retryable until someone
    remembers to opt out, and a short read or a fixed 4xx never opted out.

    Naming what MAY be retried flips that. A deterministic failure has to be
    added here on purpose to be replayed, which is the safe direction: the
    cost of wrongly not retrying is one honest error, the cost of wrongly
    retrying is minutes of backoff hiding a settled answer.
    """
    return isinstance(
        exc,
        (
            requests.ConnectionError,
            requests.Timeout,
            # The URL is refreshed and the chunk genuinely can succeed next try.
            CdnUrlExpired,
            # 5xx only; `download_transport` raises the non-retryable type
            # for a fixed 4xx and for length/protocol mismatches.
            RetryableTransferError,
        ),
    )


class MegaDownloader:
    """Multi-threaded downloader for one MEGA file."""

    def __init__(
        self,
        api,  # MegaAPIClient
        max_workers: int = 8,
        speed_limit_kbps: float = 0,
        verify_integrity: bool = True,
        timeout: int = 60,
        proxies: dict[str, str] | None = None,
        proxy_pool=None,  # SmartProxyPool | None
        force_proxy: bool = False,
        quota_wait_seconds: int = 0,
        quota_max_wait_loops: int = 0,
        keep_state_files_on_error: bool = True,
        overwrite: bool = False,
        limiter=None,  # Shared TokenBucket for aggregate command caps
        auto_resume: bool = True,
        user_agent: str | None = None,
    ):
        from .api import default_user_agent

        self.api = api
        self.max_workers = max(1, max_workers)
        self.verify_integrity = verify_integrity
        self.timeout = timeout
        self.proxies = proxies
        # Smart proxy pool: if set, each chunk request picks a proxy from
        # the pool (preferring healthy ones) and reports success/failure
        # back so the pool can cool down or promote entries.
        self.proxy_pool = proxy_pool
        self.force_proxy = force_proxy
        # One shared selection authority (see proxy/selector.py); the old
        # per-class copy of this logic is gone.
        self._selector = ProxySelector(pool=proxy_pool, static=proxies, force=force_proxy)
        # When a shared limiter is supplied, all downloaders of one command
        # drain the same bucket, so `speed_limit_kbps` acts as an aggregate
        # cap instead of multiplying per parallel file.
        self.limiter = limiter if limiter is not None else make_limiter(speed_limit_kbps)
        self.auto_resume = auto_resume
        self.user_agent = user_agent or default_user_agent()
        # Quota recovery: when the upstream returns -17/-24, the wrapper around
        # download_link sleeps up to quota_max_wait_loops × quota_wait_seconds.
        self.quota_wait_seconds = quota_wait_seconds
        self.quota_max_wait_loops = quota_max_wait_loops
        self.keep_state_files_on_error = keep_state_files_on_error
        # When False (default), an existing destination that is NOT a resumable
        # continuation of this exact transfer is never truncated; a unique name
        # is chosen instead. --overwrite forces in-place replacement.
        self.overwrite = overwrite
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._url_refresh_lock = threading.Lock()
        self._bytes_done = 0
        self._chunks_done = 0
        self._start_time = 0.0
        # Rolling window meter: reports the CURRENT transfer rate (recent
        # bytes over a short window), not the lifetime average. Re-seeded at
        # the start of every download so resumed bytes never inflate it.
        self._speed_meter = RollingSpeedMeter(window=5.0)

        # CDN URL state (shared across workers; refreshed on expiry)
        self._cdn_url_lock = threading.Lock()
        self._cdn_url: str = ""
        self._url_generation = 0  # Bumped each time the URL is refreshed
        self._url_resolver: Callable[[], str] | None = None

    def _proxies_for_request(self) -> tuple[dict[str, str] | None, str | None]:
        """Per-request proxy decision, delegated to the shared selector."""
        return self._selector.select()

    def stop(self) -> None:
        """Signal all worker threads to stop."""
        self._stop_event.set()

    # ------------------------------------------------------------------
    # Quota recovery
    # ------------------------------------------------------------------
    def _get_with_quota_wait(self, fn):
        """Call `fn()` retrying on EOVERQUOTA by sleeping per the config."""
        attempts = max(1, self.quota_max_wait_loops or 1)
        for i in range(attempts):
            try:
                return fn()
            except QuotaError as exc:
                wait = self.quota_wait_seconds
                if wait <= 0 or i == attempts - 1:
                    raise
                log.warning(
                    "MEGA quota exceeded (%s); waiting %ds before retry (%d/%d)",
                    exc,
                    wait,
                    i + 1,
                    attempts,
                )
                # Sleep responsively to stop signals
                slept = 0
                while slept < wait and not self._stop_event.is_set():
                    time.sleep(min(2.0, wait - slept))
                    slept += 2
                if self._stop_event.is_set():
                    raise
        # Unreachable but keeps type checkers happy
        raise QuotaError(message="Quota recovery exhausted")

    # ------------------------------------------------------------------
    # URL refresh helpers
    # ------------------------------------------------------------------
    def _current_url(self) -> tuple[str, int]:
        with self._cdn_url_lock:
            return self._cdn_url, self._url_generation

    def _refresh_url(self, seen_generation: int) -> str:
        """Refresh the CDN URL if no other worker has already done so."""
        with self._cdn_url_lock:
            if self._url_generation != seen_generation:
                return self._cdn_url
            if not self._url_resolver:
                raise TransferError(message="CDN URL expired and no resolver available")
            resolver = self._url_resolver

        with self._url_refresh_lock:
            with self._cdn_url_lock:
                if self._url_generation != seen_generation:
                    return self._cdn_url

            log.info("CDN URL expired; refreshing via resolver")
            fresh_url = resolver()
            with self._cdn_url_lock:
                if self._url_generation == seen_generation:
                    self._cdn_url = fresh_url
                    self._url_generation += 1
                return self._cdn_url

    # ------------------------------------------------------------------
    # Public entry point: download from a public link
    # ------------------------------------------------------------------
    def download_link(
        self,
        url: str,
        output_dir: Path,
        password: str | None = None,
        rename_to: str | None = None,
        on_progress: Callable[[DownloadProgress], None] | None = None,
    ) -> DownloadResult:
        """Download a single MEGA public file link to `output_dir`."""
        resolved = resolve_download_source(self, url, output_dir, password, rename_to)
        return self._run_download(
            cdn_url=resolved.cdn_url,
            file_size=resolved.file_size,
            aes_key=resolved.aes_key,
            nonce=resolved.nonce,
            mac_iv_a32=resolved.mac_iv_a32,
            destination=resolved.destination,
            source=url,
            on_progress=on_progress,
            url_resolver=resolved.url_resolver,
        )

    # ------------------------------------------------------------------
    # Core download loop
    # ------------------------------------------------------------------
    def _run_download(
        self,
        cdn_url: str,
        # `object`, not `int`: this is the size the REMOTE claims, and the
        # first statement below is what turns it into a trusted int. Declaring
        # it `int` here asserted the very thing the validation exists to prove.
        file_size: object,
        aes_key: bytes,
        nonce: bytes,
        mac_iv_a32: list[int],
        destination: Path,
        source: str,
        on_progress: Callable[[DownloadProgress], None] | None,
        url_resolver: Callable[[], str] | None = None,
    ) -> DownloadResult:
        # Every download path funnels through here, so the size claim is checked
        # once, at the only place that is guaranteed to run before the chunk
        # plan is built.
        file_size = _validate_declared_size(file_size)

        # Configure the URL state for workers
        with self._cdn_url_lock:
            self._cdn_url = cdn_url
            self._url_generation = 0
            self._url_resolver = url_resolver

        all_chunks = list(iter_chunks(file_size))

        # Atomically reserve the final destination before any worker starts:
        # one reserved path (and therefore one state file) belongs to exactly
        # one transfer, even when parallel links carry identical or
        # sanitization/truncation-colliding names. An existing file is reused
        # only when it is a resumable continuation of this exact transfer;
        # otherwise a unique name inside the already-contained directory is
        # claimed (or the file is replaced under --overwrite).
        requested = destination
        destination = claim_destination(
            requested,
            overwrite=self.overwrite,
            is_resumable=lambda p: self._is_usable_download_state(
                state=load_state(p),
                destination=p,
                source=source,
                file_size=file_size,
                aes_key=aes_key,
                nonce=nonce,
                all_chunks=all_chunks,
            ),
        )
        if destination != requested:
            log.info(
                "Destination already exists or is in use; writing to unique path %s instead",
                destination.name,
            )
        try:
            return self._run_claimed_download(
                file_size=file_size,
                aes_key=aes_key,
                nonce=nonce,
                mac_iv_a32=mac_iv_a32,
                destination=destination,
                source=source,
                on_progress=on_progress,
                all_chunks=all_chunks,
            )
        finally:
            release_destination(destination)

    def _run_claimed_download(
        self,
        file_size: int,
        aes_key: bytes,
        nonce: bytes,
        mac_iv_a32: list[int],
        destination: Path,
        source: str,
        on_progress: Callable[[DownloadProgress], None] | None,
        all_chunks: list[Chunk],
    ) -> DownloadResult:
        # Load existing state for resume
        # Written as resume-or-fresh rather than assign-then-maybe-replace so
        # `state` is a TransferState from here on: the old shape left it
        # Optional for the whole function and every later use had to be
        # re-proven, which the type checker could not do and a reader had to.
        loaded = load_state(destination) if self.auto_resume else None
        if loaded is not None and self._is_usable_download_state(
            state=loaded,
            destination=destination,
            source=source,
            file_size=file_size,
            aes_key=aes_key,
            nonce=nonce,
            all_chunks=all_chunks,
        ):
            state = loaded
        else:
            # Whatever is on disk lost: it is unloadable, unusable, or resume is
            # off. Leaving it there let its `revision` outrank every snapshot of
            # the fresh state below (which starts at 0), so `save_state` dropped
            # them all at debug level and the download persisted no resume state.
            clear_state(destination)
            state = TransferState(
                transfer_type="download",
                source=source,
                destination=str(destination),
                total_size=file_size,
                metadata={
                    "aes_key": aes_key.hex(),
                    "nonce": nonce.hex(),
                },
            )

        # Pre-allocate the destination file with the final size. Ask the
        # filesystem first: `truncate` to a size that does not fit either fails
        # with a bare ENOSPC deep inside a worker or (on a sparse filesystem)
        # succeeds and fails much later, mid-transfer, with the disk full.
        if not destination.exists() or destination.stat().st_size != file_size:
            already = destination.stat().st_size if destination.exists() else 0
            needed = max(0, file_size - already)
            free = available_disk_space(destination.parent)
            if free < needed:
                raise InsufficientDiskSpaceError(
                    message=(
                        f"Not enough free space for {destination.name}: need {needed} bytes, "
                        f"{free} available on {destination.parent}"
                    )
                )
            with open(destination, "wb") as f:
                f.truncate(file_size)

        pending = [c for c in all_chunks if not state.is_chunk_done(c.index)]
        self._bytes_done = sum(c.size for c in all_chunks if state.is_chunk_done(c.index))
        self._chunks_done = len(all_chunks) - len(pending)
        self._start_time = time.monotonic()
        self._stop_event.clear()
        # Fresh meter per download; the baseline sample is the resumed byte
        # count, so the reported speed measures only NEW bytes this session.
        self._speed_meter = RollingSpeedMeter(window=5.0)
        self._speed_meter.update(self._bytes_done)

        log.info(
            "Downloading %s (%d bytes, %d chunks, %d already done)",
            destination.name,
            file_size,
            len(all_chunks),
            self._chunks_done,
        )

        # Progress ticker: report progress on a steady clock instead of once
        # per completed future in submission order. fut.result() below blocks
        # on the FIRST unfinished future, so submission-order callbacks arrive
        # in late bursts; a timed reporter keeps bytes/speed/ETA flowing the
        # moment chunks land, and the rolling meter reports the CURRENT rate
        # (the old ``bytes_done / total_elapsed`` was a lifetime average that
        # also counted resumed bytes, wildly overstating speed after resume).
        def _emit_progress() -> None:
            if on_progress is None:
                return
            bytes_done, chunks_done = self._progress_snapshot()
            on_progress(
                DownloadProgress(
                    bytes_done=bytes_done,
                    total_bytes=file_size,
                    chunks_done=chunks_done,
                    total_chunks=len(all_chunks),
                    speed_bps=self._speed_meter.current(),
                )
            )

        # Spawn workers. The pool exits (joining every worker) before the
        # ticker does, so the ticker's final emit reports 100% of the bytes.
        with (
            progress_ticker(_emit_progress if on_progress else None, "mega-progress"),
            ThreadPoolExecutor(max_workers=self.max_workers) as pool,
        ):
            futures = []
            for chunk in pending:
                if self._stop_event.is_set():
                    break
                fut = pool.submit(
                    self._download_chunk,
                    chunk,
                    aes_key,
                    nonce,
                    destination,
                    state,
                )
                futures.append((chunk, fut))

            for chunk, fut in futures:
                try:
                    fut.result()
                except Exception as e:
                    self._stop_event.set()
                    if self.keep_state_files_on_error:
                        with self._lock:
                            state_to_save = snapshot_state(state)
                        save_state(state_to_save)
                    else:
                        clear_state(destination)
                    log.error("Chunk %d failed: %s", chunk.index, e)
                    raise TransferError(message=f"Chunk {chunk.index} failed: {e}") from e
        committed = snapshot_state(state)
        save_state(committed)

        # Completion is proven by CHUNK COVERAGE, not by reaching this line.
        # Cancellation breaks out of the submission loop above, so without this
        # check a cancelled transfer fell through to clear_state() and returned
        # a successful DownloadResult - and with verify_integrity=False nothing
        # else would ever have noticed. The snapshot gives one consistent view
        # of what workers actually committed.
        missing = [c.index for c in all_chunks if not committed.is_chunk_done(c.index)]
        if missing:
            if self.keep_state_files_on_error:
                save_state(committed)  # keep what was committed
            else:
                clear_state(destination)
            if self._stop_event.is_set():
                raise TransferCancelled(
                    message=(
                        f"Download cancelled with {len(missing)} of {len(all_chunks)} "
                        "chunks still missing; resume state was kept."
                    )
                )
            raise TransferError(
                message=(
                    f"Download is incomplete: {len(missing)} of {len(all_chunks)} chunks "
                    "were never committed."
                )
            )

        # Integrity check
        integrity_ok = True
        if self.verify_integrity:
            integrity_ok = self._verify_integrity(
                all_chunks, aes_key, nonce, mac_iv_a32, destination
            )
            if not integrity_ok:
                state_path = state_path_for(destination)
                if self.keep_state_files_on_error:
                    message = (
                        "File MAC verification failed. Delete the resume state file and retry: "
                        f"{state_path}"
                    )
                else:
                    clear_state(destination)
                    message = "File MAC verification failed; resume state was removed."
                raise IntegrityError(message=message)

        clear_state(destination)
        # Elapsed covers the whole operation including integrity verification,
        # matching the uploader's result semantics.
        elapsed = time.monotonic() - self._start_time
        return DownloadResult(
            path=destination, size=file_size, elapsed_seconds=elapsed, integrity_ok=integrity_ok
        )

    def _is_usable_download_state(
        self,
        state: TransferState | None,
        destination: Path,
        source: str,
        file_size: int,
        aes_key: bytes,
        nonce: bytes,
        all_chunks: list[Chunk],
    ) -> bool:
        """Return True only when a resume state matches this exact transfer."""
        return is_usable_download_state(
            auto_resume=self.auto_resume,
            state=state,
            destination=destination,
            source=source,
            file_size=file_size,
            aes_key=aes_key,
            nonce=nonce,
            all_chunks=all_chunks,
        )

    @retry(
        retry=retry_if_exception(_is_transient_chunk_failure),
        stop=stop_after_attempt(8),
        wait=wait_exponential(multiplier=2, min=2, max=30),
        reraise=True,
    )
    def _download_chunk(
        self,
        chunk: Chunk,
        aes_key: bytes,
        nonce: bytes,
        destination: Path,
        state: TransferState,
    ) -> None:
        """Download one chunk, decrypt, write, MAC, update state.

        The retry policy is declared here; the per-attempt body lives in
        `download_transport.fetch_chunk`.
        """
        fetch_chunk(self, chunk, aes_key, nonce, destination, state)

    def _verify_integrity(
        self,
        all_chunks: list[Chunk],
        aes_key: bytes,
        nonce: bytes,
        mac_iv_a32: list[int],
        destination: Path,
    ) -> bool:
        """Re-MAC the file on disk and compare against the expected file MAC."""
        return verify_file_integrity(all_chunks, aes_key, nonce, mac_iv_a32, destination)

    def _progress_snapshot(self) -> tuple[int, int]:
        with self._lock:
            return self._bytes_done, self._chunks_done
