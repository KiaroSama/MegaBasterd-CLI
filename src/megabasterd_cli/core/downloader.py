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
"""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, cast

import requests
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from ..proxy.selector import ProxySelector
from ..utils.helpers import (
    claim_destination,
    ensure_within_directory,
    release_destination,
    sanitize_filename,
)
from ..utils.speed import RollingSpeedMeter, make_limiter
from .chunks import Chunk, chunk_mac, combine_chunk_macs, condense_mac, iter_chunks
from .crypto import (
    b64_url_decode,
    decrypt_attributes,
    make_ctr_cipher,
    str_to_a32,
    unpack_file_key,
)
from .errors import IntegrityError, QuotaError, TransferError
from .links import (
    LinkType,
    get_megacrypter_download_url,
    get_megacrypter_info,
    parse_link,
    resolve_encrypted_container_link,
    resolve_megacrypter_link,
    resolve_password_link,
)
from .state import (
    TransferState,
    clear_state,
    load_state,
    save_state,
    snapshot_state,
    state_path_for,
)

log = logging.getLogger(__name__)


# HTTP status codes that indicate the CDN URL has expired or is unusable
# and should be re-fetched rather than retried as-is.
URL_EXPIRY_STATUS = {403, 410, 509}


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


class CdnUrlExpired(TransferError):  # noqa: N818 - internal retry sentinel name
    """Raised when the CDN URL has expired and needs to be refreshed."""


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
        limiter=None,  # Shared TokenBucket/NoOpLimiter for aggregate command caps
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
        parsed = parse_link(url)

        # Transparently resolve password / MegaCrypter wrappers down to a
        # standard file/folder link.
        if parsed.type == LinkType.PASSWORD_PROTECTED:
            if not password:
                raise ValueError("This link is password-protected; supply password=")
            parsed = resolve_password_link(parsed, password)
        elif parsed.type == LinkType.ENCRYPTED_CONTAINER:
            parsed = resolve_encrypted_container_link(parsed)
        elif parsed.type == LinkType.MEGACRYPTER:
            mc_parsed = parsed
            try:
                parsed = resolve_megacrypter_link(
                    parsed,
                    timeout=self.timeout,
                    password=password,
                )
            except ValueError as exc:
                mc_info = get_megacrypter_info(
                    mc_parsed,
                    timeout=self.timeout,
                    password=password,
                    selector=self._selector,
                )
                if not mc_info.key or mc_info.size is None:
                    raise ValueError("MegaCrypter metadata is missing key or size") from exc
                cdn_url = get_megacrypter_download_url(
                    mc_parsed,
                    info=mc_info,
                    timeout=self.timeout,
                    password=password,
                    selector=self._selector,
                )
                key_a32 = str_to_a32(mc_info.key)
                aes_key, nonce, mac_iv_a32 = unpack_file_key(key_a32)
                filename = rename_to or sanitize_filename(
                    mc_info.name or mc_parsed.crypter_token or "megacrypter"
                )
                output_dir.mkdir(parents=True, exist_ok=True)
                destination = output_dir / filename
                ensure_within_directory(output_dir, destination)

                def _resolver() -> str:
                    return get_megacrypter_download_url(
                        mc_parsed,
                        info=mc_info,
                        timeout=self.timeout,
                        password=password,
                        selector=self._selector,
                    )

                return self._run_download(
                    cdn_url=cdn_url,
                    file_size=mc_info.size,
                    aes_key=aes_key,
                    nonce=nonce,
                    mac_iv_a32=mac_iv_a32,
                    destination=destination,
                    source=url,
                    on_progress=on_progress,
                    url_resolver=_resolver,
                )

        if parsed.type not in (LinkType.FILE, LinkType.FILE_IN_FOLDER):
            raise ValueError(f"Link is not a single-file link: {parsed.type}")

        if parsed.type == LinkType.FILE_IN_FOLDER:
            # The link points to a node inside a public folder share. The
            # public_id is the FOLDER's handle, not the file's; we must look
            # up the file in the folder listing to get its wrapped key, and
            # request the CDN URL with `n=<folder_id>` as an extra parameter.
            from .crypto import a32_to_bytes, aes_key_wrap_decrypt, bytes_to_a32

            folder_id = parsed.public_id
            file_handle = parsed.subpath
            if not file_handle:
                raise ValueError("FILE_IN_FOLDER link is missing the file handle")
            folder_key = a32_to_bytes(str_to_a32(parsed.key))

            listing = self._get_with_quota_wait(
                lambda: self.api.get_public_folder_listing(folder_id)
            )
            file_raw = next(
                (n for n in listing.get("f", []) if n.get("h") == file_handle and n.get("t") == 0),
                None,
            )
            if file_raw is None:
                raise TransferError(
                    message=f"File {file_handle!r} not in folder share {folder_id!r}"
                )

            raw_k = file_raw.get("k", "") or ""
            _, wrapped = raw_k.split(":", 1) if ":" in raw_k else ("", raw_k)
            if not wrapped:
                raise TransferError(message=f"Empty wrapped key on {file_handle!r}")
            key_bytes = aes_key_wrap_decrypt(b64_url_decode(wrapped), folder_key)
            key_a32 = bytes_to_a32(key_bytes[:32])

            info = self._get_with_quota_wait(
                lambda: self.api.request(
                    {"a": "g", "g": 1, "n": file_handle},
                    extra_params={"n": folder_id},
                )
            )
            if "g" not in info:
                raise TransferError(message=f"No download URL returned for folder-file: {info}")
            encrypted_attrs = b64_url_decode(file_raw.get("a", "") or "")
        else:
            info = self._get_with_quota_wait(
                lambda: self.api.get_public_file_info(parsed.public_id)
            )
            if "g" not in info:
                raise TransferError(message=f"No download URL returned: {info}")
            key_a32 = str_to_a32(parsed.key)
            encrypted_attrs = b64_url_decode(info.get("at", "") or "")

        cdn_url = info["g"]
        file_size = int(info["s"])
        aes_key, nonce, mac_iv_a32 = unpack_file_key(key_a32)

        # Decrypt the filename
        attrs = decrypt_attributes(encrypted_attrs, aes_key)
        original_name = (attrs or {}).get("n") or (
            parsed.subpath if parsed.subpath else parsed.public_id
        )
        filename = rename_to or sanitize_filename(original_name)
        destination = output_dir / filename
        ensure_within_directory(output_dir, destination)
        destination.parent.mkdir(parents=True, exist_ok=True)

        # Resolver that re-fetches a fresh CDN URL when the existing one expires
        if parsed.type == LinkType.FILE_IN_FOLDER:
            _resolver_folder_id = parsed.public_id
            _resolver_file_handle = parsed.subpath

            def _resolver() -> str:
                fresh = self.api.request(
                    {"a": "g", "g": 1, "n": _resolver_file_handle},
                    extra_params={"n": _resolver_folder_id},
                )
                if "g" not in fresh:
                    raise TransferError(message=f"Resolver got no URL: {fresh}")
                return fresh["g"]

        else:
            _resolver_public_id = parsed.public_id

            def _resolver() -> str:
                fresh = self.api.get_public_file_info(_resolver_public_id)
                if "g" not in fresh:
                    raise TransferError(message=f"Resolver got no URL: {fresh}")
                return fresh["g"]

        return self._run_download(
            cdn_url=cdn_url,
            file_size=file_size,
            aes_key=aes_key,
            nonce=nonce,
            mac_iv_a32=mac_iv_a32,
            destination=destination,
            source=url,
            on_progress=on_progress,
            url_resolver=_resolver,
        )

    # ------------------------------------------------------------------
    # Core download loop
    # ------------------------------------------------------------------
    def _run_download(
        self,
        cdn_url: str,
        file_size: int,
        aes_key: bytes,
        nonce: bytes,
        mac_iv_a32: list[int],
        destination: Path,
        source: str,
        on_progress: Callable[[DownloadProgress], None] | None,
        url_resolver: Callable[[], str] | None = None,
    ) -> DownloadResult:
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
        state = load_state(destination) if self.auto_resume else None
        if not self._is_usable_download_state(
            state=state,
            destination=destination,
            source=source,
            file_size=file_size,
            aes_key=aes_key,
            nonce=nonce,
            all_chunks=all_chunks,
        ):
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

        # Pre-allocate the destination file with the final size
        if not destination.exists() or destination.stat().st_size != file_size:
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
        progress_stop = threading.Event()

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

        def _progress_loop() -> None:
            while not progress_stop.wait(0.5):
                try:
                    _emit_progress()
                except Exception:
                    log.debug("Progress callback raised", exc_info=True)

        reporter: threading.Thread | None = None
        if on_progress:
            reporter = threading.Thread(target=_progress_loop, name="mega-progress", daemon=True)
            reporter.start()

        # Spawn workers
        try:
            with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
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
        finally:
            progress_stop.set()
            if reporter is not None:
                reporter.join(timeout=2.0)

        if on_progress:
            # Final synchronous report so the consumer sees 100% of the bytes.
            try:
                _emit_progress()
            except Exception:
                log.debug("Final progress callback raised", exc_info=True)

        save_state(snapshot_state(state))

        # Integrity check
        integrity_ok = True
        if self.verify_integrity:
            integrity_ok = self._verify_integrity(state, all_chunks, aes_key, mac_iv_a32)
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
        if not self.auto_resume:
            return False
        if state is None:
            return False
        if state.transfer_type != "download":
            return False
        if state.total_size != file_size:
            return False
        if state.source != source:
            return False
        if Path(state.destination) != destination:
            return False
        metadata = state.metadata or {}
        if metadata.get("aes_key") and metadata.get("aes_key") != aes_key.hex():
            return False
        if metadata.get("nonce") and metadata.get("nonce") != nonce.hex():
            return False
        chunk_indexes = {c.index for c in all_chunks}
        completed = set(state.completed_chunks)
        if not completed:
            return True
        if not destination.exists() or destination.stat().st_size != file_size:
            return False
        if not completed.issubset(chunk_indexes):
            return False
        return all(state.get_chunk_mac(index) is not None for index in completed)

    @retry(
        retry=retry_if_exception_type(
            (requests.ConnectionError, requests.Timeout, TransferError, CdnUrlExpired)
        ),
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

        Reads the current CDN URL fresh on every attempt so refreshes by other
        workers propagate to this one.
        """
        if self._stop_event.is_set():
            return

        cdn_url, generation = self._current_url()
        headers = {
            "Range": f"bytes={chunk.offset}-{chunk.offset + chunk.size - 1}",
            "User-Agent": self.user_agent,
        }
        request_proxies, picked_proxy = self._proxies_for_request()
        encrypted = bytearray()
        try:
            with requests.get(
                cdn_url,
                headers=headers,
                timeout=self.timeout,
                stream=True,
                proxies=request_proxies,
            ) as resp:
                if resp.status_code in URL_EXPIRY_STATUS:
                    # Refresh the URL exactly once per generation, then retry.
                    # These are not proxy faults, so don't penalise the proxy.
                    self._refresh_url(generation)
                    raise CdnUrlExpired(
                        message=f"CDN URL expired (HTTP {resp.status_code}) for chunk {chunk.index}"
                    )
                if resp.status_code not in (200, 206):
                    if picked_proxy and self.proxy_pool is not None:
                        self.proxy_pool.report_failure(picked_proxy)
                    raise TransferError(message=f"HTTP {resp.status_code} for chunk {chunk.index}")

                # Read encrypted bytes
                for block in resp.iter_content(chunk_size=65536):
                    if self._stop_event.is_set():
                        return
                    encrypted.extend(block)
                    self.limiter.consume(len(block))
        except (requests.ConnectionError, requests.Timeout):
            if picked_proxy and self.proxy_pool is not None:
                self.proxy_pool.report_failure(picked_proxy)
            raise

        if len(encrypted) != chunk.size:
            if picked_proxy and self.proxy_pool is not None:
                self.proxy_pool.report_failure(picked_proxy)
            raise TransferError(
                message=f"Chunk {chunk.index} short read: got {len(encrypted)}, expected {chunk.size}"
            )

        # Decrypt with AES-CTR starting at this chunk's offset
        from .crypto import ctr_offset_to_counter

        cipher = make_ctr_cipher(
            aes_key,
            nonce,
            initial_value=ctr_offset_to_counter(chunk.offset),
        )
        plaintext = cipher.decrypt(bytes(encrypted))

        # Compute per-chunk MAC for later combining
        mac = chunk_mac(plaintext, aes_key, nonce)

        # Write plaintext to destination at the right offset
        with open(destination, "r+b") as f:
            f.seek(chunk.offset)
            f.write(plaintext)

        with self._lock:
            state.mark_chunk_done(chunk.index, mac)
            self._bytes_done += chunk.size
            self._chunks_done += 1
            bytes_done_now = self._bytes_done
            # Save state periodically (every ~16 chunks) to limit IO overhead
            should_save = self._chunks_done % 16 == 0
            state_to_save = snapshot_state(state) if should_save else None
        # Feed the rolling meter outside the state lock (it has its own).
        self._speed_meter.update(bytes_done_now)
        if should_save:
            save_state(state_to_save)

        if picked_proxy and self.proxy_pool is not None:
            self.proxy_pool.report_success(picked_proxy)

    def _verify_integrity(
        self,
        state: TransferState,
        all_chunks: list[Chunk],
        aes_key: bytes,
        mac_iv_a32: list[int],
    ) -> bool:
        """Combine per-chunk MACs and compare against the expected file MAC."""
        chunk_macs = [state.get_chunk_mac(c.index) for c in all_chunks]
        if any(m is None for m in chunk_macs):
            missing = [c.index for c in all_chunks if state.get_chunk_mac(c.index) is None]
            log.error("Missing chunk MACs for chunk(s) %s; integrity verification failed", missing)
            return False
        file_mac = combine_chunk_macs(cast(list[bytes], chunk_macs), aes_key)
        condensed = condense_mac(file_mac)
        return condensed[0] == mac_iv_a32[0] and condensed[1] == mac_iv_a32[1]

    def _progress_snapshot(self) -> tuple[int, int]:
        with self._lock:
            return self._bytes_done, self._chunks_done
