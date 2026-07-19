"""One chunk over the wire: HTTP Range request, guards, decrypt, write, MAC.

This is the per-attempt body only. The retry POLICY that decides whether a
failure here is worth replaying lives with the downloader
(`_is_transient_chunk_failure`), because the distinction between a transient
fault and a deterministic refusal is what that predicate exists to encode.

Every failure path reports the proxy it used back to the pool, except CDN URL
expiry - that is the URL ageing out, not the proxy misbehaving.
"""

from __future__ import annotations

import logging

import requests

from .chunks import Chunk, chunk_mac
from .crypto import ctr_offset_to_counter, make_ctr_cipher
from .errors import NonRetryableTransferError, TransferError
from .range_validation import RangeNotHonoredError, validate_range_response
from .state import TransferState, save_state, snapshot_state

log = logging.getLogger(__name__)


# HTTP status codes that indicate the CDN URL has expired or is unusable
# and should be re-fetched rather than retried as-is.
URL_EXPIRY_STATUS = {403, 410, 509}


class CdnUrlExpired(TransferError):  # noqa: N818 - internal retry sentinel name
    """Raised when the CDN URL has expired and needs to be refreshed."""


def fetch_chunk(
    dl,  # MegaDownloader
    chunk: Chunk,
    aes_key: bytes,
    nonce: bytes,
    destination,
    state: TransferState,
) -> None:
    """Download one chunk, decrypt, write, MAC, update `dl`'s counters.

    Reads the current CDN URL fresh on every attempt so refreshes by other
    workers propagate to this one.
    """
    if dl._stop_event.is_set():
        return

    cdn_url, generation = dl._current_url()
    headers = {
        "Range": f"bytes={chunk.offset}-{chunk.offset + chunk.size - 1}",
        "User-Agent": dl.user_agent,
    }
    request_proxies, picked_proxy = dl._proxies_for_request()
    encrypted = bytearray()
    try:
        with requests.get(
            cdn_url,
            headers=headers,
            timeout=dl.timeout,
            stream=True,
            proxies=request_proxies,
        ) as resp:
            if resp.status_code in URL_EXPIRY_STATUS:
                # Refresh the URL exactly once per generation, then retry.
                # These are not proxy faults, so don't penalise the proxy.
                dl._refresh_url(generation)
                raise CdnUrlExpired(
                    message=f"CDN URL expired (HTTP {resp.status_code}) for chunk {chunk.index}"
                )
            if resp.status_code not in (200, 206):
                if picked_proxy and dl.proxy_pool is not None:
                    dl.proxy_pool.report_failure(picked_proxy)
                raise TransferError(message=f"HTTP {resp.status_code} for chunk {chunk.index}")

            # These bytes are about to be decrypted with a CTR counter
            # derived from THIS chunk's offset and written at that offset.
            # If the CDN or a proxy ignored `Range` and sent the whole file
            # - or a different window of the same length - the result is
            # silent on-disk corruption that only a full MAC check would
            # ever notice, and only if integrity verification is enabled.
            # Same rule the streaming server enforces, from one module.
            try:
                validate_range_response(
                    resp.status_code,
                    resp.headers,
                    chunk.offset,
                    chunk.offset + chunk.size - 1,
                    state.total_size,
                )
            except RangeNotHonoredError as exc:
                if picked_proxy and dl.proxy_pool is not None:
                    dl.proxy_pool.report_failure(picked_proxy)
                # A protocol violation, not a transient fault: retrying the
                # same request against the same server would repeat it.
                raise NonRetryableTransferError(
                    message=f"Upstream ignored the requested range for chunk {chunk.index}: {exc}"
                ) from exc

            # Read encrypted bytes, never more than this chunk is worth.
            # `validate_range_response` can only check Content-Length when
            # the server sends one, so a 206 with a plausible Content-Range
            # and chunked transfer-encoding streamed into this bytearray
            # without any ceiling at all.
            for block in resp.iter_content(chunk_size=65536):
                if dl._stop_event.is_set():
                    return
                if len(encrypted) + len(block) > chunk.size:
                    if picked_proxy and dl.proxy_pool is not None:
                        dl.proxy_pool.report_failure(picked_proxy)
                    raise NonRetryableTransferError(
                        message=(
                            f"Upstream sent more than the requested range for chunk "
                            f"{chunk.index}: expected {chunk.size} bytes"
                        )
                    )
                encrypted.extend(block)
                dl.limiter.consume(len(block))
    except (requests.ConnectionError, requests.Timeout):
        if picked_proxy and dl.proxy_pool is not None:
            dl.proxy_pool.report_failure(picked_proxy)
        raise

    if len(encrypted) != chunk.size:
        if picked_proxy and dl.proxy_pool is not None:
            dl.proxy_pool.report_failure(picked_proxy)
        raise TransferError(
            message=f"Chunk {chunk.index} short read: got {len(encrypted)}, expected {chunk.size}"
        )

    # Decrypt with AES-CTR starting at this chunk's offset
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

    with dl._lock:
        state.mark_chunk_done(chunk.index, mac)
        dl._bytes_done += chunk.size
        dl._chunks_done += 1
        bytes_done_now = dl._bytes_done
        # Save state periodically (every ~16 chunks) to limit IO overhead
        should_save = dl._chunks_done % 16 == 0
        state_to_save = snapshot_state(state) if should_save else None
    # Feed the rolling meter outside the state lock (it has its own).
    dl._speed_meter.update(bytes_done_now)
    if should_save:
        save_state(state_to_save)

    if picked_proxy and dl.proxy_pool is not None:
        dl.proxy_pool.report_success(picked_proxy)
