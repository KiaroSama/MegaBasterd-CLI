"""Chunk transport for uploads: the HTTP POST, its retry policy, its body.

Split out of `core.uploader`. Everything here is about getting ONE encrypted
chunk to the upload endpoint and deciding whether a failure is worth another
attempt — no orchestration, no node registration, no resume policy.

`upload_chunk` takes the uploader as its first argument and is installed as
`MegaUploader._upload_chunk`, so it stays a bound method for callers and keeps
its tenacity wrapper reachable as `MegaUploader._upload_chunk.retry_with(...)`.

`core.uploader` re-exports every name here, so the public surface is unchanged.
"""

from __future__ import annotations

from pathlib import Path

import requests
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

from ..proxy.selector import ProxyRequiredError
from .chunks import Chunk, chunk_mac
from .crypto import ctr_offset_to_counter, make_ctr_cipher
from .errors import TransferCancelled, TransferError
from .state import TransferState, save_state, snapshot_state

UPLOAD_URL_EXPIRY_STATUS = {403, 404, 410, 509}

# An upload endpoint answers a chunk POST with either an empty body or a small
# (~27 byte) completion token. Reading it unbounded would let a broken or
# hostile endpoint stream arbitrary data straight into memory.
MAX_UPLOAD_RESPONSE_BYTES = 4096


class UploadUrlExpiredError(Exception):
    """Raised when an upload slot is no longer usable and must be refreshed."""


def read_bounded_body(resp: requests.Response, limit: int = MAX_UPLOAD_RESPONSE_BYTES) -> bytes:
    """Read at most `limit` bytes from a streamed upload response body."""
    body = b""
    for block in resp.iter_content(chunk_size=limit + 1):
        body += block
        if len(body) > limit:
            raise TransferError(
                message=f"Upload endpoint returned more than {limit} bytes instead of a token"
            )
    return body


def is_retryable_upload_error(exc: BaseException) -> bool:
    """Retry transport hiccups only.

    `TransferError` is also the base of deterministic failures — a missing
    proxy under force mode (`ProxyRequiredError`) or a deliberate cancellation
    — and retrying those only burns five exponential backoffs before returning
    the same answer.
    """
    if isinstance(exc, (ProxyRequiredError, TransferCancelled)):
        return False
    return isinstance(exc, (requests.ConnectionError, requests.Timeout, TransferError))


@retry(
    retry=retry_if_exception(is_retryable_upload_error),
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=2, min=2, max=30),
    reraise=True,
)
def upload_chunk(
    up,  # MegaUploader
    upload_url: str,
    source: Path,
    chunk: Chunk,
    aes_key: bytes,
    nonce: bytes,
    state: TransferState,
    total_chunks: int,
) -> None:
    """Read, encrypt, POST one chunk."""
    if up._stop_event.is_set():
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

    up.limiter.consume(len(encrypted))

    put_url = f"{upload_url}/{chunk.offset}"
    request_proxies, picked_proxy = up._proxies_for_request()
    try:
        resp = requests.post(
            put_url,
            data=encrypted,
            timeout=up.timeout,
            proxies=request_proxies,
            headers={"User-Agent": up.user_agent},
            stream=True,
        )
    except (requests.ConnectionError, requests.Timeout):
        if picked_proxy and up.proxy_pool is not None:
            up.proxy_pool.report_failure(picked_proxy)
        raise
    if resp.status_code in UPLOAD_URL_EXPIRY_STATUS:
        resp.close()
        raise UploadUrlExpiredError(f"Upload URL expired on chunk {chunk.index}")
    if resp.status_code != 200:
        if picked_proxy and up.proxy_pool is not None:
            up.proxy_pool.report_failure(picked_proxy)
        resp.close()
        raise TransferError(message=f"Upload chunk {chunk.index} HTTP {resp.status_code}")
    if picked_proxy and up.proxy_pool is not None:
        up.proxy_pool.report_success(picked_proxy)

    # The MEGA upload endpoint returns a non-empty body ONLY for the
    # chunk that contains the last byte of the file — this is the
    # completion token used to finalise the upload. Save it whenever
    # we see a non-empty body, regardless of which worker finishes
    # last; otherwise a race between the offset-final chunk and any
    # earlier chunk causes the token to be dropped.
    try:
        body = read_bounded_body(resp)
    finally:
        resp.close()
    # Data before state: an upload has no local destination to flush, so
    # its durability point is the HTTP 200 above - the endpoint already
    # holds the chunk before the state below claims it does. The ordering
    # is therefore satisfied by construction here; `save_state` enforces
    # the equivalent flush for a download's destination file.
    with up._lock:
        state.mark_chunk_done(chunk.index, mac)
        up._bytes_done += chunk.size
        up._chunks_done += 1
        bytes_done_now = up._bytes_done
        if body:
            up._completion_token = body
            state.metadata["completion_token"] = body.hex()
        should_save = up._chunks_done % 8 == 0 or bool(body)
        state_to_save = snapshot_state(state) if should_save else None
    # Feed the rolling meter outside the state lock (it has its own).
    up._speed_meter.update(bytes_done_now)
    if should_save:
        save_state(state_to_save)
