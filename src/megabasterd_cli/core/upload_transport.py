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

from .chunks import Chunk, chunk_mac
from .crypto import ctr_offset_to_counter, make_ctr_cipher
from .errors import NonRetryableTransferError, RetryableTransferError
from .link_services import PayloadTooLargeError, read_bounded_bytes
from .state import TransferState, save_state, snapshot_state

UPLOAD_URL_EXPIRY_STATUS = {403, 404, 410, 509}

# An upload endpoint answers a chunk POST with either an empty body or a small
# (~27 byte) completion token. Reading it unbounded would let a broken or
# hostile endpoint stream arbitrary data straight into memory.
MAX_UPLOAD_RESPONSE_BYTES = 4096


class UploadUrlExpiredError(Exception):
    """Raised when an upload slot is no longer usable and must be refreshed."""


def _report_proxy(up, picked_proxy, *, ok: bool) -> None:
    """Credit or debit the proxy that carried this request, once.

    Every call site guards on the same two conditions, and the debit sites now
    outnumber the credit site four to one - inlining the guard five times is
    how one of them ends up missing it.
    """
    if picked_proxy and up.proxy_pool is not None:
        if ok:
            up.proxy_pool.report_success(picked_proxy)
        else:
            up.proxy_pool.report_failure(picked_proxy)


def read_bounded_body(resp: requests.Response, limit: int = MAX_UPLOAD_RESPONSE_BYTES) -> bytes:
    """Read at most `limit` bytes from a streamed upload response body."""
    try:
        return read_bounded_bytes(resp, limit)
    except PayloadTooLargeError as exc:
        # Deterministic: the endpoint answered the wrong shape, and it will
        # answer the same way next time.
        raise NonRetryableTransferError(
            message=f"Upload endpoint returned more than {limit} bytes instead of a token"
        ) from exc


def is_final_chunk(chunk: Chunk, total_size: int) -> bool:
    """True when this chunk carries the LAST byte of the file.

    The upload endpoint returns a completion token for exactly one chunk - the
    one containing the final byte. Deciding that from the offset is the only
    honest test; trusting "whichever response happened to be non-empty" lets a
    broken or hostile endpoint nominate any chunk as the finaliser.
    """
    return chunk.offset + chunk.size >= total_size


def is_retryable_upload_error(exc: BaseException) -> bool:
    """An ALLOWLIST: retry only what a later attempt can plausibly survive.

    This used to be a denylist over the `TransferError` base - exclude two
    subclasses, retry everything else. That silently opted in every future
    deterministic failure, and several present ones: a local short read, an
    oversized body, a fixed HTTP status. Five exponential backoffs later they
    returned the identical answer.

    Listing what MAY be retried inverts the default, so a new deterministic
    error is non-retryable unless someone deliberately adds it here.
    """
    return isinstance(
        exc,
        (
            requests.ConnectionError,
            requests.Timeout,
            # 5xx only; `upload_chunk` raises the non-retryable type for 4xx.
            RetryableTransferError,
            # NOT UploadUrlExpiredError: a dead slot is refreshed by the
            # ORCHESTRATOR, which needs to see the exception. Retrying it here
            # replays the same request against the same expired slot until the
            # attempts run out, and the refresh never happens.
        ),
    )


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
        raise NonRetryableTransferError(message=f"Local chunk {chunk.index} short read")

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
        _report_proxy(up, picked_proxy, ok=False)
        raise
    if resp.status_code in UPLOAD_URL_EXPIRY_STATUS:
        # MEGA retired the slot. The proxy delivered the answer faithfully, so
        # it earns neither a credit nor a blame here.
        resp.close()
        raise UploadUrlExpiredError(f"Upload URL expired on chunk {chunk.index}")
    if resp.status_code != 200:
        _report_proxy(up, picked_proxy, ok=False)
        resp.close()
        if resp.status_code >= 500:
            raise RetryableTransferError(
                message=f"Upload chunk {chunk.index} HTTP {resp.status_code}"
            )
        raise NonRetryableTransferError(
            message=f"Upload chunk {chunk.index} HTTP {resp.status_code}"
        )

    # The endpoint returns a non-empty body for EXACTLY ONE chunk: the one
    # holding the file's last byte. That body is the completion token.
    #
    # This used to accept a token from whichever chunk happened to return one,
    # on the theory that it avoided a race. It did the opposite: any chunk
    # could nominate itself as the finaliser, so a broken or hostile endpoint
    # could hand back a token early and have the upload finalised against it.
    # The offset decides, not the response.
    final = is_final_chunk(chunk, state.total_size)
    # A 200 whose BODY violates the protocol is the proxy's fault as much as a
    # bad status is. Withholding success alone left its ratio untouched, so a
    # proxy mangling every response stayed as attractive to `pick` as a healthy
    # one. Anything raised while reading or validating the body is one blame.
    try:
        try:
            body = read_bounded_body(resp)
        finally:
            resp.close()

        if body and not final:
            raise NonRetryableTransferError(
                message=(
                    f"Upload endpoint returned a completion token for chunk "
                    f"{chunk.index}, which is not the final chunk of the file"
                )
            )
        if final and not body:
            raise NonRetryableTransferError(
                message=(
                    f"Upload endpoint returned no completion token for final chunk {chunk.index}"
                )
            )
    except Exception:
        _report_proxy(up, picked_proxy, ok=False)
        raise

    # Only now is the response known to be well-formed. Reporting success
    # before this credited a proxy that returned HTTP 200 with a garbage body,
    # and `SmartProxyPool.pick` weights by success ratio - so the broken proxy
    # was progressively PREFERRED. Kept OUTSIDE the block above so a later
    # bookkeeping failure cannot turn a delivered chunk into a proxy blame.
    _report_proxy(up, picked_proxy, ok=True)
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
        # `final` is proven above, so a body here is the real finaliser.
        # `not up._completion_token` guards a stale worker: a retried final
        # chunk landing after the token was recorded must not replace one
        # already held. First valid token for the final offset wins.
        if body and not up._completion_token:
            up._completion_token = body
            state.metadata["completion_token"] = body.hex()
        should_save = up._chunks_done % 8 == 0 or bool(body)
        state_to_save = snapshot_state(state) if should_save else None
    # Feed the rolling meter outside the state lock (it has its own).
    up._speed_meter.update(bytes_done_now)
    if state_to_save is not None:
        save_state(state_to_save)
