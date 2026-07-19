"""Refusals and proofs for a download: size claims, resume state, file MAC.

Three checks that all answer "is this transfer allowed to proceed / did it
actually succeed", kept apart from the transfer machinery that uses them:

* `_validate_declared_size` - the size the remote claims, checked BEFORE a
  chunk plan is built.
* `is_usable_download_state` - whether a state file on disk describes this
  exact transfer and may be resumed.
* `verify_file_integrity` - whether the committed per-chunk MACs combine to
  the MAC embedded in the file key.

None of these touch the network, the thread pool, or the destination claim.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import cast

from .chunks import MAX_CHUNKS, MAX_FILE_SIZE, Chunk, chunk_count, combine_chunk_macs, condense_mac
from .errors import NonRetryableTransferError
from .state import TransferState

log = logging.getLogger(__name__)


class DeclaredSizeError(NonRetryableTransferError):
    """The remote declared a file size we refuse to plan a transfer around.

    The size is not a fact, it is a claim: for a `mc://` link it comes from a
    server the LINK chose. Retrying cannot change the answer, hence
    non-retryable.
    """


class InsufficientDiskSpaceError(NonRetryableTransferError):
    """The destination filesystem cannot hold the file we are about to preallocate."""


def _validate_declared_size(file_size: object) -> int:
    """Return a size we are willing to allocate a chunk plan for, or raise.

    Called before ANY per-chunk work: the whole point is that the allocation
    loop never starts. `bool` is rejected explicitly because it is an `int`
    subclass and `True` would otherwise pass as a one-byte file.
    """
    if isinstance(file_size, bool) or not isinstance(file_size, int):
        raise DeclaredSizeError(message=f"Declared file size is not an integer: {file_size!r}")
    if file_size < 0:
        raise DeclaredSizeError(message=f"Declared file size is negative: {file_size}")
    if file_size > MAX_FILE_SIZE or chunk_count(file_size) > MAX_CHUNKS:
        raise DeclaredSizeError(
            message=(
                f"Declared file size {file_size} exceeds the supported maximum "
                f"{MAX_FILE_SIZE} bytes ({MAX_CHUNKS} chunks)"
            )
        )
    return file_size


def is_usable_download_state(
    *,
    auto_resume: bool,
    state: TransferState | None,
    destination: Path,
    source: str,
    file_size: int,
    aes_key: bytes,
    nonce: bytes,
    all_chunks: list[Chunk],
) -> bool:
    """Return True only when a resume state matches this exact transfer."""
    if not auto_resume:
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


def verify_file_integrity(
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
