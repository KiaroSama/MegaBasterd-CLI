"""Refusals and proofs for a download: size claims, resume state, file MAC.

Three checks that all answer "is this transfer allowed to proceed / did it
actually succeed", kept apart from the transfer machinery that uses them:

* `_validate_declared_size` - the size the remote claims, checked BEFORE a
  chunk plan is built.
* `is_usable_download_state` - whether a state file on disk describes this
  exact transfer and may be resumed.
* `verify_file_integrity` - whether the bytes ON DISK combine to the MAC
  embedded in the file key (`_verify_file_on_disk` does the reading).

None of these touch the network, the thread pool, or the destination claim.
"""

from __future__ import annotations

import logging
from pathlib import Path

from .chunks import (
    MAX_CHUNKS,
    MAX_FILE_SIZE,
    Chunk,
    chunk_count,
    chunk_mac,
    combine_chunk_macs,
    condense_mac,
)
from .errors import NonRetryableTransferError
from .state import TransferState

log = logging.getLogger(__name__)

_NONCE_BYTES = 8  # a MEGA file nonce; `chunk_mac` uses `nonce + nonce` as the CBC IV


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
    # A resumable state must RECORD the crypto it belongs to and have it match.
    # The old `metadata.get("aes_key") and ...` skipped the check when the key
    # was absent, so a state that simply omitted it was reused - its completed
    # chunks trusted without ever proving they were decrypted with this key. The
    # downloader has written aes_key/nonce since v1.1.0 (format version 1), so a
    # keyless state is tampered, not legacy; fail closed and start fresh.
    metadata = state.metadata or {}
    if metadata.get("aes_key") != aes_key.hex():
        return False
    if metadata.get("nonce") != nonce.hex():
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


def _verify_file_on_disk(
    all_chunks: list[Chunk],
    aes_key: bytes,
    nonce: bytes,
    mac_iv_a32: list[int],
    destination: Path,
) -> bool:
    """Re-MAC the file ON DISK and compare against the MAC in the file key.

    The per-chunk MACs kept in the resume state are computed from each chunk's
    plaintext in memory as it downloads, so combining THOSE only proves the
    transfer decoded correctly - not that the bytes the user is left with match.
    A chunk written by an earlier run against a destination that was replaced
    since, or a silent disk write fault, leaves a stored MAC describing bytes
    the file no longer holds, and the check passed regardless.

    The destination file IS the decrypted plaintext (`fetch_chunk` writes each
    chunk's plaintext at its offset), so reading it back and re-MACing is a true
    check of the file that exists. It runs only when `verify_integrity` is on,
    which is the point of that flag; the cost is one sequential read pass, small
    beside the download it follows. Any read short of a chunk's length -
    truncation, a missing file - fails closed.

    The transfer code calls this directly with the nonce it already holds;
    `verify_file_integrity` is the 1.x-compatible wrapper that pulls the nonce
    and destination out of the resume state.
    """
    macs: list[bytes] = []
    try:
        with open(destination, "rb") as f:
            for c in all_chunks:
                f.seek(c.offset)
                data = f.read(c.size)
                if len(data) != c.size:
                    log.error(
                        "Integrity check: chunk %d reads %d bytes from disk, expected %d",
                        c.index,
                        len(data),
                        c.size,
                    )
                    return False
                macs.append(chunk_mac(data, aes_key, nonce))
    except OSError as exc:
        log.error("Integrity check could not read the destination: %s", exc)
        return False
    condensed = condense_mac(combine_chunk_macs(macs, aes_key))
    return condensed[0] == mac_iv_a32[0] and condensed[1] == mac_iv_a32[1]


def verify_file_integrity(
    state: TransferState,
    all_chunks: list[Chunk],
    aes_key: bytes,
    mac_iv_a32: list[int],
) -> bool:
    """Verify the downloaded file against the MAC embedded in its key.

    Kept at its 1.x signature. It now checks the bytes ON DISK rather than the
    MACs stored in `state` (see `_verify_file_on_disk` for why), taking the
    nonce and destination the disk check needs from the resume state, which
    records both. Fails closed if the state does not carry a usable nonce.
    """
    nonce_hex = (state.metadata or {}).get("nonce")
    if not nonce_hex:
        log.error("Integrity check: resume state carries no nonce; cannot verify")
        return False
    try:
        nonce = bytes.fromhex(nonce_hex)
    except (TypeError, ValueError):
        log.error("Integrity check: resume state nonce is not valid hex")
        return False
    # `chunk_mac` uses `nonce + nonce` as the 16-byte CBC IV, so a nonce that is
    # not 8 bytes would raise a raw crypto error from inside the MAC rather than
    # fail closed. A valid-hex nonce of the wrong length is exactly the case
    # `bytes.fromhex` cannot catch.
    if len(nonce) != _NONCE_BYTES:
        log.error(
            "Integrity check: resume state nonce is %d bytes, expected %d", len(nonce), _NONCE_BYTES
        )
        return False
    return _verify_file_on_disk(all_chunks, aes_key, nonce, mac_iv_a32, Path(state.destination))
