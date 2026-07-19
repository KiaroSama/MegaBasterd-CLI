"""Source-file identity and resume-state addressing for uploads.

Split out of `core.uploader`. Answers exactly two questions, both of them
pure functions of the local file:

* WHERE does this source's resume state live? (`upload_state_destination`)
* Is the file on disk still byte-for-byte the one the transfer started with?
  (`source_identity` / `identities_match` / `is_resumable_upload_state`)

`core.uploader` re-exports every name here, so the public surface is unchanged.
"""

from __future__ import annotations

import hashlib
import logging
import threading
from pathlib import Path

from ..utils.helpers import sanitize_filename
from .errors import TransferError
from .state import TransferState

log = logging.getLogger(__name__)

# Versioned identity of the local source file stored in upload resume state.
# v2 uses a FULL streaming SHA-256 of the content plus path/size/mtime_ns and
# the platform file id, so resume/finalization detects any byte change
# anywhere in the file. v1 (a sampled head/middle/tail fingerprint) is never
# treated as a strict identity: v1 or missing identities restart fresh.
SOURCE_IDENTITY_VERSION = 2
_HASH_BLOCK = 1024 * 1024  # Streaming hash block size (bounded memory).
_HASH_LOG_THRESHOLD = 256 * 1024 * 1024  # Log hashing cost above this size.


def upload_state_destination(source: Path) -> Path:
    from ..config import data_dir

    identity = f"{source.resolve()}|{source.stat().st_size}".encode("utf-8", errors="replace")
    digest = hashlib.sha256(identity).hexdigest()[:24]
    return data_dir() / "upload-state" / f"{sanitize_filename(source.name)}.{digest}.upload"


def file_sha256(source: Path, size: int, stop_event: threading.Event | None = None) -> str:
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


def source_identity(source: Path, stop_event: threading.Event | None = None) -> dict:
    """Snapshot the properties that must be unchanged to resume/finalize."""
    st = source.stat()
    identity: dict = {
        "v": SOURCE_IDENTITY_VERSION,
        "path": str(source.resolve()),
        "size": st.st_size,
        "mtime_ns": st.st_mtime_ns,
        "sha256": file_sha256(source, st.st_size, stop_event),
    }
    # Platform file identity (inode / NTFS file index) when available.
    if getattr(st, "st_ino", 0):
        identity["file_id"] = f"{getattr(st, 'st_dev', 0)}:{st.st_ino}"
    return identity


def identities_match(recorded: dict | None, current: dict) -> bool:
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


def is_resumable_upload_state(
    state: TransferState, source: Path, file_size: int, identity: dict
) -> bool:
    """Resume only when the state provably belongs to this exact file."""
    if state.transfer_type != "upload":
        return False
    if state.total_size != file_size or state.source != str(source):
        return False
    return identities_match((state.metadata or {}).get("source_identity"), identity)
