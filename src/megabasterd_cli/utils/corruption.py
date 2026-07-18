"""Preserve the bytes of a corrupt file before anything can overwrite it.

Shared by `ConfigStore` and `QueueManager` (and any future store with the same
contract), because both previously skipped the backup whenever ANY older
`.corrupt.*` file existed: a second, different corruption episode was silently
destroyed by the recovery that followed it.

Enforced invariant:

    Every distinct corrupt CONTENT is preserved at least once. Backups are
    deduplicated by content hash, never by "some backup already exists", and
    the caller only learns a backup exists if the write actually succeeded.
"""

from __future__ import annotations

import contextlib
import hashlib
import logging
import os
import time
from pathlib import Path

log = logging.getLogger(__name__)

# Enough to make an accidental collision between two corrupt payloads
# implausible, while keeping the filename readable.
_DIGEST_CHARS = 16


def content_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:_DIGEST_CHARS]


def existing_backup_for(path: Path, data: bytes) -> Path | None:
    """Return the backup already holding exactly `data`, if there is one.

    The digest in the filename only narrows the search; the bytes are compared
    before adopting a file, so an unrelated file that happens to sit on the
    name can never be mistaken for this episode's backup.
    """
    digest = content_digest(data)
    for candidate in sorted(path.parent.glob(f"{path.name}.corrupt.*-{digest}.json")):
        with contextlib.suppress(OSError):
            if candidate.read_bytes() == data:
                return candidate
    return None


def preserve_corrupt_file(path: Path, data: bytes) -> Path | None:
    """Save `data` beside `path` as one timestamped, content-addressed backup.

    Returns the backup path for THIS episode (existing or newly written), or
    None when nothing could be written — callers must not claim a backup was
    made on None.

    Re-reading the same corrupt file does not pile up duplicates: the content
    hash in the name makes the check exact. A different corruption always gets
    its own file. The exclusive create keeps two processes that detect the same
    corruption in the same second from writing over each other.
    """
    digest = content_digest(data)
    existing = existing_backup_for(path, data)
    if existing is not None:
        return existing
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    for attempt in range(100):
        suffix = "" if attempt == 0 else f".{attempt}"
        backup = path.parent / f"{path.name}.corrupt.{stamp}{suffix}-{digest}.json"
        try:
            fd = os.open(str(backup), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            # Same content, same second, another process: adopt its file.
            if backup.exists() and backup.read_bytes() == data:
                return backup
            continue  # a genuine name collision: try the next suffix
        except OSError as exc:
            log.warning("Could not preserve the corrupt file: %s", type(exc).__name__)
            return None
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)  # byte-for-byte
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            log.warning("Could not write the corrupt-file backup: %s", type(exc).__name__)
            with contextlib.suppress(OSError):
                backup.unlink()
            return None
        log.warning("Preserved corrupt file as %s", backup.name)
        return backup
    log.warning("Could not find a free backup name for %s", path.name)
    return None
