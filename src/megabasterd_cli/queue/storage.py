"""Atomic on-disk write for the queue file."""

from __future__ import annotations

import contextlib
import os
import tempfile
import time
from pathlib import Path


def atomic_write_text(path: Path, payload: str) -> None:
    """Replace ``path`` with ``payload`` atomically, never leaving it partial.

    The caller is responsible for creating the parent directory and for
    building the payload BEFORE calling this, so a serialization failure
    leaves the original file untouched.
    """
    # Unique temp file per save: concurrent savers can never collide
    # on one temp name.
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        prefix=path.name + ".",
        suffix=".tmp",
        delete=False,
    ) as tf:
        tf.write(payload)
        tf.flush()
        os.fsync(tf.fileno())
        tmp_path = tf.name
    for attempt in range(5):
        try:
            os.replace(tmp_path, path)
            break
        except PermissionError:
            # Windows: transient lock by AV/another replace.
            if attempt == 4:
                raise
            time.sleep(0.05 * (attempt + 1))
    # Best effort: persist the directory entry on POSIX.
    if hasattr(os, "O_DIRECTORY"):
        with contextlib.suppress(OSError):
            dfd = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
