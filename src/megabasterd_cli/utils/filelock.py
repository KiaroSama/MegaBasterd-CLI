"""Cross-platform advisory file lock shared by the queue and config stores.

`msvcrt.locking` on Windows and `fcntl.flock` on POSIX both block other
processes AND other open descriptors in the same process, so two store
instances anywhere (threads, instances, or processes) are serialized.
Acquisition is bounded by a timeout and never silently skipped.
"""

from __future__ import annotations

import contextlib
import os
import time
from pathlib import Path


class FileLockError(Exception):  # noqa: N818 - a timeout, not a generic error
    """Raised when the advisory file lock cannot be acquired in time."""


class FileLock:
    """A bounded, cross-platform exclusive lock backed by a sidecar file."""

    def __init__(self, path: Path, message: str | None = None):
        self.path = path
        self._message = message
        self._fd: int | None = None

    def acquire(self, timeout: float) -> None:
        deadline = time.monotonic() + max(0.0, timeout)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(self.path), os.O_CREAT | os.O_RDWR)
        try:
            while True:
                try:
                    if os.name == "nt":
                        # msvcrt only exists on Windows; fcntl only on POSIX.
                        # Each platform's module is invisible to mypy on the
                        # other, so both branches are attribute-ignored.
                        import msvcrt  # type: ignore[import-not-found, unused-ignore]

                        os.lseek(fd, 0, os.SEEK_SET)
                        msvcrt.locking(  # type: ignore[attr-defined, unused-ignore]
                            fd,
                            msvcrt.LK_NBLCK,  # type: ignore[attr-defined, unused-ignore]
                            1,
                        )
                    else:
                        import fcntl  # type: ignore[import-not-found, unused-ignore]

                        fcntl.flock(  # type: ignore[attr-defined, unused-ignore]
                            fd,
                            fcntl.LOCK_EX | fcntl.LOCK_NB,  # type: ignore[attr-defined, unused-ignore]
                        )
                    self._fd = fd
                    return
                except OSError:
                    if time.monotonic() >= deadline:
                        msg = self._message or (
                            f"Could not acquire the lock {self.path.name} within "
                            f"{timeout:.0f}s; another operation is holding it. "
                            "Retry after it finishes."
                        )
                        raise FileLockError(msg) from None
                    time.sleep(0.05)
        except BaseException:
            if self._fd is None:
                os.close(fd)
            raise

    def release(self) -> None:
        fd, self._fd = self._fd, None
        if fd is None:
            return
        try:
            if os.name == "nt":
                import msvcrt  # type: ignore[import-not-found, unused-ignore]

                os.lseek(fd, 0, os.SEEK_SET)
                with contextlib.suppress(OSError):
                    msvcrt.locking(  # type: ignore[attr-defined, unused-ignore]
                        fd,
                        msvcrt.LK_UNLCK,  # type: ignore[attr-defined, unused-ignore]
                        1,
                    )
            else:
                import fcntl  # type: ignore[import-not-found, unused-ignore]

                with contextlib.suppress(OSError):
                    fcntl.flock(fd, fcntl.LOCK_UN)  # type: ignore[attr-defined, unused-ignore]
        finally:
            os.close(fd)
