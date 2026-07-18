"""Small helper functions used across modules."""

from __future__ import annotations

import contextlib
import os
import re
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Callable

_INVALID_FILENAME_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


def sanitize_filename(name: str, replacement: str = "_") -> str:
    """Replace characters that are invalid in filenames on Windows/Linux/macOS.

    The result is always a safe *single* path component: it can never be empty,
    ".", "..", or a name made only of dots/whitespace, and it never contains a
    path separator. This stops attacker-controlled remote node names from being
    used for directory traversal (e.g. a folder share whose node name is "..").
    """
    cleaned = _INVALID_FILENAME_CHARS.sub(replacement, name).strip()
    # Windows ignores trailing dots and spaces; drop them so "evil." or "name "
    # cannot silently collide with, or escape past, a real name.
    cleaned = cleaned.rstrip(" .")
    # Reject empty, dot-only, or whitespace-only components (".", "..", "...").
    if not cleaned or set(cleaned) <= {".", " "}:
        cleaned = "unnamed"
    reserved = (
        {"CON", "PRN", "AUX", "NUL"}
        | {f"COM{i}" for i in range(1, 10)}
        | {f"LPT{i}" for i in range(1, 10)}
    )
    base = cleaned.split(".")[0].upper()
    if base in reserved:
        cleaned = "_" + cleaned
    # Cap at 240 chars to leave room for paths
    if len(cleaned) <= 240:
        return cleaned
    suffix = Path(cleaned).suffix
    if suffix and len(suffix) < 32:
        return cleaned[: 240 - len(suffix)] + suffix
    return cleaned[:240]


def format_bytes(num: int) -> str:
    """Render a byte count as a human-readable string (KB / MB / GB)."""
    if num < 0:
        return f"-{format_bytes(-num)}"
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if num < 1024:
            return f"{num:.2f} {unit}" if unit != "B" else f"{num} B"
        num /= 1024
    return f"{num:.2f} EB"


def format_speed(bytes_per_sec: float) -> str:
    return f"{format_bytes(int(bytes_per_sec))}/s"


def format_eta(seconds: float) -> str:
    """Format a duration as H:MM:SS or M:SS."""
    if seconds < 0 or seconds == float("inf"):
        return "--:--"
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h:d}:{m:02d}:{s:02d}"
    return f"{m:02d}:{s:02d}"


def ensure_unique_path(path: Path) -> Path:
    """If `path` exists, append (1), (2), etc. until a free name is found.

    NOTE: this check is not atomic; concurrent transfers must go through
    `claim_destination` instead, which combines the uniqueness walk with a
    process-wide reservation.
    """
    if not path.exists():
        return path
    for candidate in _numbered_candidates(path):
        if not candidate.exists():
            return candidate
    raise AssertionError("unreachable")  # pragma: no cover - generator is infinite


def _numbered_candidates(path: Path) -> Iterator[Path]:
    """Yield `path`, then `path (1)`, `path (2)`, ..."""
    yield path
    stem, suffix = path.stem, path.suffix
    i = 1
    while True:
        yield path.parent / f"{stem} ({i}){suffix}"
        i += 1


# Destination reservations. One claimed path belongs to exactly one in-flight
# transfer, so parallel downloads with identical (or sanitization/truncation-
# colliding) names can never write to the same file or share a state file.
#
# Two layers, because a `threading.Lock` cannot see another OS process:
#   * `_claimed_destinations` - fast in-process bookkeeping;
#   * a `.mbclaim` sidecar holding an ADVISORY FILE LOCK for the lifetime of
#     the transfer, which is what makes two independent `mb` processes
#     mutually exclusive.
#
# The file lock is deliberately chosen over a marker file: the OS drops it when
# the owning process exits for any reason, so a crash can never leave a stale
# reservation that permanently blocks a valid future transfer.
CLAIM_SUFFIX = ".mbclaim"

_claimed_destinations: set[str] = set()
_claim_locks: dict[str, object] = {}
_claim_lock = threading.Lock()


def _claim_lock_path(candidate: Path) -> Path:
    return candidate.parent / (candidate.name + CLAIM_SUFFIX)


def claim_destination(
    path: Path,
    overwrite: bool = False,
    is_resumable: Callable[[Path], bool] | None = None,
) -> Path:
    """Atomically reserve a destination for exactly one transfer, process-wide.

    Walks `path`, `path (1)`, ... and claims the first candidate that is not
    reserved by another transfer IN ANY PROCESS and either does not exist on
    disk, may be overwritten, or is a resumable continuation of this exact
    transfer (as decided by `is_resumable`). Call `release_destination` when
    done.
    """
    from .filelock import FileLock, FileLockError

    with _claim_lock:
        for candidate in _numbered_candidates(path):
            key = os.path.normcase(str(candidate))
            if key in _claimed_destinations:
                continue
            blocked = candidate.exists() and not overwrite
            if blocked and (is_resumable is None or not is_resumable(candidate)):
                continue
            lock = FileLock(_claim_lock_path(candidate))
            try:
                # timeout=0 makes this a try-lock: a candidate held by another
                # process is skipped instead of waited on.
                lock.acquire(timeout=0)
            except (FileLockError, OSError):
                continue
            # Re-check UNDER the reservation: this closes the TOCTOU window in
            # which another process created the file between our existence
            # check and our claim.
            still_blocked = candidate.exists() and not overwrite
            if still_blocked and (is_resumable is None or not is_resumable(candidate)):
                lock.release()
                continue
            _claimed_destinations.add(key)
            _claim_locks[key] = lock
            return candidate
    raise AssertionError("unreachable")  # pragma: no cover - generator is infinite


def release_destination(path: Path) -> None:
    """Release a reservation made by `claim_destination`."""
    with _claim_lock:
        key = os.path.normcase(str(path))
        _claimed_destinations.discard(key)
        lock = _claim_locks.pop(key, None)
    if lock is not None:
        lock.release()  # type: ignore[attr-defined]
        # Best effort: another process may already hold the sidecar again.
        with contextlib.suppress(OSError):
            _claim_lock_path(Path(path)).unlink()


def file_md5(path: Path, chunk: int = 65536) -> str:
    """Compute MD5 of a local file (hex)."""
    import hashlib

    h = hashlib.md5()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def is_within_directory(base: Path, target: Path) -> bool:
    """Return True only when `target` resolves to a location inside `base`.

    Resolves symlinks/`..` segments without requiring `target` to exist, then
    compares using `os.path.commonpath` (not a string prefix, which would treat
    `/out-evil` as inside `/out`). Case is normalized for Windows. Returns False
    across different drives.
    """
    try:
        base_resolved = base.resolve()
        target_resolved = target.resolve()
    except (OSError, RuntimeError, ValueError):
        return False
    base_s = os.path.normcase(str(base_resolved))
    target_s = os.path.normcase(str(target_resolved))
    try:
        return os.path.commonpath([base_s, target_s]) == base_s
    except ValueError:
        # Raised when the paths are on different drives/roots.
        return False


def ensure_within_directory(base: Path, target: Path) -> Path:
    """Return `target` if it is inside `base`, otherwise raise ValueError.

    Use this as a defense-in-depth guard before creating directories, opening
    destination files, preallocating, resuming, or writing transfer state from
    paths derived from untrusted remote names.
    """
    if not is_within_directory(base, target):
        raise ValueError(f"Refusing path outside the output directory: {target}")
    return target


def available_disk_space(path: Path) -> int:
    """Return free bytes available at the given path's filesystem."""
    try:
        stat = os.statvfs(path) if hasattr(os, "statvfs") else None
        if stat:
            return stat.f_bavail * stat.f_frsize
    except OSError:
        pass
    # Windows fallback
    import shutil

    return shutil.disk_usage(str(path)).free
