"""Small helper functions used across modules."""

from __future__ import annotations

import os
import re
from pathlib import Path


_INVALID_FILENAME_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


def sanitize_filename(name: str, replacement: str = "_") -> str:
    """Replace characters that are invalid in filenames on Windows/Linux/macOS."""
    cleaned = _INVALID_FILENAME_CHARS.sub(replacement, name).strip()
    # Avoid empty names and reserved Windows names
    if not cleaned:
        cleaned = "unnamed"
    reserved = {"CON", "PRN", "AUX", "NUL"} | {f"COM{i}" for i in range(1, 10)} | {f"LPT{i}" for i in range(1, 10)}
    base = cleaned.split(".")[0].upper()
    if base in reserved:
        cleaned = "_" + cleaned
    # Cap at 240 chars to leave room for paths
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
    """If `path` exists, append (1), (2), etc. until a free name is found."""
    if not path.exists():
        return path
    stem, suffix = path.stem, path.suffix
    parent = path.parent
    i = 1
    while True:
        candidate = parent / f"{stem} ({i}){suffix}"
        if not candidate.exists():
            return candidate
        i += 1


def file_md5(path: Path, chunk: int = 65536) -> str:
    """Compute MD5 of a local file (hex)."""
    import hashlib

    h = hashlib.md5()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


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
