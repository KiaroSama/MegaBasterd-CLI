"""File splitter and merger.

Mirrors MegaBasterd's split/merge feature:

    Split: source.zip               → source.zip.part1-N, ..., source.zip.partN-N
                                       source.zip.sha1     (hex SHA-1 of original)

    Merge: source.zip.part1-N (+...) → source.zip
                                       (verifies SHA-1 if a .sha1 file is present)

The naming convention matches the original (`*.part<n>-<total>`), so files
produced by MegaBasterd can be merged here and vice versa.
"""

from __future__ import annotations

import contextlib
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

_PART_RE = re.compile(r"^(?P<base>.+)\.part(?P<idx>\d+)-(?P<total>\d+)$")


class SplitterError(Exception):
    pass


@dataclass
class SplitResult:
    parts: list[Path]
    sha1: str
    total_bytes: int


def split_file(
    source: Path,
    part_size_mb: int,
    output_dir: Path | None = None,
    on_progress: Callable[[int, int], None] | None = None,
) -> SplitResult:
    """Split `source` into part files of `part_size_mb` MiB each.

    Writes `<source>.sha1` next to the parts with the SHA-1 of the original.
    Returns the list of part Paths.
    """
    if part_size_mb <= 0:
        raise SplitterError("part_size_mb must be positive")
    if not source.is_file():
        raise SplitterError(f"Not a file: {source}")

    bytes_per_part = part_size_mb * 1024 * 1024
    total = source.stat().st_size
    if total == 0:
        raise SplitterError("Cannot split an empty file")
    num_parts = (total + bytes_per_part - 1) // bytes_per_part

    out_dir = output_dir or source.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    sha = hashlib.sha1()
    parts: list[Path] = []
    written = 0
    with open(source, "rb") as fin:
        for idx in range(1, num_parts + 1):
            remaining = bytes_per_part
            part_path = out_dir / f"{source.name}.part{idx}-{num_parts}"
            with open(part_path, "wb") as fout:
                while remaining > 0:
                    block = fin.read(min(1 << 20, remaining))
                    if not block:
                        break
                    fout.write(block)
                    sha.update(block)
                    written += len(block)
                    remaining -= len(block)
                    if on_progress:
                        on_progress(written, total)
            parts.append(part_path)

    digest = sha.hexdigest()
    (out_dir / f"{source.name}.sha1").write_text(digest + "\n", encoding="ascii")
    return SplitResult(parts=parts, sha1=digest, total_bytes=total)


def merge_parts(
    first_part: Path,
    output: Path | None = None,
    verify_sha1: bool = True,
    on_progress: Callable[[int, int], None] | None = None,
    delete_parts: bool = False,
) -> Path:
    """Merge a `*.partX-N` file (and its siblings) back into the original file.

    `first_part` can be any of the parts; the base name and total count are
    inferred from the filename. The output is written next to the parts (or to
    `output` if supplied). If a `.sha1` file is present and `verify_sha1` is
    True, the merged file's hash is checked.
    """
    m = _PART_RE.match(first_part.name)
    if not m:
        raise SplitterError(f"{first_part.name!r} doesn't match the *.part<n>-<total> convention")
    base = m.group("base")
    total = int(m.group("total"))
    part_dir = first_part.parent

    parts: list[Path] = []
    for i in range(1, total + 1):
        part = part_dir / f"{base}.part{i}-{total}"
        if not part.is_file():
            raise SplitterError(f"Missing part: {part}")
        parts.append(part)

    target = output or part_dir / base
    target.parent.mkdir(parents=True, exist_ok=True)

    sha = hashlib.sha1()
    total_size = sum(p.stat().st_size for p in parts)
    written = 0
    with open(target, "wb") as fout:
        for part in parts:
            with open(part, "rb") as fin:
                while True:
                    block = fin.read(1 << 20)
                    if not block:
                        break
                    fout.write(block)
                    sha.update(block)
                    written += len(block)
                    if on_progress:
                        on_progress(written, total_size)

    sha_file = part_dir / f"{base}.sha1"
    if verify_sha1 and sha_file.is_file():
        expected = sha_file.read_text(encoding="ascii").strip().split()[0].lower()
        got = sha.hexdigest().lower()
        if expected != got:
            raise SplitterError(f"SHA-1 mismatch: expected {expected}, got {got}")

    if delete_parts:
        for part in parts:
            with contextlib.suppress(OSError):
                part.unlink()
        with contextlib.suppress(OSError, TypeError):
            sha_file.unlink(missing_ok=True)  # py3.8+: missing_ok via try

    return target
