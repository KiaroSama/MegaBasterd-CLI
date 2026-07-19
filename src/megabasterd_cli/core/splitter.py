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
import os
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

# Same temp-file-then-os.replace helper the Crypter uses, including its Windows
# PermissionError retry and its BaseException cleanup. Reused rather than copied
# so both paths keep the same durability guarantees.
from .crypter import _atomic_output

_PART_RE = re.compile(r"^(?P<base>.+)\.part(?P<idx>\d+)-(?P<total>\d+)$")


class SplitterError(Exception):
    pass


class SplitterAliasError(SplitterError):
    """An output path is (or resolves to) one of the input files.

    Refused before anything is written: merging into one of its own parts
    truncated that part and then fed the merge its own tail, destroying the
    input and growing the file without bound.
    """


def _is_same_file(a: Path, b: Path) -> bool:
    """True when `a` and `b` name the same file, even if one does not exist yet.

    `os.path.samefile` is the authoritative test - it sees through hard links,
    symlinks and case-insensitive filesystems - but it needs both paths to
    exist, and a merge target usually does not. Fall back to comparing fully
    resolved paths in that case.
    """
    try:
        return os.path.samefile(a, b)
    except OSError:
        return os.path.normcase(os.path.realpath(a)) == os.path.normcase(os.path.realpath(b))


def _reject_aliases(outputs: Iterable[Path], inputs: Iterable[Path], action: str) -> None:
    """Refuse, before writing anything, to use one of our inputs as an output.

    Truncating an input and then reading it back is a self-feeding loop: the
    merge appends to the very file it is still reading, so the file grows
    without bound until the disk fills, and the original part is gone.
    """
    sources = list(inputs)
    for out in outputs:
        for src in sources:
            if _is_same_file(out, src):
                raise SplitterAliasError(
                    f"{action} refused: output {out} is the same file as input {src}"
                )


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

    parts = [out_dir / f"{source.name}.part{idx}-{num_parts}" for idx in range(1, num_parts + 1)]
    sha_path = out_dir / f"{source.name}.sha1"
    _reject_aliases([*parts, sha_path], [source], "split")

    sha = hashlib.sha1()
    written = 0
    with open(source, "rb") as fin:
        for part_path in parts:
            remaining = bytes_per_part
            # Atomic: an interrupt must not leave a truncated part that looks
            # exactly like a complete one.
            with _atomic_output(part_path) as fout:
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

    digest = sha.hexdigest()
    with _atomic_output(sha_path) as fout:
        fout.write((digest + "\n").encode("ascii"))
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
    sha_file = part_dir / f"{base}.sha1"
    _reject_aliases([target], [*parts, sha_file], "merge")

    expected: str | None = None
    if verify_sha1 and sha_file.is_file():
        expected = sha_file.read_text(encoding="ascii").strip().split()[0].lower()

    sha = hashlib.sha1()
    total_size = sum(p.stat().st_size for p in parts)
    written = 0
    with _atomic_output(target) as fout:
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

        # Inside the atomic block on purpose: a bad checksum must abort the
        # replace, so a pre-existing target survives a failed merge intact.
        if expected is not None:
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
