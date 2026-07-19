"""File-selection helpers for folder-share downloads.

CLI counterpart of the original MegaBasterd ``FolderLinkDialog``: glob
include/exclude filters and an interactive numbered picker decide which files
inside a public folder share actually get downloaded.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

# A folder-download job as produced by MegaFolderDownloader._build_file_jobs.
FileJob = tuple[Any, Path]
FileFilter = Callable[[list[FileJob]], list[FileJob]]


class SelectionCancelled(Exception):  # noqa: N818 - control-flow signal, not an error
    """The user chose to download nothing from a folder share."""


def _normalize_pattern(pattern: str) -> str:
    # Accept Windows-style separators and match case-insensitively.
    return pattern.replace("\\", "/").casefold()


def _match_subjects(node: Any, destination: Path, root: Path) -> tuple[str, ...]:
    """Strings a pattern may match: folder-relative path and bare filenames."""
    try:
        relative = destination.relative_to(root).as_posix()
    except ValueError:
        relative = destination.name
    name = str(getattr(node, "name", "") or destination.name)
    return (relative.casefold(), destination.name.casefold(), name.casefold())


def _matches_any(patterns: tuple[str, ...], subjects: tuple[str, ...]) -> bool:
    return any(fnmatchcase(subject, pattern) for pattern in patterns for subject in subjects)


def build_folder_file_filter(
    include: Sequence[str],
    exclude: Sequence[str],
    root: Path,
) -> FileFilter | None:
    """Build a file-job filter from glob patterns, or None when unfiltered.

    Patterns match the file's path relative to `root` (posix separators) or
    its bare name, case-insensitively. With include patterns a file must match
    at least one of them; any exclude match removes the file (exclude wins).
    """
    # Like gitignore, an unanchored path pattern matches at any depth: try the
    # pattern as-is and with a leading "*/" against the relative path.
    include_patterns = tuple(
        variant
        for p in include
        if p
        for variant in (_normalize_pattern(p), f"*/{_normalize_pattern(p)}")
    )
    exclude_patterns = tuple(
        variant
        for p in exclude
        if p
        for variant in (_normalize_pattern(p), f"*/{_normalize_pattern(p)}")
    )
    if not include_patterns and not exclude_patterns:
        return None

    def _filter(file_jobs: list[FileJob]) -> list[FileJob]:
        kept: list[FileJob] = []
        for node, destination in file_jobs:
            subjects = _match_subjects(node, destination, root)
            if include_patterns and not _matches_any(include_patterns, subjects):
                continue
            if exclude_patterns and _matches_any(exclude_patterns, subjects):
                continue
            kept.append((node, destination))
        return kept

    return _filter


def parse_selection_tokens(text: str, count: int) -> set[int]:
    """Parse a ``1,3-5`` style selection into 1-based indexes.

    ``all``/``a``/``*`` or an empty answer selects every file; ``none``/``n``
    selects nothing. Tokens may be separated by commas or spaces; each token
    is a single index or an ``N-M`` range. Raises ValueError on malformed
    tokens or indexes outside ``1..count``.
    """
    cleaned = (text or "").strip().casefold()
    if cleaned in {"", "all", "a", "*"}:
        return set(range(1, count + 1))
    if cleaned in {"none", "n"}:
        return set()
    chosen: set[int] = set()
    for token in cleaned.replace(",", " ").split():
        first, is_range, last = token.partition("-")
        try:
            low = int(first)
            high = int(last) if is_range else low
        except ValueError as exc:
            raise ValueError(f"invalid token {token!r}") from exc
        if low < 1 or high > count or high < low:
            raise ValueError(f"token {token!r} out of range 1-{count}")
        chosen.update(range(low, high + 1))
    return chosen


def compose_file_filters(*filters: FileFilter | None) -> FileFilter | None:
    """Chain filters left-to-right, skipping Nones; None when nothing active."""
    active = [f for f in filters if f is not None]
    if not active:
        return None

    def _run(file_jobs: list[FileJob]) -> list[FileJob]:
        for step in active:
            if not file_jobs:
                break
            file_jobs = step(file_jobs)
        return file_jobs

    return _run
