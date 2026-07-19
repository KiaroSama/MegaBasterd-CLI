"""Local directory walking and whole-tree upload.

Split out of `core.uploader`. Owns the decision of WHAT gets uploaded from a
directory (`walk_upload_entries`) and the mirroring of that local tree into
remote folders (`upload_directory`), delegating every actual file transfer
back to the uploader's `upload_file`.

`upload_directory` takes the uploader as its first argument and is installed as
`MegaUploader.upload_directory`, so callers keep the bound method they had.

`core.uploader` re-exports every name here, so the public surface is unchanged.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from .errors import TransferError

if TYPE_CHECKING:  # Avoids a runtime cycle: uploader imports this module.
    from .uploader import UploadProgress, UploadResult

log = logging.getLogger(__name__)


def walk_upload_entries(root: Path) -> tuple[list[Path], int]:
    """Sorted ``rglob("*")`` of `root` with every symlink skipped.

    A symlinked FILE passes `is_file()` and would be uploaded, publishing
    whatever it points at (`notes.lnk -> ~/.ssh/id_rsa`); a symlinked DIRECTORY
    would be recreated as an empty remote folder, silently producing an
    incomplete tree. Anything below a skipped symlinked directory is skipped
    too. Returns the kept entries and how many were skipped, so callers can
    tell the user the upload is deliberately incomplete.
    """
    kept: list[Path] = []
    skipped_dirs: set[Path] = set()
    skipped = 0
    # Sorting puts a parent directly before its children, so a symlinked
    # directory is always recorded before the entries underneath it.
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            skipped_dirs.add(path)
            skipped += 1
            continue
        if skipped_dirs and any(parent in skipped_dirs for parent in path.parents):
            skipped += 1
            continue
        kept.append(path)
    return kept, skipped


def upload_directory(
    up,  # MegaUploader
    source_dir: Path,
    target_handle: str | None = None,
    on_progress: Callable[[UploadProgress], None] | None = None,
    on_file_done: Callable[[UploadResult, Path], None] | None = None,
    keep_going: bool = False,
    on_manifest: Callable[[list[tuple[Path, int]]], None] | None = None,
    on_file_progress: Callable[[Path, UploadProgress], None] | None = None,
) -> list[UploadResult]:
    """Upload an entire local directory tree, preserving structure.

    Creates remote folders as needed and uploads each file in place.
    `on_manifest` receives the complete `(path, size)` file list before any
    byte is uploaded; `on_file_progress` identifies which file a progress
    report belongs to. Remote directory creation is not part of the byte
    totals.
    """
    up.last_directory_failures = []
    if not source_dir.is_dir():
        raise FileNotFoundError(f"Not a directory: {source_dir}")

    # Complete file manifest first: total files and bytes are known before
    # any upload starts. Symlinks are excluded, so the manifest is the
    # truth about what will actually be uploaded.
    entries, skipped_links = walk_upload_entries(source_dir)
    if skipped_links:
        log.warning(
            "Skipped %d symlink(s) under %s; symlinked files are never uploaded, "
            "so the remote tree is deliberately incomplete.",
            skipped_links,
            source_dir,
        )
    if on_manifest:
        on_manifest([(p, p.stat().st_size) for p in entries if p.is_file()])

    base_parent = target_handle or up.client.find_root()
    if not base_parent:
        raise TransferError(message="No target folder available")

    # Map local Path → remote handle
    handle_for: dict[Path, str] = {source_dir: base_parent}
    # Create the root remote folder
    root_handle = up.client.mkdir(source_dir.name, parent_handle=base_parent)
    handle_for[source_dir] = root_handle

    results: list[UploadResult] = []
    failures: list[str] = []
    failed_dirs: set[Path] = set()
    for local_path in entries:
        if any(parent in failed_dirs for parent in local_path.parents):
            failures.append(f"{local_path}: parent folder creation failed")
            continue
        try:
            if local_path.is_dir():
                parent_remote = handle_for.get(local_path.parent, root_handle)
                handle_for[local_path] = up.client.mkdir(
                    local_path.name, parent_handle=parent_remote
                )
            elif local_path.is_file():
                parent_remote = handle_for.get(local_path.parent, root_handle)

                def _file_progress(p: UploadProgress, fp: Path = local_path) -> None:
                    if on_file_progress:
                        on_file_progress(fp, p)
                    if on_progress:
                        on_progress(p)

                result = up.upload_file(
                    local_path,
                    target_handle=parent_remote,
                    on_progress=(_file_progress if (on_file_progress or on_progress) else None),
                )
                results.append(result)
                if on_file_done:
                    on_file_done(result, local_path)
        except Exception as exc:  # noqa: BLE001
            log.error("Failed to upload %s: %s", local_path, exc)
            failures.append(f"{local_path}: {exc}")
            if local_path.is_dir():
                failed_dirs.add(local_path)

    up.last_directory_failures = list(failures)
    if failures and not keep_going:
        sample = "; ".join(failures[:3])
        more = "" if len(failures) <= 3 else f"; and {len(failures) - 3} more"
        raise TransferError(message=f"{len(failures)} upload item(s) failed: {sample}{more}")

    return results
