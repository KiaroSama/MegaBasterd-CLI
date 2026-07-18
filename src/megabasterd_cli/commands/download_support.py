"""Per-transfer execution helpers behind `mb download`.

Split out of `download_cmd.py`, which had grown past 800 lines. Everything here
runs AFTER Click has parsed the command line: it drives one file or folder
transfer, renders progress, and reports results. The Click command itself, its
options, and link expansion stay in `download_cmd.py`.
"""

from __future__ import annotations

import logging
from pathlib import Path

import click

from ..core.errors import MegaError
from ..core.folder_downloader import MegaFolderDownloader
from ..ui.machine_output import MachineOutput, error_code_for
from ..ui.prompts import print_error, print_info, print_success
from ..ui.transfer_progress import TransferProgress, redact_link
from ..utils.helpers import format_bytes
from ..utils.hooks import run_post_transfer_command
from ..utils.selection import SelectionCancelled, parse_selection_tokens

log = logging.getLogger(__name__)


def _interactive_file_picker(output_dir: Path):
    """Build a file_filter that lists the folder's files and asks what to keep."""

    def _pick(file_jobs):
        click.echo(f"\nFolder contains {len(file_jobs)} file(s):")
        total_size = 0
        for index, (node, destination) in enumerate(file_jobs, 1):
            size = int(node.size or 0)
            total_size += size
            try:
                relative = destination.relative_to(output_dir).as_posix()
            except ValueError:
                relative = destination.name
            click.echo(f"  {index:3d}. {format_bytes(size):>12}  {relative}")
        click.echo(f"Total: {format_bytes(total_size)}")
        while True:
            answer = click.prompt(
                "Files to download (e.g. 1,3-5 | all | none)",
                default="all",
                show_default=True,
            )
            try:
                chosen = parse_selection_tokens(answer, len(file_jobs))
            except ValueError as exc:
                click.echo(f"Invalid selection: {exc}")
                continue
            if not chosen:
                raise SelectionCancelled()
            return [job for index, job in enumerate(file_jobs, 1) if index in chosen]

    return _pick


def _run_hook_for(path: Path, run_command: str | None) -> None:
    """Run the post-transfer hook for a finished file.

    `run_command` is passed in DELIBERATELY. This used to read
    `click.get_current_context()`, which is thread-local: in a parallel
    download (`-P N`) every transfer runs on a worker thread, the context was
    None there, and the user's configured hook silently never ran.
    """
    if run_command:
        run_post_transfer_command(run_command, path)


def _download_file(
    downloader,
    url,
    output_dir,
    progress: TransferProgress,
    password=None,
    rename_to=None,
    machine: MachineOutput | None = None,
    run_command: str | None = None,
) -> bool:
    machine = machine or MachineOutput(False)
    item = progress.add_item(redact_link(url), status="active")

    def on_progress(p):
        progress.update_item(item, p.bytes_done, p.total_bytes)

    try:
        result = downloader.download_link(
            url,
            output_dir,
            password=password,
            rename_to=rename_to,
            on_progress=on_progress,
        )
        progress.set_item_name(item, result.path.name)
        progress.update_item(item, result.size, result.size)
        progress.finish_item(item, "complete")
        print_success(
            f"{result.path.name} ({format_bytes(result.size)}) " f"in {result.elapsed_seconds:.1f}s"
        )
        machine.emit(
            event="result",
            type="download",
            status="success",
            name=result.path.name,
            path=str(result.path),
            size=result.size,
            elapsed_seconds=round(result.elapsed_seconds, 2),
            integrity_ok=result.integrity_ok,
        )
        _run_hook_for(result.path, run_command)
        return True
    except MegaError as e:
        progress.finish_item(item, "failed")
        print_error(f"Download failed: {e}")
        machine.emit(
            event="result",
            type="download",
            status="failed",
            source=redact_link(url),
            error_code=error_code_for(e),
            error=str(e),
        )
        return False
    except Exception as e:
        log.exception("Unexpected error during download")
        progress.finish_item(item, "failed")
        print_error(f"Unexpected error: {e}")
        machine.emit(
            event="result",
            type="download",
            status="failed",
            source=redact_link(url),
            error_code=error_code_for(e),
            error=str(e),
        )
        return False
    finally:
        if downloader.api is not None:
            downloader.api.close()


def _download_folder(
    downloader,
    url,
    output_dir,
    parallel_files: int = 1,
    file_filter=None,
    quiet: bool = False,
    machine: MachineOutput | None = None,
    run_command: str | None = None,
) -> bool:
    machine = machine or MachineOutput(False)
    folder_dl = MegaFolderDownloader(downloader)
    items: dict[str, str] = {}  # destination str -> progress item key
    progress = TransferProgress(
        title="MEGA Folder Download",
        direction="download",
        details=[
            f"Source: {redact_link(url)}",
            f"Output: {output_dir}",
            "",
            "Backend: MegaBasterd-CLI",
        ],
        quiet=quiet,
    )

    def _relative_name(path: Path) -> str:
        try:
            return str(path.relative_to(output_dir))
        except ValueError:
            return path.name

    def on_manifest(file_jobs):
        for node, destination in file_jobs:
            items[str(destination)] = progress.add_item(
                _relative_name(destination), int(node.size or 0)
            )

    def _item_for(path: Path) -> str:
        key = str(path)
        if key not in items:
            items[key] = progress.add_item(_relative_name(path))
        return items[key]

    def on_file_progress(path: Path, p):
        progress.update_item(_item_for(path), p.bytes_done, p.total_bytes)

    def on_file_done(result):
        progress.finish_item(_item_for(result.path), "complete")
        machine.emit(
            event="result",
            type="download",
            status="success",
            name=result.path.name,
            path=str(result.path),
            size=result.size,
            elapsed_seconds=round(result.elapsed_seconds, 2),
            integrity_ok=result.integrity_ok,
        )

    def on_file_failed(path: Path, exc: Exception):
        progress.finish_item(_item_for(path), "failed")
        machine.emit(
            event="result",
            type="download",
            status="failed",
            name=path.name,
            path=str(path),
            error_code=error_code_for(exc),
            error=str(exc),
        )

    try:
        with progress:
            results = folder_dl.download_folder(
                url,
                output_dir,
                on_file_done=on_file_done,
                on_folder_manifest=on_manifest,
                on_file_progress=on_file_progress,
                parallel_files=parallel_files,
                file_filter=file_filter,
                on_file_failed=on_file_failed,
            )
        total_bytes = sum(r.size for r in results)
        print_success(f"Folder complete: {len(results)} files, {format_bytes(total_bytes)} total")
        machine.emit(
            event="summary",
            type="download",
            status="success",
            source=redact_link(url),
            files=len(results),
            total_bytes=total_bytes,
        )
        for result in results:
            _run_hook_for(result.path, run_command)
        return True
    except SelectionCancelled:
        # Documented behavior: answering "none" skips the folder and is NOT a
        # failure (exit stays zero if nothing else failed).
        print_info(f"Selection cancelled; skipped folder: {redact_link(url)}")
        machine.emit(event="result", type="download", status="skipped", source=redact_link(url))
        return True
    except MegaError as e:
        print_error(f"Folder download failed: {e}")
        machine.emit(
            event="summary",
            type="download",
            status="failed",
            source=redact_link(url),
            error_code=error_code_for(e),
            error=str(e),
        )
        return False
    except Exception as e:
        log.exception("Unexpected error during folder download")
        print_error(f"Unexpected error: {e}")
        machine.emit(
            event="summary",
            type="download",
            status="failed",
            source=redact_link(url),
            error_code=error_code_for(e),
            error=str(e),
        )
        return False
    finally:
        if downloader.api is not None:
            downloader.api.close()


def _download_folder_file(
    downloader,
    url,
    output_dir,
    progress: TransferProgress,
    file_filter=None,
    machine: MachineOutput | None = None,
    run_command: str | None = None,
) -> bool:
    machine = machine or MachineOutput(False)
    folder_dl = MegaFolderDownloader(downloader)
    items: dict[str, str] = {}

    def _item_for(path: Path) -> str:
        key = str(path)
        if key not in items:
            items[key] = progress.add_item(path.name)
        return items[key]

    def on_file_progress(path: Path, p):
        progress.update_item(_item_for(path), p.bytes_done, p.total_bytes)

    def on_file_done(result):
        progress.finish_item(_item_for(result.path), "complete")
        machine.emit(
            event="result",
            type="download",
            status="success",
            name=result.path.name,
            path=str(result.path),
            size=result.size,
            elapsed_seconds=round(result.elapsed_seconds, 2),
            integrity_ok=result.integrity_ok,
        )

    def on_file_failed(path: Path, exc: Exception):
        progress.finish_item(_item_for(path), "failed")
        machine.emit(
            event="result",
            type="download",
            status="failed",
            name=path.name,
            path=str(path),
            error_code=error_code_for(exc),
            error=str(exc),
        )

    try:
        results = folder_dl.download_node_in_folder(
            url,
            output_dir,
            on_file_progress=on_file_progress,
            on_file_done=on_file_done,
            on_file_failed=on_file_failed,
            file_filter=file_filter,
        )
        result = results[0] if results else None
        if result is None:
            print_success("Folder complete: 0 files, 0 B total")
            return True
        if len(results) == 1:
            print_success(
                f"{result.path} ({format_bytes(result.size)}) " f"in {result.elapsed_seconds:.1f}s"
            )
        else:
            total_bytes = sum(item.size for item in results)
            print_success(
                f"Folder complete: {len(results)} files, {format_bytes(total_bytes)} total"
            )
        for item in results:
            _run_hook_for(item.path, run_command)
        return True
    except SelectionCancelled:
        print_info(f"Selection cancelled; skipped folder node: {redact_link(url)}")
        machine.emit(event="result", type="download", status="skipped", source=redact_link(url))
        return True
    except MegaError as e:
        print_error(f"Download failed: {e}")
        machine.emit(
            event="result",
            type="download",
            status="failed",
            source=redact_link(url),
            error_code=error_code_for(e),
            error=str(e),
        )
        return False
    except Exception as e:
        log.exception("Unexpected error during folder-file download")
        print_error(f"Unexpected error: {e}")
        machine.emit(
            event="result",
            type="download",
            status="failed",
            source=redact_link(url),
            error_code=error_code_for(e),
            error=str(e),
        )
        return False
    finally:
        if downloader.api is not None:
            downloader.api.close()
