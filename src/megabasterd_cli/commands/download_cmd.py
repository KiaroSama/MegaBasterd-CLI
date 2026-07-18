"""`mb download` - download files/folders from MEGA public links."""

from __future__ import annotations

import contextlib
import logging
import sys
from pathlib import Path

import click

from ..core.api import MegaAPIClient
from ..core.downloader import MegaDownloader
from ..core.errors import MegaError
from ..core.folder_downloader import MegaFolderDownloader
from ..core.links import (
    LinkType,
    decrypt_dlc_container,
    parse_link,
    resolve_elc_links,
    resolve_encrypted_container_link,
    resolve_megacrypter_link,
    resolve_password_link,
)
from ..ui.machine_output import MachineOutput
from ..ui.prompts import print_error, print_info, print_success
from ..ui.transfer_progress import TransferProgress, redact_link
from ..utils.helpers import format_bytes
from ..utils.hooks import run_post_transfer_command
from ..utils.selection import (
    SelectionCancelled,
    build_folder_file_filter,
    compose_file_filters,
    parse_selection_tokens,
)
from ..utils.speed import make_limiter

log = logging.getLogger(__name__)


def _read_links_file(path: Path) -> list[str]:
    """Read a list of MEGA URLs from a text file (one per line, # for comments)."""
    urls: list[str] = []
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            urls.append(line)
    return urls


@click.command("download", short_help="Download a file or folder from a MEGA link.")
@click.argument("urls", nargs=-1, required=False)
@click.option(
    "-o",
    "--output",
    "output_dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Destination directory (defaults to config download_path).",
)
@click.option(
    "-w",
    "--workers",
    type=int,
    default=None,
    help="Number of parallel chunk workers per file.",
)
@click.option(
    "-l",
    "--limit",
    "speed_limit_kbps",
    type=float,
    default=None,
    help="Aggregate download speed limit for this command in KB/s (0 = unlimited).",
)
@click.option(
    "-p",
    "--password",
    default=None,
    help="Password for password-protected links.",
)
@click.option(
    "--no-verify",
    is_flag=True,
    help="Skip file integrity check (faster but unsafe).",
)
@click.option(
    "--overwrite",
    "--force",
    "overwrite",
    is_flag=True,
    help="Overwrite an existing destination file. By default an unrelated "
    "existing file is preserved and a unique name is used instead.",
)
@click.option(
    "--rename",
    default=None,
    help="Override the filename (only for single-file links).",
)
@click.option(
    "--proxy",
    default=None,
    help="HTTP/SOCKS proxy URL (e.g. http://127.0.0.1:8080).",
)
@click.option(
    "-i",
    "--input-file",
    "input_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Read links from a text file, or decrypt a .dlc container.",
)
@click.option("--elc-user", default=None, help="ELC account user for mega://elc links.")
@click.option("--elc-api-key", default=None, help="ELC API key for mega://elc links.")
@click.option(
    "-P",
    "--parallel",
    "parallel_transfers",
    type=int,
    default=None,
    help="Number of files to download simultaneously (global limit).",
)
@click.option(
    "-I",
    "--include",
    "include_patterns",
    multiple=True,
    help="Folder links: only download files matching this glob (repeatable; "
    "matches the folder-relative path or filename, case-insensitive).",
)
@click.option(
    "-X",
    "--exclude",
    "exclude_patterns",
    multiple=True,
    help="Folder links: skip files matching this glob (repeatable; wins over --include).",
)
@click.option(
    "--select",
    "select_files",
    is_flag=True,
    help="Folder links: list the files and interactively choose which to download "
    "(e.g. 1,3-5 | all | none).",
)
@click.option(
    "--json",
    "json_output",
    is_flag=True,
    help="Machine mode: emit one JSON result record per line on stdout; "
    "human output and progress go to stderr.",
)
@click.pass_context
def download(
    ctx: click.Context,
    urls: tuple[str, ...],
    output_dir: Path | None,
    workers: int | None,
    speed_limit_kbps: float | None,
    password: str | None,
    no_verify: bool,
    overwrite: bool,
    rename: str | None,
    proxy: str | None,
    input_file: Path | None,
    elc_user: str | None,
    elc_api_key: str | None,
    parallel_transfers: int | None,
    include_patterns: tuple[str, ...],
    exclude_patterns: tuple[str, ...],
    select_files: bool,
    json_output: bool,
) -> None:
    """Download one or more MEGA links.

    Exit status is non-zero when any link fails; an interactive selection
    answered with "none" is a user skip, not a failure.
    """
    cfg = ctx.obj["config"]
    quiet = bool(ctx.obj.get("quiet"))
    # Machine mode: JSONL records own stdout; humans read stderr; the live
    # progress view is disabled. The emitter grabs the real stdout BEFORE the
    # redirect below.
    machine = MachineOutput(json_output)
    if json_output:
        quiet = True
        redirect = contextlib.redirect_stdout(sys.stderr)
        redirect.__enter__()
        ctx.call_on_close(lambda: redirect.__exit__(None, None, None))
    proxies = {"http": proxy, "https": proxy} if proxy else None
    failures = 0

    # Collect URLs from args and/or file
    url_list: list[str] = list(urls)
    if input_file:
        if input_file.suffix.lower() == ".dlc":
            try:
                url_list.extend(
                    decrypt_dlc_container(
                        input_file.read_bytes(),
                        timeout=cfg.timeout_seconds,
                        proxies=proxies,
                    )
                )
            except Exception as exc:  # noqa: BLE001
                print_error(f"DLC decrypt failed: {exc}")
                ctx.exit(1)
        else:
            url_list.extend(_read_links_file(input_file))
    if not url_list:
        print_error("No URLs given. Pass URLs as arguments or use -i <file>.")
        ctx.exit(2)

    output_dir = output_dir or Path(cfg.download_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    # Folder-link file selection (parity with MegaBasterd's FolderLinkDialog):
    # glob filters first, then the interactive picker on whatever remains.
    folder_file_filter = compose_file_filters(
        build_folder_file_filter(include_patterns, exclude_patterns, output_dir),
        _interactive_file_picker(output_dir) if select_files else None,
    )
    workers = workers if workers is not None else cfg.max_workers
    speed_limit_kbps = speed_limit_kbps if speed_limit_kbps is not None else cfg.speed_limit_kbps
    verify = not no_verify and cfg.verify_integrity
    parallel = parallel_transfers if parallel_transfers is not None else cfg.max_parallel_downloads
    parallel = max(1, parallel)

    # Smart proxy: if enabled and no explicit --proxy was given, load the
    # persistent pool + any URLs from `smart_proxy_url` config so chunk
    # requests are routed through rotating proxies.
    from ..proxy.runtime import effective_pool_for_cmd

    proxy_pool = effective_pool_for_cmd(cfg, proxy)

    def _new_api() -> MegaAPIClient:
        """One isolated API client (own Session + sequence) per transfer.

        `MegaAPIClient` owns a mutable `requests.Session`, sequence counter,
        and SID; independent parallel transfers must never share one. The
        proxy pool below IS shared — it is explicitly thread-safe.
        """
        return MegaAPIClient(
            timeout=cfg.timeout_seconds,
            proxies=proxies,
            proxy_pool=proxy_pool,
            force_proxy=cfg.force_smart_proxy,
            user_agent=cfg.user_agent,
        )

    # ONE limiter per command: `speed_limit_kbps` (or --limit) is an aggregate
    # cap shared by every parallel transfer, not a per-file value.
    shared_limiter = make_limiter(speed_limit_kbps)

    # Each parallel slot gets its own MegaDownloader because the downloader
    # holds per-transfer state (CDN URL, generation counter) — and its own
    # API client (see `_new_api`). The helpers below close that API client
    # on every path.
    def _new_downloader() -> MegaDownloader:
        return MegaDownloader(
            api=_new_api(),
            max_workers=workers,
            speed_limit_kbps=speed_limit_kbps,
            verify_integrity=verify,
            timeout=cfg.timeout_seconds,
            proxies=proxies,
            proxy_pool=proxy_pool,
            force_proxy=cfg.force_smart_proxy,
            quota_wait_seconds=cfg.quota_wait_seconds,
            quota_max_wait_loops=cfg.quota_max_wait_loops,
            keep_state_files_on_error=cfg.keep_state_files_on_error,
            overwrite=overwrite,
            limiter=shared_limiter,
            auto_resume=cfg.auto_resume,
            user_agent=cfg.user_agent,
        )

    # First pass: parse + filter URLs, collect actionable jobs
    file_jobs: list[tuple[str, str | None]] = []  # (url, rename_to)
    folder_file_jobs: list[str] = []
    folder_jobs: list[str] = []
    expanded_urls: list[str] = []
    for url in url_list:
        try:
            parsed = parse_link(url)
        except ValueError as e:
            print_error(str(e))
            failures += 1
            continue
        if parsed.type == LinkType.ELC_CONTAINER:
            try:
                expanded_urls.extend(
                    resolve_elc_links(
                        parsed,
                        accounts=cfg.elc_accounts,
                        user=elc_user,
                        api_key=elc_api_key,
                        timeout=cfg.timeout_seconds,
                        proxies=proxies,
                    )
                )
            except Exception as exc:  # noqa: BLE001
                print_error(f"ELC resolution failed: {exc}")
                failures += 1
            continue
        expanded_urls.append(url)

    for url in expanded_urls:
        try:
            parsed = parse_link(url)
        except ValueError as e:
            print_error(str(e))
            failures += 1
            continue

        # Unwrap container formats before classifying as file vs folder.
        if parsed.type == LinkType.PASSWORD_PROTECTED:
            if not password:
                print_error(f"Link is password-protected; supply -p PASSWORD: {url}")
                failures += 1
                continue
            try:
                parsed = resolve_password_link(parsed, password)
            except ValueError as exc:
                print_error(f"Wrong password: {exc}")
                failures += 1
                continue
        elif parsed.type == LinkType.ENCRYPTED_CONTAINER:
            try:
                parsed = resolve_encrypted_container_link(parsed)
            except ValueError as exc:
                print_error(f"Encrypted container decode failed: {exc}")
                failures += 1
                continue
        elif parsed.type == LinkType.MEGACRYPTER:
            try:
                parsed = resolve_megacrypter_link(
                    parsed,
                    timeout=cfg.timeout_seconds,
                    password=password,
                )
            except ValueError as exc:
                log.info("MegaCrypter link will be downloaded via server API: %s", exc)
                file_jobs.append((url, rename if len(expanded_urls) == 1 else None))
                continue

        # `url` here may still be the original container/password URL — after
        # the resolve step above we MUST construct the downstream URL from
        # the parsed (resolved) form, not from `url`, or the downloader will
        # try to re-parse the wrapper and fail.
        if parsed.type in (LinkType.FOLDER, LinkType.FOLDER_IN_FOLDER):
            resolved_url = (
                f"https://mega.nz/folder/{parsed.public_id}#{parsed.key}"
                if parsed.public_id and parsed.key
                else url
            )
            if parsed.type == LinkType.FOLDER_IN_FOLDER and parsed.subpath:
                resolved_url = (
                    f"https://mega.nz/folder/{parsed.public_id}#{parsed.key}"
                    f"/folder/{parsed.subpath}"
                )
            folder_jobs.append(resolved_url)
        elif parsed.type == LinkType.FILE_IN_FOLDER:
            if not parsed.subpath:
                print_error("File-in-folder link is missing the file handle.")
                failures += 1
                continue
            resolved_url = (
                f"https://mega.nz/folder/{parsed.public_id}#{parsed.key}" f"/file/{parsed.subpath}"
            )
            folder_file_jobs.append(resolved_url)
        elif parsed.type == LinkType.FILE:
            resolved_url = f"https://mega.nz/file/{parsed.public_id}#{parsed.key}"
            file_jobs.append((resolved_url, rename if len(expanded_urls) == 1 else None))
        else:
            print_error(f"Unsupported link type: {parsed.type}")
            failures += 1

    # One shared progress system for every download mode: single files,
    # parallel files, and file-in-folder links share this controller; each
    # full folder link gets its own controller (its manifest defines it).
    if file_jobs or folder_file_jobs:
        progress = TransferProgress(
            title="MEGA Download",
            direction="download",
            details=[
                f"Source: {len(file_jobs) + len(folder_file_jobs)} link(s)",
                f"Output: {output_dir}",
                "",
                "Backend: MegaBasterd-CLI",
            ],
            quiet=quiet,
        )
        with progress:
            # Process file jobs in parallel slots
            if file_jobs:
                if parallel == 1 or len(file_jobs) == 1:
                    for url, rename_to in file_jobs:
                        failures += (
                            0
                            if _download_file(
                                _new_downloader(),
                                url,
                                output_dir,
                                progress,
                                password=password,
                                rename_to=rename_to,
                                machine=machine,
                            )
                            else 1
                        )
                else:
                    from concurrent.futures import ThreadPoolExecutor, as_completed

                    def _run(job):
                        url, rename_to = job
                        return _download_file(
                            _new_downloader(),
                            url,
                            output_dir,
                            progress,
                            password=password,
                            rename_to=rename_to,
                            machine=machine,
                        )

                    with ThreadPoolExecutor(max_workers=parallel) as pool:
                        futs = [pool.submit(_run, job) for job in file_jobs]
                        for f in as_completed(futs):
                            try:
                                if not f.result():
                                    failures += 1
                            except Exception as e:  # noqa: BLE001
                                log.error("Parallel download failed: %s", e)
                                failures += 1

            if folder_file_jobs:
                # Interactive selection must prompt from the main thread, so
                # --select forces these jobs to run sequentially.
                if parallel == 1 or select_files or len(folder_file_jobs) == 1:
                    for url in folder_file_jobs:
                        outcome = _download_folder_file(
                            _new_downloader(),
                            url,
                            output_dir,
                            progress,
                            file_filter=folder_file_filter,
                            machine=machine,
                        )
                        failures += 0 if outcome else 1
                else:
                    from concurrent.futures import ThreadPoolExecutor, as_completed

                    def _run_folder_file(url):
                        return _download_folder_file(
                            _new_downloader(),
                            url,
                            output_dir,
                            progress,
                            file_filter=folder_file_filter,
                            machine=machine,
                        )

                    with ThreadPoolExecutor(max_workers=parallel) as pool:
                        futs = [pool.submit(_run_folder_file, url) for url in folder_file_jobs]
                        for f in as_completed(futs):
                            try:
                                if not f.result():
                                    failures += 1
                            except Exception as e:  # noqa: BLE001
                                log.error("Parallel folder-file download failed: %s", e)
                                failures += 1

    # Folder jobs get one controller each (their manifests define the rows).
    for url in folder_jobs:
        if not _download_folder(
            _new_downloader(),
            url,
            output_dir,
            parallel_files=parallel,
            file_filter=folder_file_filter,
            quiet=quiet,
            machine=machine,
        ):
            failures += 1

    if failures:
        print_error(f"{failures} download item(s) failed.")
        ctx.exit(1)


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


def _run_hook_for(path: Path) -> None:
    ctx = click.get_current_context(silent=True)
    cfg = ctx.obj.get("config") if ctx and ctx.obj else None
    if cfg is not None:
        run_post_transfer_command(cfg.run_command, path)


def _download_file(
    downloader,
    url,
    output_dir,
    progress: TransferProgress,
    password=None,
    rename_to=None,
    machine: MachineOutput | None = None,
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
        _run_hook_for(result.path)
        return True
    except MegaError as e:
        progress.finish_item(item, "failed")
        print_error(f"Download failed: {e}")
        machine.emit(
            event="result",
            type="download",
            status="failed",
            source=redact_link(url),
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
            path=str(path),
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
            _run_hook_for(result.path)
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
            path=str(path),
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
            _run_hook_for(item.path)
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
            error=str(e),
        )
        return False
    finally:
        if downloader.api is not None:
            downloader.api.close()
