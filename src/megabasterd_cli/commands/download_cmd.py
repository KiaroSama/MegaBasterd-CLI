"""`mb download` - download files/folders from MEGA public links."""

from __future__ import annotations

import logging
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
from ..ui.progress import MultiFileProgressView, ProgressFileState, build_progress
from ..ui.prompts import print_error, print_success
from ..utils.helpers import format_bytes

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
    help="Per-transfer speed limit in KB/s (0 = unlimited).",
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
) -> None:
    """Download one or more MEGA links."""
    cfg = ctx.obj["config"]
    proxies = {"http": proxy, "https": proxy} if proxy else None

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
                return
        else:
            url_list.extend(_read_links_file(input_file))
    if not url_list:
        print_error("No URLs given. Pass URLs as arguments or use -i <file>.")
        return

    output_dir = output_dir or Path(cfg.download_path)
    output_dir.mkdir(parents=True, exist_ok=True)
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

    api = MegaAPIClient(
        timeout=cfg.timeout_seconds,
        proxies=proxies,
        proxy_pool=proxy_pool,
        force_proxy=cfg.force_smart_proxy,
    )

    # Each parallel slot gets its own MegaDownloader because the downloader
    # holds per-transfer state (CDN URL, generation counter).
    def _new_downloader() -> MegaDownloader:
        return MegaDownloader(
            api=api,
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
            continue
        expanded_urls.append(url)

    for url in expanded_urls:
        try:
            parsed = parse_link(url)
        except ValueError as e:
            print_error(str(e))
            continue

        # Unwrap container formats before classifying as file vs folder.
        if parsed.type == LinkType.PASSWORD_PROTECTED:
            if not password:
                print_error(f"Link is password-protected; supply -p PASSWORD: {url}")
                continue
            try:
                parsed = resolve_password_link(parsed, password)
            except ValueError as exc:
                print_error(f"Wrong password: {exc}")
                continue
        elif parsed.type == LinkType.ENCRYPTED_CONTAINER:
            try:
                parsed = resolve_encrypted_container_link(parsed)
            except ValueError as exc:
                print_error(f"Encrypted container decode failed: {exc}")
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

    overall_progress = build_progress()
    with overall_progress:
        # Process file jobs in parallel slots
        if file_jobs:
            if parallel == 1:
                for url, rename_to in file_jobs:
                    _download_file(
                        _new_downloader(),
                        url,
                        output_dir,
                        overall_progress,
                        password=password,
                        rename_to=rename_to,
                    )
            else:
                from concurrent.futures import ThreadPoolExecutor, as_completed

                def _run(job):
                    url, rename_to = job
                    return _download_file(
                        _new_downloader(),
                        url,
                        output_dir,
                        overall_progress,
                        password=password,
                        rename_to=rename_to,
                    )

                with ThreadPoolExecutor(max_workers=parallel) as pool:
                    futs = [pool.submit(_run, job) for job in file_jobs]
                    for f in as_completed(futs):
                        try:
                            f.result()
                        except Exception as e:  # noqa: BLE001
                            log.error("Parallel download failed: %s", e)

        if folder_file_jobs:
            if parallel == 1:
                for url in folder_file_jobs:
                    _download_folder_file(
                        _new_downloader(),
                        url,
                        output_dir,
                        overall_progress,
                    )
            else:
                from concurrent.futures import ThreadPoolExecutor, as_completed

                def _run_folder_file(url):
                    return _download_folder_file(
                        _new_downloader(),
                        url,
                        output_dir,
                        overall_progress,
                    )

                with ThreadPoolExecutor(max_workers=parallel) as pool:
                    futs = [pool.submit(_run_folder_file, url) for url in folder_file_jobs]
                    for f in as_completed(futs):
                        try:
                            f.result()
                        except Exception as e:  # noqa: BLE001
                            log.error("Parallel folder-file download failed: %s", e)

    # Folder jobs use their own EVdlc-style multi-file live view.
    for url in folder_jobs:
        _download_folder(
            _new_downloader(),
            url,
            output_dir,
            parallel_files=parallel,
        )


def _download_file(downloader, url, output_dir, overall_progress, password=None, rename_to=None):
    task_id = overall_progress.add_task(description="Resolving...", total=1)

    def on_progress(p):
        overall_progress.update(task_id, completed=p.bytes_done, total=p.total_bytes)

    try:
        result = downloader.download_link(
            url,
            output_dir,
            password=password,
            rename_to=rename_to,
            on_progress=on_progress,
        )
        overall_progress.update(
            task_id,
            description=f"Done: {result.path.name}",
            completed=result.size,
            total=result.size,
        )
        print_success(
            f"{result.path.name} ({format_bytes(result.size)}) " f"in {result.elapsed_seconds:.1f}s"
        )
        from ..utils.hooks import run_post_transfer_command

        cfg = click.get_current_context().obj.get("config") if click.get_current_context() else None
        if cfg is not None:
            run_post_transfer_command(cfg.run_command, result.path)
    except MegaError as e:
        overall_progress.update(task_id, description=f"Failed: {e}")
        print_error(f"Download failed: {e}")
    except Exception as e:
        log.exception("Unexpected error during download")
        print_error(f"Unexpected error: {e}")


def _download_folder(downloader, url, output_dir, parallel_files: int = 1):
    folder_dl = MegaFolderDownloader(downloader)
    import threading

    lock = threading.RLock()
    states: dict[str, ProgressFileState] = {}
    view: MultiFileProgressView | None = None

    def _relative_name(path: Path) -> str:
        try:
            return str(path.relative_to(output_dir))
        except ValueError:
            return path.name

    def _refresh(force: bool = False, status: str = "Downloading") -> None:
        if view is None:
            return
        file_states = list(states.values())
        total = sum((state.total or 0) for state in file_states) if file_states else None
        completed = sum(max(0, state.completed) for state in file_states)
        completed_items = sum(
            1
            for state in file_states
            if state.status in {"complete", "downloaded", "resumed"}
            or bool(state.total and state.completed >= state.total)
        )
        failed_items = sum(1 for state in file_states if state.status in {"failed", "error"})
        view.update(
            file_states,
            overall_completed=completed,
            overall_total=total,
            completed_items=completed_items,
            total_items=len(file_states),
            failed_items=failed_items,
            status=status,
            force=force,
        )

    def on_manifest(file_jobs):
        nonlocal view
        with lock:
            states.clear()
            for node, destination in file_jobs:
                key = str(destination)
                states[key] = ProgressFileState(
                    key=key,
                    name=_relative_name(destination),
                    completed=0,
                    total=int(node.size or 0),
                    speed=0.0,
                    status="queued",
                )
            view = MultiFileProgressView(
                title="MEGA Folder Download",
                details=[
                    f"Source: {url}",
                    f"Output: {output_dir}",
                    "",
                    "Backend: MegaBasterd-CLI",
                ],
                item_label="files",
            )
            _refresh(force=True, status="Starting")

    def on_file_progress(path: Path, p):
        with lock:
            key = str(path)
            state = states.get(key)
            if state is None:
                state = ProgressFileState(key=key, name=_relative_name(path))
                states[key] = state
            state.completed = p.bytes_done
            state.total = p.total_bytes
            state.speed = p.speed_bps
            state.status = "active"
            _refresh(status="Downloading")

    def on_file_done(result):
        with lock:
            key = str(result.path)
            state = states.get(key)
            if state is None:
                state = ProgressFileState(key=key, name=_relative_name(result.path))
                states[key] = state
            state.completed = result.size
            state.total = result.size
            state.speed = 0.0
            state.status = "complete"
            _refresh(force=True, status="Downloading")

    try:
        results = folder_dl.download_folder(
            url,
            output_dir,
            on_file_done=on_file_done,
            on_folder_manifest=on_manifest,
            on_file_progress=on_file_progress,
            parallel_files=parallel_files,
        )
        total_bytes = sum(r.size for r in results)
        if view is not None:
            _refresh(force=True, status="Complete")
            view.close(success=True)
        print_success(f"Folder complete: {len(results)} files, {format_bytes(total_bytes)} total")
    except MegaError as e:
        if view is not None:
            _refresh(force=True, status="Failed")
            view.close(success=False)
        print_error(f"Folder download failed: {e}")
    except Exception as e:
        log.exception("Unexpected error during folder download")
        if view is not None:
            _refresh(force=True, status="Failed")
            view.close(success=False)
        print_error(f"Unexpected error: {e}")


def _download_folder_file(downloader, url, output_dir, overall_progress):
    task_id = overall_progress.add_task(description="Resolving folder file...", total=1)
    folder_dl = MegaFolderDownloader(downloader)

    def on_progress(p):
        overall_progress.update(task_id, completed=p.bytes_done, total=p.total_bytes)

    try:
        results = folder_dl.download_node_in_folder(
            url,
            output_dir,
            on_progress=on_progress,
        )
        result = results[0] if results else None
        if result is None:
            overall_progress.update(task_id, description="Done: empty folder", completed=1, total=1)
            print_success("Folder complete: 0 files, 0 B total")
            return
        overall_progress.update(
            task_id,
            description=f"Done: {result.path.name}" if len(results) == 1 else "Folder complete",
            completed=result.size,
            total=result.size,
        )
        if len(results) == 1:
            print_success(
                f"{result.path} ({format_bytes(result.size)}) " f"in {result.elapsed_seconds:.1f}s"
            )
        else:
            total_bytes = sum(item.size for item in results)
            print_success(
                f"Folder complete: {len(results)} files, {format_bytes(total_bytes)} total"
            )
        from ..utils.hooks import run_post_transfer_command

        cfg = click.get_current_context().obj.get("config") if click.get_current_context() else None
        if cfg is not None:
            for item in results:
                run_post_transfer_command(cfg.run_command, item.path)
    except MegaError as e:
        overall_progress.update(task_id, description=f"Failed: {e}")
        print_error(f"Download failed: {e}")
    except Exception as e:
        log.exception("Unexpected error during folder-file download")
        print_error(f"Unexpected error: {e}")
