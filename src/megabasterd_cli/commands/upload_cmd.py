"""`mb upload` - upload local files to a MEGA account."""

from __future__ import annotations

import logging
import threading
from pathlib import Path

import click

from ..accounts.manager import AccountManager, AccountNotFound, resolve_account_id
from ..config import accounts_file
from ..core.api import MegaAPIClient
from ..core.client import MegaClient
from ..core.errors import MegaError, QuotaError
from ..core.uploader import MegaUploader, UploadResult
from ..ui.prompts import ask, ask_password, print_error, print_info, print_success, print_warn
from ..ui.transfer_progress import TransferProgress
from ..utils.helpers import format_bytes
from ..utils.hooks import append_upload_log, run_post_transfer_command
from ..utils.speed import make_limiter

log = logging.getLogger(__name__)


def _mfa_prompt() -> str:
    return ask("Enter 6-digit 2FA code").strip()


def finalize_upload_success(
    cfg,
    client: MegaClient,
    result: UploadResult,
    local_path: Path,
    *,
    share: bool = False,
    share_password: str | None = None,
    notes: list[tuple[str, str]] | None = None,
) -> str | None:
    """Centralized post-upload success pipeline used by EVERY upload mode
    (sequential, parallel, flat/structured directory, queue, auto-account).

    Handles success output, the optional public/password-protected share
    link, the JSONL upload log, the post-transfer command, and account
    attribution. A share/hook failure is reported separately and never
    converts a successful transfer into a failure. Returns the share link.

    When `notes` is given, user-facing messages are buffered there (so a live
    progress view is not torn up) and the caller prints them after closing.
    """

    def say(kind: str, message: str) -> None:
        if notes is not None:
            notes.append((kind, message))
        else:
            {"success": print_success, "info": print_info, "error": print_error}[kind](message)

    say(
        "success",
        f"{result.name} ({format_bytes(result.size)}) in {result.elapsed_seconds:.1f}s",
    )
    link: str | None = None
    if share:
        try:
            link = client.export_link(result.file_handle, password=share_password)
            say("info", f"Share link: {link}")
        except MegaError as exc:
            # Reported separately: the upload itself succeeded.
            say("error", f"Could not generate share link for {result.name}: {exc}")
    append_upload_log(
        cfg.upload_log_path,
        local_path=local_path,
        file_handle=result.file_handle,
        size=result.size,
        elapsed_seconds=result.elapsed_seconds,
        public_link=link,
        account=client.session.email if client.session else None,
    )
    run_post_transfer_command(cfg.run_command, local_path)
    return link


def plan_auto_accounts(
    jobs: list[tuple[Path, int]], ledger: dict[str, int]
) -> tuple[dict[Path, str], list[Path]]:
    """Assign each file to the stored account with the most known free space.

    The in-memory `ledger` (email -> free bytes) is decremented as files are
    assigned, so later files spill over to other accounts and no account is
    ever picked without enough known free space. Files no account can hold
    are returned separately.
    """
    assignment: dict[Path, str] = {}
    unassigned: list[Path] = []
    for path, size in jobs:
        candidates = [(free, email) for email, free in ledger.items() if free >= size]
        if not candidates:
            unassigned.append(path)
            continue
        free, email = max(candidates)
        assignment[path] = email
        ledger[email] = free - size
    return assignment, unassigned


def _tree_size(path: Path) -> int:
    return sum(f.stat().st_size for f in path.rglob("*") if f.is_file())


@click.command("upload", short_help="Upload local files to MEGA.")
@click.argument(
    "paths",
    nargs=-1,
    required=True,
    type=click.Path(exists=True, dir_okay=True, file_okay=True, path_type=Path),
)
@click.option(
    "-a",
    "--account",
    default=None,
    help="Account email or label (default: vault default, then config default_account).",
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
    help="Aggregate upload speed limit for this command in KB/s (0 = unlimited).",
)
@click.option(
    "--rename",
    default=None,
    help="Override the remote name (single file only).",
)
@click.option(
    "--target",
    default=None,
    help="Destination folder handle or path (default: account root).",
)
@click.option(
    "--keep-structure",
    is_flag=True,
    help="When uploading a directory, preserve its tree structure on MEGA.",
)
@click.option(
    "--keep-going",
    is_flag=True,
    help="Continue directory uploads after item failures and keep successful uploads.",
)
@click.option(
    "--auto-account",
    is_flag=True,
    help="Pick the stored account with the most free space for each file "
    "(whole tree with --keep-structure).",
)
@click.option(
    "--vault-passphrase",
    default=None,
    help="Passphrase used to decrypt stored credentials.",
)
@click.option("--mfa-code", default=None, help="2FA code if your account requires it.")
@click.option(
    "-P",
    "--parallel",
    "parallel_transfers",
    type=int,
    default=None,
    help="Number of files to upload simultaneously.",
)
@click.option(
    "--share",
    "auto_share",
    is_flag=True,
    help="After each upload, print a public link for the uploaded file "
    "(directories: one link per uploaded file).",
)
@click.option(
    "--share-password",
    default=None,
    help="If set with --share, generate password-protected links.",
)
@click.pass_context
def upload(
    ctx: click.Context,
    paths: tuple[Path, ...],
    account: str | None,
    workers: int | None,
    speed_limit_kbps: float | None,
    rename: str | None,
    target: str | None,
    keep_structure: bool,
    keep_going: bool,
    auto_account: bool,
    vault_passphrase: str | None,
    mfa_code: str | None,
    parallel_transfers: int | None,
    auto_share: bool,
    share_password: str | None,
) -> None:
    """Upload files (or all files inside a directory) to MEGA.

    Exit status is non-zero when any item fails (`--keep-going` continues
    processing but does not turn failures into overall success).
    """
    cfg = ctx.obj["config"]
    quiet = bool(ctx.obj.get("quiet"))

    mgr = AccountManager(accounts_file())
    if not mgr.list_accounts():
        print_error("No accounts found. Use `mb account add` first.")
        ctx.exit(1)
    passphrase = vault_passphrase or ask_password("Vault passphrase")
    mgr.unlock(passphrase)

    # Build the flat job list early so auto-account can size-match per file.
    # Each job is (path, size); --keep-structure directories are one job
    # covering the whole tree (a preserved tree must live in ONE account).
    jobs: list[tuple[Path, int]] = []
    for p in paths:
        if p.is_dir() and not keep_structure:
            jobs.extend((f, f.stat().st_size) for f in sorted(p.rglob("*")) if f.is_file())
        elif p.is_dir() and keep_structure:
            jobs.append((p, _tree_size(p)))
        else:
            jobs.append((p, p.stat().st_size))

    workers = workers if workers is not None else cfg.upload_workers
    speed_limit_kbps = (
        speed_limit_kbps if speed_limit_kbps is not None else cfg.upload_speed_limit_kbps
    )
    parallel = parallel_transfers if parallel_transfers is not None else cfg.max_parallel_uploads
    parallel = max(1, parallel)

    from ..proxy.runtime import effective_pool

    proxy_pool = effective_pool(cfg)
    # ONE limiter per command: `upload_speed_limit_kbps` (or --limit) is an
    # aggregate cap shared by every parallel worker, not a per-file value.
    shared_limiter = make_limiter(speed_limit_kbps)

    def _new_api() -> MegaAPIClient:
        return MegaAPIClient(
            timeout=cfg.timeout_seconds,
            proxy_pool=proxy_pool,
            force_proxy=cfg.force_smart_proxy,
            user_agent=cfg.user_agent,
        )

    def _login_client(email: str, password: str) -> MegaClient | None:
        client = MegaClient(api=_new_api())
        try:
            client.login(email, password, mfa_code=mfa_code, mfa_prompt=_mfa_prompt)
            return client
        except MegaError as exc:
            print_error(f"Login failed for {email}: {exc}")
            return None

    def _worker_client(base: MegaClient) -> MegaClient:
        """Isolated API client/session per parallel file, reusing the
        already-authenticated session material (no MFA re-prompt)."""
        api = _new_api()
        worker = MegaClient(api=api)
        worker.session = base.session
        api.set_session(base.session.sid if base.session else None)
        return worker

    def _make_uploader(client: MegaClient) -> MegaUploader:
        return MegaUploader(
            client=client,
            max_workers=workers,
            speed_limit_kbps=speed_limit_kbps,
            timeout=cfg.timeout_seconds,
            proxy_pool=proxy_pool,
            force_proxy=cfg.force_smart_proxy,
            limiter=shared_limiter,
            auto_resume=cfg.auto_resume,
            user_agent=cfg.user_agent,
        )

    def _resolve_target_handle(client: MegaClient) -> str | None:
        if not target:
            return None
        node = client.find_node(handle=target) or client.find_node(path=target)
        if not node or not node.is_folder:
            raise MegaError(message=f"Target folder not found: {target}")
        return node.handle

    # ------------------------------------------------------------------
    # Account planning (login happens BEFORE the live view so MFA/vault
    # prompts never fight the renderer).
    # ------------------------------------------------------------------
    clients: dict[str, MegaClient] = {}  # email -> logged-in client
    failures = 0
    fail_lock = threading.Lock()
    notes: list[tuple[str, str]] = []

    def _client_for_email(email_or_label: str) -> MegaClient | None:
        try:
            acc = mgr.get_account(email_or_label)
            password = mgr.get_password(email_or_label)
        except AccountNotFound:
            print_error(f"Account not found: {email_or_label}")
            return None
        if acc.email in clients:
            return clients[acc.email]
        client = _login_client(acc.email, password)
        if client is not None:
            clients[acc.email] = client
        return client

    assignment: dict[Path, str] = {}
    ledger: dict[str, int] = {}
    if auto_account and not account:
        for acc in mgr.list_accounts():
            if acc.quota_total is not None and acc.quota_used is not None:
                ledger[acc.email] = acc.quota_total - acc.quota_used
        if not ledger:
            print_error("--auto-account needs cached quotas; run `mb account refresh-all` first.")
            ctx.exit(1)
        assignment, unassigned = plan_auto_accounts(jobs, ledger)
        for path in unassigned:
            print_error(f"No stored account has enough free space for {path.name}; skipping.")
            failures += 1
        jobs = [(p, s) for p, s in jobs if p in assignment]
        for path, email in assignment.items():
            print_info(f"Using {email} for {path.name}")
        for email in sorted(set(assignment.values())):
            if _client_for_email(email) is None:
                # Login failed: fail that account's files.
                failed_paths = [p for p, e in assignment.items() if e == email]
                failures += len(failed_paths)
                jobs = [(p, s) for p, s in jobs if p not in failed_paths]
    else:
        account_id = resolve_account_id(mgr, cfg.default_account, account)
        if not account_id:
            print_error("No account specified and no default set.")
            ctx.exit(1)
        if _client_for_email(account_id) is None:
            ctx.exit(1)
        only_email = next(iter(clients.keys()))
        assignment = {p: only_email for p, _ in jobs}

    def _client_for_path(path: Path) -> MegaClient:
        return clients[assignment[path]]

    def _on_upload_failure(path: Path, email: str, size: int, exc: Exception) -> None:
        nonlocal failures
        with fail_lock:
            failures += 1
        if isinstance(exc, QuotaError) and email in ledger:
            # Refresh the cached quota so later planning stops trusting it.
            try:
                quota = clients[email].get_quota()
                ledger[email] = quota.get("mstrg", 0) - quota.get("cstrg", 0)
                mgr.update_quota(email, quota.get("cstrg", 0), quota.get("mstrg", 0))
            except MegaError:
                ledger[email] = 0

    def _progress_cb(key: str):
        def _cb(p) -> None:
            progress.update_item(key, p.bytes_done, p.total_bytes)

        return _cb

    single_file = len(jobs) == 1 and jobs[0][0].is_file()
    progress = TransferProgress(
        title="MEGA Upload",
        direction="upload",
        details=[
            f"Source: {len(jobs)} item(s)",
            f"Target: {target or '/'}",
            "",
            "Backend: MegaBasterd-CLI",
        ],
        quiet=quiet,
    )

    can_parallel = parallel > 1 and not keep_structure and not auto_account and len(jobs) > 1

    try:
        with progress:
            if can_parallel:
                base_client = next(iter(clients.values()))
                try:
                    shared_target = _resolve_target_handle(base_client)
                except MegaError as exc:
                    print_error(str(exc))
                    ctx.exit(1)

                from concurrent.futures import ThreadPoolExecutor

                def _upload_one(job: tuple[Path, int]) -> None:
                    file_path, size = job
                    if not file_path.is_file():
                        return
                    worker = _worker_client(base_client)
                    item = progress.add_item(file_path.name, size)
                    try:
                        uploader = _make_uploader(worker)
                        result = uploader.upload_file(
                            file_path,
                            target_handle=shared_target,
                            rename_to=None,
                            on_progress=_progress_cb(item),
                        )
                        finalize_upload_success(
                            cfg,
                            worker,
                            result,
                            file_path,
                            share=auto_share,
                            share_password=share_password,
                            notes=notes,
                        )
                        progress.finish_item(item, "complete")
                    except MegaError as exc:
                        progress.finish_item(item, "failed")
                        _on_upload_failure(file_path, assignment[file_path], size, exc)
                        notes.append(("error", f"Upload failed: {file_path.name}: {exc}"))
                    except Exception as exc:  # noqa: BLE001
                        log.exception("Unexpected error during upload")
                        progress.finish_item(item, "failed")
                        _on_upload_failure(file_path, assignment[file_path], size, exc)
                        notes.append(("error", f"Unexpected error: {file_path.name}: {exc}"))
                    finally:
                        # Close the worker's HTTP session WITHOUT logging out
                        # the shared server-side session.
                        worker.close()

                with ThreadPoolExecutor(max_workers=parallel) as pool:
                    list(pool.map(_upload_one, jobs))
            else:
                for file_path, size in jobs:
                    client = _client_for_path(file_path)
                    try:
                        target_handle = _resolve_target_handle(client)
                    except MegaError as exc:
                        notes.append(("error", str(exc)))
                        with fail_lock:
                            failures += 1
                        continue
                    uploader = _make_uploader(client)

                    if file_path.is_dir() and keep_structure:
                        _upload_structured_directory(
                            uploader,
                            file_path,
                            target_handle,
                            progress,
                            cfg,
                            client,
                            keep_going=keep_going,
                            share=auto_share,
                            share_password=share_password,
                            notes=notes,
                            on_failure=lambda exc, fp=file_path, sz=size: _on_upload_failure(
                                fp, assignment[fp], sz, exc
                            ),
                        )
                        continue

                    item = progress.add_item(file_path.name, size)
                    try:
                        result = uploader.upload_file(
                            file_path,
                            target_handle=target_handle,
                            rename_to=rename if single_file else None,
                            on_progress=_progress_cb(item),
                        )
                        finalize_upload_success(
                            cfg,
                            client,
                            result,
                            file_path,
                            share=auto_share,
                            share_password=share_password,
                            notes=notes,
                        )
                        progress.finish_item(item, "complete")
                    except MegaError as exc:
                        progress.finish_item(item, "failed")
                        _on_upload_failure(file_path, assignment[file_path], size, exc)
                        notes.append(("error", f"Upload failed: {file_path.name}: {exc}"))
                    except Exception as exc:  # noqa: BLE001
                        log.exception("Unexpected error during upload")
                        progress.finish_item(item, "failed")
                        _on_upload_failure(file_path, assignment[file_path], size, exc)
                        notes.append(("error", f"Unexpected error: {file_path.name}: {exc}"))
    finally:
        for client in clients.values():
            try:
                client.logout()
            except Exception:  # noqa: BLE001
                log.debug("Logout failed", exc_info=True)

    printer = {"success": print_success, "info": print_info, "error": print_error}
    for kind, message in notes:
        printer[kind](message)
    if failures:
        print_warn(f"{failures} upload item(s) failed.")
        ctx.exit(1)


def _upload_structured_directory(
    uploader: MegaUploader,
    directory: Path,
    target_handle: str | None,
    progress: TransferProgress,
    cfg,
    client: MegaClient,
    *,
    keep_going: bool,
    share: bool,
    share_password: str | None,
    notes: list[tuple[str, str]],
    on_failure,
) -> None:
    """Structured (--keep-structure) directory upload with real progress rows."""
    items: dict[Path, str] = {}

    def on_manifest(files: list[tuple[Path, int]]) -> None:
        for path, size in files:
            try:
                name = str(path.relative_to(directory.parent))
            except ValueError:
                name = path.name
            items[path] = progress.add_item(name, size)

    def on_file_progress(path: Path, p) -> None:
        key = items.get(path)
        if key is not None:
            progress.update_item(key, p.bytes_done, p.total_bytes)

    def on_file_done(result, local_path: Path) -> None:
        finalize_upload_success(
            cfg,
            client,
            result,
            local_path,
            share=share,
            share_password=share_password,
            notes=notes,
        )
        key = items.get(local_path)
        if key is not None:
            progress.finish_item(key, "complete")

    try:
        uploader.upload_directory(
            directory,
            target_handle=target_handle,
            on_manifest=on_manifest,
            on_file_progress=on_file_progress,
            on_file_done=on_file_done,
            keep_going=keep_going,
        )
        if keep_going and uploader.last_directory_failures:
            for line in uploader.last_directory_failures:
                notes.append(("error", f"Failed: {line}"))
            for _ in uploader.last_directory_failures:
                on_failure(MegaError(message="directory item failed"))
        # Anything not finished (failed mid-file) is finalized by close().
        for path, key in items.items():
            if uploader.last_directory_failures and any(
                line.startswith(str(path)) for line in uploader.last_directory_failures
            ):
                progress.finish_item(key, "failed")
    except MegaError as exc:
        notes.append(("error", f"Upload failed: {exc}"))
        for line in uploader.last_directory_failures or [str(exc)]:
            log.error("Directory upload failure: %s", line)
        for path, key in items.items():
            if any(line.startswith(str(path)) for line in uploader.last_directory_failures):
                progress.finish_item(key, "failed")
        on_failure(exc)
