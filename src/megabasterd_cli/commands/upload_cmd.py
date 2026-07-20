"""`mb upload` - upload local files to a MEGA account."""

from __future__ import annotations

import contextlib
import logging
import sys
import threading
from pathlib import Path

import click

from ..accounts.manager import AccountManager, AccountNotFound, resolve_account_id
from ..config import accounts_file
from ..core.api import MegaAPIClient
from ..core.client import MegaClient
from ..core.errors import MegaError, QuotaError
from ..core.uploader import MegaUploader, walk_upload_entries
from ..ui.machine_output import MachineOutput, error_code_for
from ..ui.prompts import (
    ask_mfa_code,
    ask_password,
    print_error,
    print_info,
    print_success,
    print_warn,
)
from ..ui.transfer_progress import TransferProgress
from ..upload_support import QuotaLedger, finalize_upload_success
from ..utils.redaction import redact_text
from ..utils.speed import make_limiter
from .api_support import api_for

log = logging.getLogger(__name__)


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
@click.option(
    "--json",
    "json_output",
    is_flag=True,
    help="Machine mode: emit one JSON result record per line on stdout; "
    "human output and progress go to stderr.",
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
    json_output: bool,
) -> None:
    """Upload files (or all files inside a directory) to MEGA.

    Exit status is non-zero when any item fails (`--keep-going` continues
    processing but does not turn failures into overall success).
    """
    cfg = ctx.obj["config"]
    quiet = bool(ctx.obj.get("quiet"))
    machine = MachineOutput(json_output)
    if json_output:
        quiet = True
        redirect = contextlib.redirect_stdout(sys.stderr)
        redirect.__enter__()
        ctx.call_on_close(lambda: redirect.__exit__(None, None, None))

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
        if p.is_dir():
            # Symlinks are never walked into an upload; say so, because the
            # resulting upload is deliberately incomplete.
            entries, skipped_links = walk_upload_entries(p)
            if skipped_links:
                print_info(
                    f"Skipping {skipped_links} symlink(s) under {p.name}: symlinked files "
                    "are not uploaded, so this upload is deliberately incomplete."
                )
            files = [f for f in entries if f.is_file()]
            if keep_structure:
                jobs.append((p, sum(f.stat().st_size for f in files)))
            else:
                jobs.extend((f, f.stat().st_size) for f in files)
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
        return api_for(cfg, proxy_pool=proxy_pool, user_agent=cfg.user_agent)

    def _login_client(email: str, password: str) -> MegaClient | None:
        api = _new_api()
        client = MegaClient(api=api)
        try:
            client.login(email, password, mfa_code=mfa_code, mfa_prompt=ask_mfa_code)
            return client
        except MegaError as exc:
            print_error(f"Login failed for {email}: {redact_text(str(exc))}")
            # MF8: never leak the API/HTTP session when login fails.
            api.close()
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
    clients: dict[str, MegaClient] = {}  # email -> logged-in BASE client (cached)
    client_cache_lock = threading.Lock()
    failures = 0
    fail_lock = threading.Lock()
    notes: list[tuple[str, str]] = []
    notes_lock = threading.Lock()

    def _note(kind: str, message: str) -> None:
        with notes_lock:
            notes.append((kind, message))

    def _base_for_email(email_or_label: str) -> MegaClient | None:
        """Thread-safe cached login: one authenticated BASE client per account.

        Logins are serialized under the cache lock so two parallel files that
        first touch the same account never double-login (and never prompt MFA
        twice)."""
        try:
            acc = mgr.get_account(email_or_label)
            password = mgr.get_password(email_or_label)
        except AccountNotFound:
            print_error(f"Account not found: {email_or_label}")
            return None
        with client_cache_lock:
            if acc.email in clients:
                return clients[acc.email]
            client = _login_client(acc.email, password)
            if client is not None:
                clients[acc.email] = client
            return client

    ledger: QuotaLedger | None = None
    fixed_email: str | None = None
    if auto_account and not account:
        free = {
            acc.email: acc.quota_total - acc.quota_used
            for acc in mgr.list_accounts()
            if acc.quota_total is not None and acc.quota_used is not None
        }
        if not free:
            print_error("--auto-account needs cached quotas; run `mb account refresh-all` first.")
            ctx.exit(1)
        ledger = QuotaLedger(free)
    else:
        account_id = resolve_account_id(mgr, cfg.default_account, account)
        if not account_id:
            print_error("No account specified and no default set.")
            ctx.exit(1)
        if _base_for_email(account_id) is None:
            ctx.exit(1)
        fixed_email = next(iter(clients.keys()))

    def _refresh_quota_after_error(email: str) -> None:
        """After a QuotaError, replace the stale ledger balance with the
        account's LIVE quota so re-planning never trusts old numbers.

        The refresh runs on a SHORT-LIVED ISOLATED client (its own API/HTTP
        session and request counter, reusing the account's already
        authenticated session material — no second login or MFA prompt), so
        two files hitting QuotaError on one account never share the cached
        base client's mutable request state. The client is always closed.
        """
        if ledger is None:
            return
        with client_cache_lock:
            base = clients.get(email)
        if base is None:
            ledger.reconcile_free(email, 0)
            return
        client = _worker_client(base)
        try:
            quota = client.get_quota()
            live_free = quota.get("mstrg", 0) - quota.get("cstrg", 0)
            ledger.reconcile_free(email, live_free)
            mgr.update_quota(email, quota.get("cstrg", 0), quota.get("mstrg", 0))
        except MegaError:
            # Cannot verify: treat the account as unavailable for this run.
            ledger.reconcile_free(email, 0)
        finally:
            client.close()

    def _fail_item(
        message: str,
        *,
        path: Path | None = None,
        exc: BaseException | None = None,
        account: str | None = None,
    ) -> None:
        nonlocal failures
        with fail_lock:
            failures += 1
        _note("error", message)
        machine.emit(
            event="result",
            type="upload",
            status="failed",
            name=path.name if path is not None else None,
            path=str(path) if path is not None else None,
            account=account,
            error_code=error_code_for(exc) if exc is not None else None,
            error=message,
        )

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

    def _run_one(job: tuple[Path, int]) -> None:
        file_path, size = job
        _upload_one_sequential(
            file_path,
            size,
            ledger=ledger,
            fixed_email=fixed_email,
            # An ISOLATED per-transfer client (own API/HTTP session) reusing the
            # cached account's authenticated session material.
            worker_for_email=lambda e: (
                _worker_client(base) if (base := _base_for_email(e)) is not None else None
            ),
            refresh_quota=_refresh_quota_after_error,
            resolve_target=_resolve_target_handle,
            make_uploader=_make_uploader,
            progress=progress,
            cfg=cfg,
            keep_structure=keep_structure,
            keep_going=keep_going,
            auto_share=auto_share,
            share_password=share_password,
            rename_to=rename if single_file else None,
            note=_note,
            fail_item=_fail_item,
            machine=machine,
        )

    # Parallel whenever more than one FLAT file is queued — including
    # `--auto-account`, which selects/reserves per file safely from the
    # thread-safe ledger and gives every transfer its own isolated client.
    # `--keep-structure` trees stay sequential (one tree = one account).
    can_parallel = parallel > 1 and not keep_structure and len(jobs) > 1

    try:
        with progress:
            if can_parallel:
                from concurrent.futures import ThreadPoolExecutor

                with ThreadPoolExecutor(max_workers=parallel) as pool:
                    list(pool.map(_run_one, jobs))
            else:
                for job in jobs:
                    _run_one(job)
    finally:
        for client in clients.values():
            try:
                client.logout()
            except Exception:  # noqa: BLE001
                log.debug("Logout failed", exc_info=True)
            finally:
                client.api.close()

    printer = {"success": print_success, "info": print_info, "error": print_error}
    for kind, message in notes:
        printer[kind](message)
    if failures:
        print_warn(f"{failures} upload item(s) failed.")
        ctx.exit(1)


def _upload_one_sequential(
    file_path: Path,
    size: int,
    *,
    ledger: QuotaLedger | None,
    fixed_email: str | None,
    worker_for_email,
    refresh_quota,
    resolve_target,
    make_uploader,
    progress: TransferProgress,
    cfg,
    keep_structure: bool,
    keep_going: bool,
    auto_share: bool,
    share_password: str | None,
    rename_to: str | None,
    note,
    fail_item,
    machine: MachineOutput | None = None,
) -> None:  # noqa: C901 - one cohesive per-file state machine
    """Upload one job, selecting the account at start time.

    Thread-safe: safe to call concurrently (one call per file). The account is
    reserved from the live ledger immediately before the file starts, and each
    attempt gets its OWN isolated per-transfer client (own API/HTTP session),
    closed in a `finally`. On `QuotaError` the account's quota is refreshed and
    the SAME file is retried on another suitable account; each account is tried
    at most once per file, so the retry is bounded. A `--keep-structure` tree
    is uploaded as ONE unit on ONE account; a mid-tree failure is a clear
    failure (never a silently distributed or partial tree).
    """
    is_tree = file_path.is_dir() and keep_structure
    row = progress.add_item(file_path.name, None if is_tree else size)
    attempted: set[str] = set()
    while True:
        if ledger is not None:
            email = ledger.reserve(size, exclude=attempted)
            if email is None:
                progress.finish_item(row, "failed")
                fail_item(
                    f"No stored account has enough known free space for {file_path.name}.",
                    path=file_path,
                )
                return
        else:
            email = fixed_email
            if email is None:
                progress.finish_item(row, "failed")
                fail_item(f"No active session for {file_path.name}.", path=file_path)
                return

        client = worker_for_email(email)
        if client is None:
            if ledger is not None:
                attempted.add(email)
                ledger.release(email, size)
                continue
            progress.finish_item(row, "failed")
            fail_item(f"No active session for {file_path.name}.", path=file_path, account=email)
            return
        if ledger is not None:
            note("info", f"Using {email} for {file_path.name}")

        try:
            try:
                target_handle = resolve_target(client)
            except MegaError as exc:
                if ledger is not None:
                    ledger.release(email, size)
                progress.finish_item(row, "failed")
                fail_item(
                    f"Target resolution failed for {file_path.name}: {redact_text(str(exc))}",
                    path=file_path,
                    exc=exc,
                    account=email,
                )
                return

            uploader = make_uploader(client)
            try:
                if is_tree:
                    tree_ok = _upload_structured_directory(
                        uploader,
                        file_path,
                        target_handle,
                        progress,
                        cfg,
                        client,
                        keep_going=keep_going,
                        share=auto_share,
                        share_password=share_password,
                        note=note,
                        on_failure=lambda exc, em=email: fail_item(
                            f"Directory upload incomplete on {em}: {file_path.name}",
                            path=file_path,
                            exc=exc,
                            account=em,
                        ),
                        machine=machine,
                    )
                    if tree_ok:
                        progress.finish_item(row, "complete")
                    else:
                        # A partial remote tree is a clear failure — never
                        # re-planned to another account, never marked complete.
                        progress.finish_item(row, "failed")
                        if ledger is not None:
                            refresh_quota(email)
                    return
                result = uploader.upload_file(
                    file_path,
                    target_handle=target_handle,
                    rename_to=rename_to,
                    on_progress=lambda p: progress.update_item(row, p.bytes_done, p.total_bytes),
                )
                finalize_upload_success(
                    cfg,
                    client,
                    result,
                    file_path,
                    share=auto_share,
                    share_password=share_password,
                    note=note,
                    machine=machine,
                )
                progress.finish_item(row, "complete")
                return
            except QuotaError as exc:
                attempted.add(email)
                refresh_quota(email)
                if ledger is not None and not is_tree:
                    # Bounded re-plan: retry this file once per remaining account.
                    note("error", f"Quota exhausted on {email}; re-planning {file_path.name}.")
                    continue
                progress.finish_item(row, "failed")
                fail_item(
                    f"Upload failed: {file_path.name}: {redact_text(str(exc))}",
                    path=file_path,
                    exc=exc,
                    account=email,
                )
                return
            except MegaError as exc:
                if ledger is not None:
                    # A failed single file consumed nothing; a partial tree DID
                    # consume remote space, so refresh instead of re-crediting.
                    if is_tree:
                        refresh_quota(email)
                    else:
                        ledger.release(email, size)
                progress.finish_item(row, "failed")
                fail_item(
                    f"Upload failed: {file_path.name}: {redact_text(str(exc))}",
                    path=file_path,
                    exc=exc,
                    account=email,
                )
                return
            except Exception as exc:  # noqa: BLE001
                log.exception("Unexpected error during upload")
                if ledger is not None:
                    if is_tree:
                        refresh_quota(email)
                    else:
                        ledger.release(email, size)
                progress.finish_item(row, "failed")
                fail_item(
                    f"Unexpected error: {file_path.name}: {redact_text(str(exc))}",
                    path=file_path,
                    exc=exc,
                    account=email,
                )
                return
        finally:
            # Close the per-transfer worker's HTTP session WITHOUT logging out
            # the shared cached account session.
            client.close()


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
    note,
    on_failure,
    machine: MachineOutput | None = None,
) -> bool:
    """Structured (--keep-structure) directory upload with real progress rows.

    Returns True when every file in the tree uploaded successfully."""
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
            note=note,
            machine=machine,
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
                note("error", f"Failed: {redact_text(line)}")
            for _ in uploader.last_directory_failures:
                on_failure(MegaError(message="directory item failed"))
        for path, key in items.items():
            if uploader.last_directory_failures and any(
                line.startswith(str(path)) for line in uploader.last_directory_failures
            ):
                progress.finish_item(key, "failed")
        return not uploader.last_directory_failures
    except MegaError as exc:
        note("error", f"Upload failed: {redact_text(str(exc))}")
        for line in uploader.last_directory_failures or [str(exc)]:
            log.error("Directory upload failure: %s", redact_text(line))
        for path, key in items.items():
            if any(line.startswith(str(path)) for line in uploader.last_directory_failures):
                progress.finish_item(key, "failed")
        on_failure(exc)
        return False
