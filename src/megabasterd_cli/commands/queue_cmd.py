"""`mb queue` - manage persistent transfer queue."""

from __future__ import annotations

import contextlib
import logging
import threading
import uuid

import click

from ..config import data_dir
from ..queue.manager import (
    JobStatus,
    JobType,
    QueueCorruptionError,
    QueueItem,
    QueueLockError,
    QueueManager,
)
from ..ui.prompts import confirm, print_error, print_success
from ..ui.tables import render_queue

log = logging.getLogger(__name__)


def _queue(ctx: click.Context | None = None) -> QueueManager:
    """Build a QueueManager; on a corrupt queue, report and exit non-zero.

    A corrupt file is preserved and backed up by the manager; the command
    exits with a clear error rather than acting on an empty queue.
    """
    q = QueueManager(data_dir() / "queue.json")
    if q.is_corrupt and ctx is not None:
        print_error(q._corrupt_reason)
        ctx.exit(1)
    return q


def _guard(ctx: click.Context, fn):
    """Run a queue mutation; map corruption/lock errors to non-zero exits."""
    try:
        return fn()
    except QueueCorruptionError as exc:
        print_error(str(exc))
        ctx.exit(1)
    except QueueLockError as exc:
        print_error(str(exc))
        ctx.exit(1)


@click.group("queue", short_help="Manage the transfer queue.")
def queue() -> None:
    """Inspect and modify queued transfers."""


@queue.command("list", short_help="Show all queued transfers.")
@click.pass_context
def queue_list(ctx: click.Context) -> None:
    q = _queue(ctx)
    render_queue(
        [
            {
                "type": i.type,
                "source": i.source,
                "destination": i.destination,
                "size": i.size,
                "status": i.status,
            }
            for i in q.items
        ]
    )


@queue.command("add-download", short_help="Add a download to the queue.")
@click.argument("url")
@click.option("-o", "--output", default="", help="Destination directory.")
@click.option("-p", "--password", default=None)
@click.pass_context
def queue_add_download(ctx: click.Context, url: str, output: str, password: str | None) -> None:
    q = _queue(ctx)
    item = QueueItem(
        id=QueueItem.new_id(),
        type=JobType.DOWNLOAD.value,
        source=url,
        destination=output,
        password=password,
    )
    _guard(ctx, lambda: q.add(item))
    print_success(f"Queued download {item.id}: {url}")


@queue.command("add-upload", short_help="Add an upload to the queue.")
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
@click.option("-a", "--account", default=None)
@click.pass_context
def queue_add_upload(ctx: click.Context, path: str, account: str | None) -> None:
    q = _queue(ctx)
    item = QueueItem(
        id=QueueItem.new_id(),
        type=JobType.UPLOAD.value,
        source=path,
        destination="",
        account=account,
    )
    _guard(ctx, lambda: q.add(item))
    print_success(f"Queued upload {item.id}: {path}")


@queue.command("remove", short_help="Remove an item by id.")
@click.argument("item_id")
@click.pass_context
def queue_remove(ctx: click.Context, item_id: str) -> None:
    q = _queue(ctx)
    if _guard(ctx, lambda: q.remove(item_id)):
        print_success(f"Removed {item_id}")
    else:
        click.echo(f"Not found: {item_id}", err=True)
        ctx.exit(2)


@queue.command("retry", short_help="Return failed/interrupted items to pending.")
@click.argument("item_id")
@click.pass_context
def queue_retry(ctx: click.Context, item_id: str) -> None:
    """Retry a failed, interrupted, or canceled item (or `all` of them)."""
    q = _queue(ctx)
    if item_id == "all":
        retried = _guard(
            ctx,
            lambda: [
                i.id
                for i in list(q.items)
                if i.status
                in (JobStatus.FAILED.value, JobStatus.INTERRUPTED.value, JobStatus.CANCELED.value)
                and q.retry(i.id)
            ],
        )
        print_success(f"Retrying {len(retried)} item(s).")
        return
    if _guard(ctx, lambda: q.retry(item_id)):
        print_success(f"Retrying {item_id}")
    else:
        click.echo(f"Not found or not retryable: {item_id}", err=True)
        ctx.exit(2)


@queue.command("clear", short_help="Remove completed/canceled items.")
@click.pass_context
def queue_clear(ctx: click.Context) -> None:
    q = _queue(ctx)
    if not confirm("Clear completed and canceled items?", default=True):
        return
    n = _guard(ctx, q.clear_done)
    print_success(f"Removed {n} items.")


@queue.command("reset", short_help="Discard a corrupt/current queue and start empty.")
@click.pass_context
def queue_reset(ctx: click.Context) -> None:
    """Recover from a corrupt queue by writing a fresh empty one.

    The corrupt original was already backed up as `queue.json.corrupt.*`.
    """
    q = QueueManager(data_dir() / "queue.json")
    if not confirm("Discard the current queue and start empty?", default=False):
        return
    _guard(ctx, q.reset)
    print_success("Queue reset to empty.")


@queue.command("run", short_help="Process pending queue items sequentially.")
@click.option(
    "--vault-passphrase",
    default=None,
    help="Vault passphrase (for queued uploads). Prompted once if needed.",
)
@click.option("--mfa-code", default=None, help="2FA code if queued upload accounts require it.")
@click.pass_context
def queue_run(ctx: click.Context, vault_passphrase: str | None, mfa_code: str | None) -> None:
    """Run all pending items in order.

    Jobs left `active` by a crashed/killed run are recovered as `interrupted`
    and re-run automatically. Exit status is non-zero when any job fails.
    Downloads run with an anonymous MEGA API client. Uploads need an unlocked
    credential vault — the passphrase is requested once (either via
    `--vault-passphrase` or interactively) and reused for every queued upload.
    """
    from pathlib import Path

    from ..accounts.manager import AccountManager, AccountNotFound, resolve_account_id
    from ..config import accounts_file
    from ..core.api import MegaAPIClient
    from ..core.client import MegaClient
    from ..core.downloader import MegaDownloader
    from ..core.errors import MegaError
    from ..core.uploader import MegaUploader
    from ..ui.prompts import ask, ask_password
    from ..ui.transfer_progress import TransferProgress, redact_link
    from ..upload_support import finalize_upload_success
    from ..utils.redaction import redact_text
    from ..utils.speed import make_limiter

    cfg = ctx.obj["config"]
    quiet = bool(ctx.obj.get("quiet"))
    q = _queue(ctx)
    for recovered_item in _guard(ctx, q.recover_interrupted):
        print_error(f"Recovered interrupted job {recovered_item.id} from a previous run.")
    runnable = q.runnable()
    if not runnable:
        print_success("Queue is empty.")
        return

    run_id = uuid.uuid4().hex[:12]

    from ..proxy.runtime import effective_pool

    proxy_pool = effective_pool(cfg)

    api = MegaAPIClient(
        timeout=cfg.timeout_seconds,
        proxy_pool=proxy_pool,
        force_proxy=cfg.force_smart_proxy,
        user_agent=cfg.user_agent,
    )
    # Aggregate command-wide caps shared with every queue transfer.
    download_limiter = make_limiter(cfg.speed_limit_kbps)
    upload_limiter = make_limiter(cfg.upload_speed_limit_kbps)
    downloader = MegaDownloader(
        api=api,
        max_workers=cfg.max_workers,
        speed_limit_kbps=cfg.speed_limit_kbps,
        verify_integrity=cfg.verify_integrity,
        timeout=cfg.timeout_seconds,
        proxy_pool=proxy_pool,
        force_proxy=cfg.force_smart_proxy,
        quota_wait_seconds=cfg.quota_wait_seconds,
        quota_max_wait_loops=cfg.quota_max_wait_loops,
        keep_state_files_on_error=cfg.keep_state_files_on_error,
        limiter=download_limiter,
        auto_resume=cfg.auto_resume,
        user_agent=cfg.user_agent,
    )

    # Lazy-unlock the credential vault only when we hit an upload item.
    mgr: AccountManager | None = None
    client_cache: dict[str, MegaClient] = {}

    def _manager() -> AccountManager | None:
        nonlocal mgr
        if mgr is None:
            candidate = AccountManager(accounts_file())
            if not candidate.list_accounts():
                print_error("No stored accounts; cannot run queued uploads.")
                return None
            passphrase = vault_passphrase or ask_password("Vault passphrase")
            candidate.unlock(passphrase)
            mgr = candidate
        return mgr

    def _client_for(account_id: str) -> MegaClient | None:
        """Resolve account_id -> logged-in MegaClient (cached)."""
        if account_id in client_cache:
            return client_cache[account_id]
        manager = _manager()
        if manager is None:
            return None
        try:
            acc = manager.get_account(account_id)
            password = manager.get_password(account_id)
        except AccountNotFound:
            print_error(f"Account not found: {account_id}")
            return None
        upload_api = MegaAPIClient(
            timeout=cfg.timeout_seconds,
            proxy_pool=proxy_pool,
            force_proxy=cfg.force_smart_proxy,
            user_agent=cfg.user_agent,
        )
        upload_client = MegaClient(api=upload_api)
        try:
            upload_client.login(
                acc.email,
                password,
                mfa_code=mfa_code,
                mfa_prompt=lambda: ask("Enter 6-digit 2FA code").strip(),
            )
        except MegaError as exc:
            print_error(f"Login failed for {acc.email}: {redact_text(str(exc))}")
            # MF8: close the API/HTTP session on the failed-login path before
            # the client ever enters the cache.
            upload_api.close()
            return None
        client_cache[account_id] = upload_client
        return upload_client

    # Heartbeat: prove this run is alive so a parallel `queue run` (or the
    # recovery pass of the next run) never steals a live lease.
    heartbeat_stop = threading.Event()
    current_item_id: list[str | None] = [None]

    def _heartbeat_loop() -> None:
        while not heartbeat_stop.wait(30.0):
            item_id = current_item_id[0]
            if item_id:
                with contextlib.suppress(Exception):
                    q.touch(item_id, run_id)

    heartbeat = threading.Thread(target=_heartbeat_loop, name="queue-heartbeat", daemon=True)
    heartbeat.start()

    failures = 0
    notes: list[tuple[str, str]] = []
    progress = TransferProgress(
        title="MEGA Queue Run",
        direction="mixed",
        details=[f"Jobs: {len(runnable)}", "", "Backend: MegaBasterd-CLI"],
        item_label="jobs",
        quiet=quiet,
    )

    def _fail(item, row: str, message: str) -> None:
        nonlocal failures
        message = redact_text(message)
        q.update_status(item.id, JobStatus.FAILED, error=message)
        progress.finish_item(row, "failed")
        notes.append(("error", f"Job {item.id} failed: {message}"))
        failures += 1

    try:
        with progress:
            while True:
                # Atomic claim: reload + stale recovery + lease under ONE
                # cross-process lock, so a second `queue run` (thread,
                # instance, or process) can never take the same job.
                item = q.claim_next(run_id)
                if item is None:
                    break
                current_item_id[0] = item.id
                # The progress row exists BEFORE any branch runs; every
                # outcome below finalizes it exactly once so queue JSON and
                # the visible row always agree.
                if item.type == JobType.UPLOAD.value:
                    row = progress.add_item(
                        Path(item.source).name, direction="upload", status="active"
                    )
                else:
                    row = progress.add_item(
                        redact_link(item.source), direction="download", status="active"
                    )
                try:
                    if item.type == JobType.DOWNLOAD.value:
                        out = (
                            Path(item.destination) if item.destination else Path(cfg.download_path)
                        )
                        out.mkdir(parents=True, exist_ok=True)

                        def cb(p, t=row):
                            progress.update_item(t, p.bytes_done, p.total_bytes)

                        result = downloader.download_link(
                            item.source,
                            out,
                            password=item.password,
                            on_progress=cb,
                        )
                        progress.set_item_name(row, f"↓ {result.path.name}")
                        progress.finish_item(row, "complete")
                        q.update_status(item.id, JobStatus.DONE)
                    elif item.type == JobType.UPLOAD.value:
                        manager = _manager()
                        account_id = item.account or (
                            resolve_account_id(manager, cfg.default_account) if manager else None
                        )
                        if not account_id:
                            _fail(
                                item, row, "No account on queued upload and no default account set"
                            )
                            continue
                        upload_client = _client_for(account_id)
                        if upload_client is None:
                            _fail(item, row, f"Could not log in to {account_id}")
                            continue
                        local_path = Path(item.source)
                        if not local_path.is_file():
                            _fail(item, row, f"Local file missing: {local_path}")
                            continue
                        uploader = MegaUploader(
                            client=upload_client,
                            max_workers=cfg.upload_workers,
                            speed_limit_kbps=cfg.upload_speed_limit_kbps,
                            timeout=cfg.timeout_seconds,
                            proxy_pool=proxy_pool,
                            force_proxy=cfg.force_smart_proxy,
                            limiter=upload_limiter,
                            auto_resume=cfg.auto_resume,
                            user_agent=cfg.user_agent,
                        )
                        progress.update_item(row, 0, local_path.stat().st_size)

                        def cb_up(p, t=row):
                            progress.update_item(t, p.bytes_done, p.total_bytes)

                        upload_result = uploader.upload_file(local_path, on_progress=cb_up)
                        finalize_upload_success(
                            cfg,
                            upload_client,
                            upload_result,
                            local_path,
                            note=lambda kind, msg: notes.append((kind, msg)),
                        )
                        progress.finish_item(row, "complete")
                        q.update_status(item.id, JobStatus.DONE)
                    else:
                        _fail(item, row, f"Unknown job type: {item.type}")
                except KeyboardInterrupt:
                    # User cancellation: release the lease so the next run
                    # resumes this job, and finalize the row as canceled.
                    progress.finish_item(row, "canceled")
                    with contextlib.suppress(Exception):
                        q.update_status(item.id, JobStatus.INTERRUPTED)
                    raise
                except MegaError as e:
                    _fail(item, row, str(e))
                except Exception as e:  # noqa: BLE001
                    log.exception("Unexpected error while running queue job %s", item.id)
                    _fail(item, row, str(e))
                finally:
                    current_item_id[0] = None
    except QueueLockError as exc:
        print_error(str(exc))
        failures += 1
    finally:
        heartbeat_stop.set()
        heartbeat.join(timeout=2.0)
        api.close()
        for c in client_cache.values():
            with contextlib.suppress(Exception):
                c.logout()
                c.api.close()

    from ..ui.prompts import print_info

    printer = {"success": print_success, "info": print_info, "error": print_error}
    for kind, message in notes:
        printer[kind](message)
    if failures:
        print_error(f"{failures} queue job(s) failed.")
        ctx.exit(1)
