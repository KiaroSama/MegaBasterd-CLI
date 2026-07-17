"""`mb queue` - manage persistent transfer queue."""

from __future__ import annotations

import contextlib
import threading
import uuid

import click

from ..config import data_dir
from ..queue.manager import JobStatus, JobType, QueueItem, QueueManager
from ..ui.prompts import confirm, print_error, print_success
from ..ui.tables import render_queue


def _queue() -> QueueManager:
    return QueueManager(data_dir() / "queue.json")


@click.group("queue", short_help="Manage the transfer queue.")
def queue() -> None:
    """Inspect and modify queued transfers."""


@queue.command("list", short_help="Show all queued transfers.")
def queue_list() -> None:
    q = _queue()
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
def queue_add_download(url: str, output: str, password: str | None) -> None:
    q = _queue()
    item = QueueItem(
        id=QueueItem.new_id(),
        type=JobType.DOWNLOAD.value,
        source=url,
        destination=output,
        password=password,
    )
    q.add(item)
    print_success(f"Queued download {item.id}: {url}")


@queue.command("add-upload", short_help="Add an upload to the queue.")
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
@click.option("-a", "--account", default=None)
def queue_add_upload(path: str, account: str | None) -> None:
    q = _queue()
    item = QueueItem(
        id=QueueItem.new_id(),
        type=JobType.UPLOAD.value,
        source=path,
        destination="",
        account=account,
    )
    q.add(item)
    print_success(f"Queued upload {item.id}: {path}")


@queue.command("remove", short_help="Remove an item by id.")
@click.argument("item_id")
def queue_remove(item_id: str) -> None:
    q = _queue()
    if q.remove(item_id):
        print_success(f"Removed {item_id}")
    else:
        click.echo(f"Not found: {item_id}", err=True)


@queue.command("retry", short_help="Return failed/interrupted items to pending.")
@click.argument("item_id")
def queue_retry(item_id: str) -> None:
    """Retry a failed, interrupted, or canceled item (or `all` of them)."""
    q = _queue()
    if item_id == "all":
        retried = [
            i.id
            for i in list(q.items)
            if i.status
            in (JobStatus.FAILED.value, JobStatus.INTERRUPTED.value, JobStatus.CANCELED.value)
            and q.retry(i.id)
        ]
        print_success(f"Retrying {len(retried)} item(s).")
        return
    if q.retry(item_id):
        print_success(f"Retrying {item_id}")
    else:
        click.echo(f"Not found or not retryable: {item_id}", err=True)


@queue.command("clear", short_help="Remove completed/canceled items.")
def queue_clear() -> None:
    q = _queue()
    if not confirm("Clear completed and canceled items?", default=True):
        return
    n = q.clear_done()
    print_success(f"Removed {n} items.")


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
    from ..utils.speed import make_limiter
    from .upload_cmd import finalize_upload_success

    cfg = ctx.obj["config"]
    quiet = bool(ctx.obj.get("quiet"))
    q = _queue()
    recovered = q.recover_interrupted()
    for item in recovered:
        print_error(f"Recovered interrupted job {item.id} from a previous run.")
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
            print_error(f"Login failed for {acc.email}: {exc}")
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
    try:
        with progress:
            for item in runnable:
                q.mark_active(item.id, run_id)
                current_item_id[0] = item.id
                try:
                    if item.type == JobType.DOWNLOAD.value:
                        out = (
                            Path(item.destination) if item.destination else Path(cfg.download_path)
                        )
                        out.mkdir(parents=True, exist_ok=True)
                        row = progress.add_item(
                            redact_link(item.source), direction="download", status="active"
                        )

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
                            q.update_status(
                                item.id,
                                JobStatus.FAILED,
                                error="No account on queued upload and no default account set",
                            )
                            failures += 1
                            continue
                        upload_client = _client_for(account_id)
                        if upload_client is None:
                            q.update_status(
                                item.id,
                                JobStatus.FAILED,
                                error=f"Could not log in to {account_id}",
                            )
                            failures += 1
                            continue
                        local_path = Path(item.source)
                        if not local_path.is_file():
                            q.update_status(
                                item.id,
                                JobStatus.FAILED,
                                error=f"Local file missing: {local_path}",
                            )
                            failures += 1
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
                        row = progress.add_item(
                            local_path.name,
                            local_path.stat().st_size,
                            direction="upload",
                        )

                        def cb_up(p, t=row):
                            progress.update_item(t, p.bytes_done, p.total_bytes)

                        upload_result = uploader.upload_file(local_path, on_progress=cb_up)
                        finalize_upload_success(
                            cfg, upload_client, upload_result, local_path, notes=notes
                        )
                        progress.finish_item(row, "complete")
                        q.update_status(item.id, JobStatus.DONE)
                    else:
                        q.update_status(
                            item.id,
                            JobStatus.FAILED,
                            error=f"Unknown job type: {item.type}",
                        )
                        failures += 1
                except MegaError as e:
                    q.update_status(item.id, JobStatus.FAILED, error=str(e))
                    failures += 1
                except Exception as e:  # noqa: BLE001
                    q.update_status(item.id, JobStatus.FAILED, error=str(e))
                    failures += 1
                finally:
                    current_item_id[0] = None
    finally:
        heartbeat_stop.set()
        heartbeat.join(timeout=2.0)
        for c in client_cache.values():
            with contextlib.suppress(Exception):
                c.logout()

    from ..ui.prompts import print_info

    printer = {"success": print_success, "info": print_info, "error": print_error}
    for kind, message in notes:
        printer[kind](message)
    if failures:
        print_error(f"{failures} queue job(s) failed.")
        ctx.exit(1)
