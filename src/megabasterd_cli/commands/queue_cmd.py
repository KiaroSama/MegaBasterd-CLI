"""`mb queue` - manage persistent transfer queue."""

from __future__ import annotations

import contextlib

import click

from ..config import data_dir
from ..queue.manager import JobStatus, JobType, QueueItem, QueueManager
from ..ui.prompts import confirm, print_success
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

    Downloads run with an anonymous MEGA API client. Uploads need an unlocked
    credential vault — the passphrase is requested once (either via
    `--vault-passphrase` or interactively) and reused for every queued upload.
    """
    from pathlib import Path

    from ..accounts.manager import AccountManager, AccountNotFound
    from ..config import accounts_file
    from ..core.api import MegaAPIClient
    from ..core.client import MegaClient
    from ..core.downloader import MegaDownloader
    from ..core.errors import MegaError
    from ..core.uploader import MegaUploader
    from ..ui.progress import build_progress
    from ..ui.prompts import ask, ask_password, print_error

    cfg = ctx.obj["config"]
    q = _queue()
    pending = q.pending()
    if not pending:
        print_success("Queue is empty.")
        return

    from ..proxy.runtime import effective_pool

    proxy_pool = effective_pool(cfg)

    api = MegaAPIClient(
        timeout=cfg.timeout_seconds,
        proxy_pool=proxy_pool,
        force_proxy=cfg.force_smart_proxy,
    )
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
    )

    # Lazy-unlock the credential vault only when we hit an upload item.
    mgr: AccountManager | None = None
    client_cache: dict[str, MegaClient] = {}

    def _client_for(account_id: str) -> MegaClient | None:
        """Resolve account_id -> logged-in MegaClient (cached)."""
        nonlocal mgr
        if account_id in client_cache:
            return client_cache[account_id]
        if mgr is None:
            mgr = AccountManager(accounts_file())
            if not mgr.list_accounts():
                print_error("No stored accounts; cannot run queued uploads.")
                return None
            passphrase = vault_passphrase or ask_password("Vault passphrase")
            mgr.unlock(passphrase)
        try:
            acc = mgr.get_account(account_id)
            password = mgr.get_password(account_id)
        except AccountNotFound:
            print_error(f"Account not found: {account_id}")
            return None
        upload_api = MegaAPIClient(
            timeout=cfg.timeout_seconds,
            proxy_pool=proxy_pool,
            force_proxy=cfg.force_smart_proxy,
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

    progress = build_progress()
    try:
        with progress:
            for item in pending:
                q.update_status(item.id, JobStatus.ACTIVE)
                try:
                    if item.type == JobType.DOWNLOAD.value:
                        out = (
                            Path(item.destination) if item.destination else Path(cfg.download_path)
                        )
                        out.mkdir(parents=True, exist_ok=True)
                        task_id = progress.add_task(item.source, total=1)

                        def cb(p, t=task_id):
                            progress.update(t, completed=p.bytes_done, total=p.total_bytes)

                        downloader.download_link(
                            item.source,
                            out,
                            password=item.password,
                            on_progress=cb,
                        )
                        q.update_status(item.id, JobStatus.DONE)
                    elif item.type == JobType.UPLOAD.value:
                        account_id = item.account or cfg.default_account
                        if not account_id:
                            q.update_status(
                                item.id,
                                JobStatus.FAILED,
                                error="No account on queued upload and no default_account set",
                            )
                            continue
                        upload_client = _client_for(account_id)
                        if upload_client is None:
                            q.update_status(
                                item.id,
                                JobStatus.FAILED,
                                error=f"Could not log in to {account_id}",
                            )
                            continue
                        local_path = Path(item.source)
                        if not local_path.is_file():
                            q.update_status(
                                item.id,
                                JobStatus.FAILED,
                                error=f"Local file missing: {local_path}",
                            )
                            continue
                        uploader = MegaUploader(
                            client=upload_client,
                            max_workers=cfg.upload_workers,
                            speed_limit_kbps=cfg.upload_speed_limit_kbps,
                            timeout=cfg.timeout_seconds,
                            proxy_pool=proxy_pool,
                            force_proxy=cfg.force_smart_proxy,
                        )
                        task_id = progress.add_task(
                            f"upload: {local_path.name}",
                            total=local_path.stat().st_size,
                        )

                        def cb_up(p, t=task_id):
                            progress.update(t, completed=p.bytes_done, total=p.total_bytes)

                        uploader.upload_file(local_path, on_progress=cb_up)
                        q.update_status(item.id, JobStatus.DONE)
                    else:
                        q.update_status(
                            item.id,
                            JobStatus.FAILED,
                            error=f"Unknown job type: {item.type}",
                        )
                except MegaError as e:
                    q.update_status(item.id, JobStatus.FAILED, error=str(e))
                except Exception as e:  # noqa: BLE001
                    q.update_status(item.id, JobStatus.FAILED, error=str(e))
    finally:
        for c in client_cache.values():
            with contextlib.suppress(Exception):
                c.logout()
