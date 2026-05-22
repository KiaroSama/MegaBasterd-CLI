"""`mb upload` - upload local files to a MEGA account."""

from __future__ import annotations

import logging
from pathlib import Path

import click

from ..accounts.manager import AccountManager, AccountNotFound
from ..config import accounts_file
from ..core.api import MegaAPIClient
from ..core.client import MegaClient
from ..core.errors import MegaError
from ..core.uploader import MegaUploader
from ..ui.progress import build_progress
from ..ui.prompts import ask, ask_password, print_error, print_info, print_success, print_warn
from ..utils.helpers import format_bytes

log = logging.getLogger(__name__)


def _mfa_prompt() -> str:
    return ask("Enter 6-digit 2FA code").strip()


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
    help="Account email or label (default: config default).",
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
    help="Per-transfer upload speed limit in KB/s (0 = unlimited).",
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
    help="Pick the stored account with the most free space for each file.",
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
    help="After each upload, print a public link for the uploaded file.",
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
    """Upload files (or all files inside a directory) to MEGA."""
    cfg = ctx.obj["config"]

    mgr = AccountManager(accounts_file())
    if not mgr.list_accounts():
        print_error("No accounts found. Use `mb account add` first.")
        return
    passphrase = vault_passphrase or ask_password("Vault passphrase")
    mgr.unlock(passphrase)

    # Build the flat file list early so auto-account can size-match per file
    file_list: list[Path] = []
    for p in paths:
        if p.is_dir() and not keep_structure:
            file_list.extend(sorted(f for f in p.rglob("*") if f.is_file()))
        elif p.is_dir() and keep_structure:
            file_list.append(p)  # Treated specially below
        else:
            file_list.append(p)

    workers = workers if workers is not None else cfg.upload_workers
    speed_limit_kbps = (
        speed_limit_kbps if speed_limit_kbps is not None else cfg.upload_speed_limit_kbps
    )
    parallel = parallel_transfers if parallel_transfers is not None else cfg.max_parallel_uploads
    parallel = max(1, parallel)

    # Load the SmartProxyPool when enabled so chunk uploads rotate proxies.
    from ..proxy.runtime import effective_pool

    proxy_pool = effective_pool(cfg)

    def _resolve_account_for(size: int) -> tuple[str, str] | None:
        """Return (email, decrypted_password) — by --account, --auto-account, or default."""
        if account:
            try:
                acc = mgr.get_account(account)
                return acc.email, mgr.get_password(account)
            except AccountNotFound:
                print_error(f"Account not found: {account}")
                return None
        if auto_account:
            picked = mgr.pick_account_with_space(size)
            if picked is None:
                print_error("No stored account has enough free space.")
                return None
            return picked.email, mgr.get_password(picked.email)
        default = cfg.default_account
        if not default:
            print_error("No account specified and no default set.")
            return None
        try:
            acc = mgr.get_account(default)
            return acc.email, mgr.get_password(default)
        except AccountNotFound:
            print_error(f"Default account not found: {default}")
            return None

    # When --auto-account is OFF we can log in once and reuse the client
    fixed_creds: tuple[str, str] | None = None
    if not auto_account:
        fixed_creds = _resolve_account_for(0)
        if not fixed_creds:
            return

    def _new_client(email: str, password: str) -> MegaClient | None:
        api = MegaAPIClient(
            timeout=cfg.timeout_seconds,
            proxy_pool=proxy_pool,
            force_proxy=cfg.force_smart_proxy,
        )
        client = MegaClient(api=api)
        try:
            client.login(email, password, mfa_code=mfa_code, mfa_prompt=_mfa_prompt)
            return client
        except MegaError as exc:
            print_error(f"Login failed for {email}: {exc}")
            return None

    overall_progress = build_progress()
    active_client: MegaClient | None = None
    try:
        if fixed_creds:
            active_client = _new_client(*fixed_creds)
            if not active_client:
                return

        # Decide whether to parallelize file uploads.
        # Folder-uploads with --keep-structure and --auto-account stay sequential
        # because they need fresh state per file.
        can_parallel = (
            parallel > 1 and not keep_structure and not auto_account and active_client is not None
        )

        if can_parallel:
            from concurrent.futures import ThreadPoolExecutor

            def _upload_one(file_path: Path):
                if not file_path.is_file():
                    return
                target_handle: str | None = None
                if target:
                    node = active_client.find_node(handle=target) or active_client.find_node(
                        path=target
                    )
                    if not node or not node.is_folder:
                        print_error(f"Target folder not found: {target}")
                        return
                    target_handle = node.handle

                uploader = MegaUploader(
                    client=active_client,
                    max_workers=workers,
                    speed_limit_kbps=speed_limit_kbps,
                    timeout=cfg.timeout_seconds,
                    proxy_pool=proxy_pool,
                    force_proxy=cfg.force_smart_proxy,
                )
                task_id = overall_progress.add_task(
                    description=f"Uploading: {file_path.name}",
                    total=file_path.stat().st_size,
                )

                def on_progress(p, t=task_id):
                    overall_progress.update(t, completed=p.bytes_done, total=p.total_bytes)

                try:
                    result = uploader.upload_file(
                        file_path,
                        target_handle=target_handle,
                        rename_to=rename if len(file_list) == 1 else None,
                        on_progress=on_progress,
                    )
                    overall_progress.update(
                        task_id,
                        description=f"Done: {result.name}",
                        completed=result.size,
                        total=result.size,
                    )
                    print_success(
                        f"{result.name} ({format_bytes(result.size)}) "
                        f"in {result.elapsed_seconds:.1f}s"
                    )
                    if auto_share:
                        try:
                            link = active_client.export_link(
                                result.file_handle,
                                password=share_password,
                            )
                            print_info(f"Share link: {link}")
                        except MegaError as exc:
                            print_error(f"Could not generate share link: {exc}")
                except MegaError as e:
                    print_error(f"Upload failed: {e}")
                except Exception as e:
                    log.exception("Unexpected error during upload")
                    print_error(f"Unexpected error: {e}")

            with overall_progress, ThreadPoolExecutor(max_workers=parallel) as pool:
                list(pool.map(_upload_one, [p for p in file_list if p.is_file()]))
            return

        with overall_progress:
            for file_path in file_list:
                # Per-file account selection in auto mode
                client = active_client
                if auto_account:
                    size = file_path.stat().st_size if file_path.is_file() else 0
                    creds = _resolve_account_for(size)
                    if not creds:
                        continue
                    if client is not None:
                        client.logout()
                    client = _new_client(*creds)
                    if not client:
                        continue
                    print_info(f"Using {creds[0]} for {file_path.name}")

                if client is None:
                    print_error("No active session.")
                    return

                # Resolve target handle
                target_handle: str | None = None
                if target:
                    node = client.find_node(handle=target) or client.find_node(path=target)
                    if not node or not node.is_folder:
                        print_error(f"Target folder not found: {target}")
                        continue
                    target_handle = node.handle

                uploader = MegaUploader(
                    client=client,
                    max_workers=workers,
                    speed_limit_kbps=speed_limit_kbps,
                    timeout=cfg.timeout_seconds,
                    proxy_pool=proxy_pool,
                    force_proxy=cfg.force_smart_proxy,
                )

                if file_path.is_dir() and keep_structure:
                    print_info(f"Uploading directory {file_path} (keeping structure)")

                    def on_dir_progress(p, fp=file_path):
                        pass

                    def on_dir_file_done(result, lp):
                        print_success(
                            f"{lp.name} ({format_bytes(result.size)}) "
                            f"in {result.elapsed_seconds:.1f}s"
                        )

                    try:
                        uploader.upload_directory(
                            file_path,
                            target_handle=target_handle,
                            on_progress=on_dir_progress,
                            on_file_done=on_dir_file_done,
                            keep_going=keep_going,
                        )
                        if keep_going and uploader.last_directory_failures:
                            print_warn(
                                f"{len(uploader.last_directory_failures)} upload item(s) failed; "
                                "successful files were kept. See the log for details."
                            )
                    except MegaError as exc:
                        print_error(f"Upload failed: {exc}")
                    continue

                # Single file
                task_id = overall_progress.add_task(
                    description=f"Uploading: {file_path.name}",
                    total=file_path.stat().st_size,
                )

                def on_progress(p, t=task_id):
                    overall_progress.update(t, completed=p.bytes_done, total=p.total_bytes)

                try:
                    result = uploader.upload_file(
                        file_path,
                        target_handle=target_handle,
                        rename_to=rename if len(file_list) == 1 else None,
                        on_progress=on_progress,
                    )
                    overall_progress.update(
                        task_id,
                        description=f"Done: {result.name}",
                        completed=result.size,
                        total=result.size,
                    )
                    print_success(
                        f"{result.name} ({format_bytes(result.size)}) "
                        f"in {result.elapsed_seconds:.1f}s"
                    )
                    link_for_log: str | None = None
                    if auto_share:
                        try:
                            link_for_log = client.export_link(
                                result.file_handle,
                                password=share_password,
                            )
                            print_info(f"Share link: {link_for_log}")
                        except MegaError as exc:
                            print_error(f"Could not generate share link: {exc}")
                    from ..utils.hooks import append_upload_log, run_post_transfer_command

                    append_upload_log(
                        cfg.upload_log_path,
                        local_path=file_path,
                        file_handle=result.file_handle,
                        size=result.size,
                        elapsed_seconds=result.elapsed_seconds,
                        public_link=link_for_log,
                        account=client.session.email if client.session else None,
                    )
                    run_post_transfer_command(cfg.run_command, file_path)
                except MegaError as e:
                    print_error(f"Upload failed: {e}")
                except Exception as e:
                    log.exception("Unexpected error during upload")
                    print_error(f"Unexpected error: {e}")
    finally:
        if active_client is not None:
            active_client.logout()
