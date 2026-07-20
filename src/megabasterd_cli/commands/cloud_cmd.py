"""`mb ls / mkdir / rm / mv / rename / search / import / trash` — cloud operations."""

from __future__ import annotations

import logging

import click

from ..accounts.manager import AccountManager, AccountNotFound
from ..config import accounts_file
from ..core.api import MegaAPIClient
from ..core.client import MegaClient, MegaNode
from ..core.errors import MegaError
from ..core.links import LinkType, parse_link
from ..ui.prompts import (
    ask_mfa_code,
    ask_password,
    confirm,
    print_error,
    print_info,
    print_success,
)
from ..ui.theme import SafeTable, make_console
from ..utils.helpers import format_bytes

log = logging.getLogger(__name__)
_console = make_console()


def _client(
    ctx: click.Context,
    vault_passphrase: str | None,
    account: str | None,
    mfa_code: str | None = None,
) -> MegaClient:
    """Helper: unlock vault, resolve account, log in, return a ready MegaClient."""
    from ..accounts.manager import resolve_account_id

    cfg = ctx.obj["config"]
    mgr = AccountManager(accounts_file())
    account_id = resolve_account_id(mgr, cfg.default_account, account)
    if not account_id:
        raise click.UsageError(
            "No account specified and no default set. Use --account or set config."
        )

    passphrase = vault_passphrase or ask_password("Vault passphrase")
    mgr.unlock(passphrase)
    try:
        acc = mgr.get_account(account_id)
        password = mgr.get_password(account_id)
    except AccountNotFound as exc:
        raise click.UsageError(f"Account not found: {account_id}") from exc

    from ..proxy.runtime import effective_pool

    proxy_pool = effective_pool(cfg)
    api = MegaAPIClient(
        timeout=cfg.timeout_seconds,
        proxy_pool=proxy_pool,
        force_proxy=cfg.force_smart_proxy,
    )
    client = MegaClient(api=api)
    try:
        client.login(acc.email, password, mfa_code=mfa_code, mfa_prompt=ask_mfa_code)
    except BaseException:
        # The caller only gets a client it can close if login succeeded, so
        # a failure here has to release the session it just opened.
        api.close()
        raise
    return client


# ---------------------------------------------------------------------------
# `mb ls`
# ---------------------------------------------------------------------------


def _render_nodes(nodes: list[MegaNode], parent_filter: str | None = None) -> None:
    """Render a list of nodes as a Rich table."""
    if parent_filter:
        nodes = [n for n in nodes if n.parent == parent_filter]
    if not nodes:
        _console.print("[mb.dim]No items[/mb.dim]")
        return

    table = SafeTable(
        show_header=True,
        header_style="mb.table.header",
        border_style="mb.table.border",
    )
    table.add_column("Handle", style="mb.dim")
    table.add_column("Type", width=6, style="mb.option")
    table.add_column("Name")
    table.add_column("Size", justify="right", style="mb.value")
    for n in sorted(nodes, key=lambda x: (x.node_type != 1, (x.name or ""))):
        if n.is_root or n.is_trash or n.is_inbox:
            continue
        kind = "DIR" if n.is_folder else "FILE"
        size = format_bytes(n.size) if n.is_file else "-"
        table.add_row(n.handle, kind, n.name or "?", size)
    _console.print(table)


@click.command("ls", short_help="List files in your MEGA cloud.")
@click.argument("path", required=False, default="")
@click.option("-a", "--account", default=None)
@click.option("--vault-passphrase", default=None)
@click.option("--mfa-code", default=None, help="2FA code if your account requires it.")
@click.option("--all", "show_all", is_flag=True, help="Show the entire tree.")
@click.pass_context
def ls_cmd(
    ctx: click.Context,
    path: str,
    account: str | None,
    vault_passphrase: str | None,
    mfa_code: str | None,
    show_all: bool,
) -> None:
    """List your remote files. PATH is a slash-separated path under the root."""
    try:
        client = _client(ctx, vault_passphrase, account, mfa_code)
    except MegaError as exc:
        print_error(f"Login failed: {exc}")
        return

    try:
        nodes = client.list_files()
        if show_all:
            _render_nodes(nodes)
        elif path:
            node = client.find_node(path=path)
            if not node or not node.is_folder:
                print_error(f"Folder not found: {path}")
                return
            _render_nodes(nodes, parent_filter=node.handle)
        else:
            root = client.find_root()
            _render_nodes(nodes, parent_filter=root)
    finally:
        client.logout()


# ---------------------------------------------------------------------------
# `mb mkdir`
# ---------------------------------------------------------------------------


@click.command("mkdir", short_help="Create a remote folder.")
@click.argument("name")
@click.option("--parent", default=None, help="Parent folder handle or path.")
@click.option("-a", "--account", default=None)
@click.option("--vault-passphrase", default=None)
@click.option("--mfa-code", default=None, help="2FA code if your account requires it.")
@click.pass_context
def mkdir_cmd(
    ctx: click.Context,
    name: str,
    parent: str | None,
    account: str | None,
    vault_passphrase: str | None,
    mfa_code: str | None,
) -> None:
    """Create a folder called NAME (under --parent if given, else under root)."""
    try:
        client = _client(ctx, vault_passphrase, account, mfa_code)
    except MegaError as exc:
        print_error(f"Login failed: {exc}")
        return
    try:
        parent_handle = None
        if parent:
            node = client.find_node(handle=parent) or client.find_node(path=parent)
            if not node or not node.is_folder:
                print_error(f"Parent not found: {parent}")
                return
            parent_handle = node.handle
        handle = client.mkdir(name, parent_handle=parent_handle)
        print_success(f"Created folder {name!r} (handle {handle})")
    except MegaError as exc:
        print_error(f"mkdir failed: {exc}")
    finally:
        client.logout()


# ---------------------------------------------------------------------------
# `mb rm`
# ---------------------------------------------------------------------------


@click.command("rm", short_help="Delete a file or folder (moves to trash).")
@click.argument("target")
@click.option("-a", "--account", default=None)
@click.option("--vault-passphrase", default=None)
@click.option("--mfa-code", default=None, help="2FA code if your account requires it.")
@click.option("--yes", is_flag=True, help="Skip confirmation.")
@click.pass_context
def rm_cmd(
    ctx: click.Context,
    target: str,
    account: str | None,
    vault_passphrase: str | None,
    mfa_code: str | None,
    yes: bool,
) -> None:
    """Move a node into the trash by handle or path."""
    try:
        client = _client(ctx, vault_passphrase, account, mfa_code)
    except MegaError as exc:
        print_error(f"Login failed: {exc}")
        return
    try:
        node = client.find_node(handle=target) or client.find_node(path=target)
        if not node:
            print_error(f"Not found: {target}")
            return
        label = node.name or node.handle
        if not yes and not confirm(f"Move {label!r} to trash?", default=False):
            return
        client.delete(node.handle)
        print_success(f"Deleted {label}")
    except MegaError as exc:
        print_error(f"rm failed: {exc}")
    finally:
        client.logout()


# ---------------------------------------------------------------------------
# `mb mv`
# ---------------------------------------------------------------------------


@click.command("mv", short_help="Move a node to a different folder.")
@click.argument("source")
@click.argument("destination")
@click.option("-a", "--account", default=None)
@click.option("--vault-passphrase", default=None)
@click.option("--mfa-code", default=None, help="2FA code if your account requires it.")
@click.pass_context
def mv_cmd(
    ctx: click.Context,
    source: str,
    destination: str,
    account: str | None,
    vault_passphrase: str | None,
    mfa_code: str | None,
) -> None:
    """Move SOURCE node to DESTINATION folder (handles or paths)."""
    try:
        client = _client(ctx, vault_passphrase, account, mfa_code)
    except MegaError as exc:
        print_error(f"Login failed: {exc}")
        return
    try:
        src = client.find_node(handle=source) or client.find_node(path=source)
        dst = client.find_node(handle=destination) or client.find_node(path=destination)
        if not src or not dst:
            print_error("Source or destination not found.")
            return
        if not dst.is_folder:
            print_error("Destination must be a folder.")
            return
        client.move(src.handle, dst.handle)
        print_success(f"Moved {src.name or src.handle} -> {dst.name or dst.handle}")
    except MegaError as exc:
        print_error(f"mv failed: {exc}")
    finally:
        client.logout()


# ---------------------------------------------------------------------------
# `mb rename`
# ---------------------------------------------------------------------------


@click.command("rename", short_help="Rename a remote node.")
@click.argument("target")
@click.argument("new_name")
@click.option("-a", "--account", default=None)
@click.option("--vault-passphrase", default=None)
@click.option("--mfa-code", default=None, help="2FA code if your account requires it.")
@click.pass_context
def rename_cmd(
    ctx: click.Context,
    target: str,
    new_name: str,
    account: str | None,
    vault_passphrase: str | None,
    mfa_code: str | None,
) -> None:
    try:
        client = _client(ctx, vault_passphrase, account, mfa_code)
    except MegaError as exc:
        print_error(f"Login failed: {exc}")
        return
    try:
        node = client.find_node(handle=target) or client.find_node(path=target)
        if not node:
            print_error(f"Not found: {target}")
            return
        client.rename(node.handle, new_name)
        print_success(f"Renamed {node.name!r} -> {new_name!r}")
    except MegaError as exc:
        print_error(f"rename failed: {exc}")
    finally:
        client.logout()


# ---------------------------------------------------------------------------
# `mb search`
# ---------------------------------------------------------------------------


@click.command("search", short_help="Search your cloud by filename.")
@click.argument("pattern")
@click.option("--regex", is_flag=True, help="Treat pattern as a regex.")
@click.option("-a", "--account", default=None)
@click.option("--vault-passphrase", default=None)
@click.option("--mfa-code", default=None, help="2FA code if your account requires it.")
@click.pass_context
def search_cmd(
    ctx: click.Context,
    pattern: str,
    regex: bool,
    account: str | None,
    vault_passphrase: str | None,
    mfa_code: str | None,
) -> None:
    try:
        client = _client(ctx, vault_passphrase, account, mfa_code)
    except MegaError as exc:
        print_error(f"Login failed: {exc}")
        return
    try:
        matches = client.search(pattern, regex=regex)
        _render_nodes(matches)
    finally:
        client.logout()


# ---------------------------------------------------------------------------
# `mb trash empty`
# ---------------------------------------------------------------------------


@click.group("trash", short_help="Trash operations.")
def trash_cmd() -> None:
    """Inspect or empty the trash."""


@trash_cmd.command("list", short_help="List files in trash.")
@click.option("-a", "--account", default=None)
@click.option("--vault-passphrase", default=None)
@click.option("--mfa-code", default=None, help="2FA code if your account requires it.")
@click.pass_context
def trash_list(
    ctx: click.Context,
    account: str | None,
    vault_passphrase: str | None,
    mfa_code: str | None,
) -> None:
    try:
        client = _client(ctx, vault_passphrase, account, mfa_code)
    except MegaError as exc:
        print_error(f"Login failed: {exc}")
        return
    try:
        trash = client.find_trash()
        if not trash:
            print_info("No trash node.")
            return
        _render_nodes(client.list_files(), parent_filter=trash)
    finally:
        client.logout()


@trash_cmd.command("empty", short_help="Permanently delete every trashed item.")
@click.option("-a", "--account", default=None)
@click.option("--vault-passphrase", default=None)
@click.option("--mfa-code", default=None, help="2FA code if your account requires it.")
@click.option("--yes", is_flag=True)
@click.pass_context
def trash_empty(
    ctx: click.Context,
    account: str | None,
    vault_passphrase: str | None,
    mfa_code: str | None,
    yes: bool,
) -> None:
    try:
        client = _client(ctx, vault_passphrase, account, mfa_code)
    except MegaError as exc:
        print_error(f"Login failed: {exc}")
        return
    try:
        if not yes and not confirm("Permanently empty the trash?", default=False):
            return
        client.empty_trash()
        print_success("Trash emptied.")
    finally:
        client.logout()


# ---------------------------------------------------------------------------
# `mb import` — copy a public folder share into the user's tree
# ---------------------------------------------------------------------------


@click.command("import", short_help="Import a public folder share into your account.")
@click.argument("share_url")
@click.option("--target", default=None, help="Destination folder handle or path (default: root).")
@click.option("-a", "--account", default=None)
@click.option("--vault-passphrase", default=None)
@click.option("--mfa-code", default=None, help="2FA code if your account requires it.")
@click.pass_context
def import_cmd(
    ctx: click.Context,
    share_url: str,
    target: str | None,
    account: str | None,
    vault_passphrase: str | None,
    mfa_code: str | None,
) -> None:
    """Copy every node in a public folder share into your own MEGA tree."""
    try:
        parsed = parse_link(share_url)
    except ValueError as exc:
        print_error(str(exc))
        return
    if parsed.type not in (LinkType.FOLDER, LinkType.FOLDER_IN_FOLDER):
        print_error("Only folder shares can be imported.")
        return
    try:
        client = _client(ctx, vault_passphrase, account, mfa_code)
    except MegaError as exc:
        print_error(f"Login failed: {exc}")
        return
    try:
        target_parent = None
        if target:
            node = client.find_node(handle=target) or client.find_node(path=target)
            if not node or not node.is_folder:
                print_error(f"Target folder not found: {target}")
                return
            target_parent = node.handle
        handles = client.import_public_share(share_url, target_parent=target_parent)
        print_success(f"Imported {len(handles)} node(s).")
    except MegaError as exc:
        print_error(f"Import failed: {exc}")
    finally:
        client.logout()
