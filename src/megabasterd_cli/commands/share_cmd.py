"""`mb share` — generate a public MEGA link from one of your files/folders."""

from __future__ import annotations

import click

from ..accounts.manager import AccountManager, AccountNotFound
from ..config import accounts_file
from ..core.api import MegaAPIClient
from ..core.client import MegaClient
from ..core.errors import MegaError
from ..ui.prompts import ask, ask_password, print_error, print_success


def _mfa_prompt() -> str:
    return ask("Enter 6-digit 2FA code").strip()


@click.command("share", short_help="Create a public MEGA link for one of your nodes.")
@click.argument("target")
@click.option(
    "--password",
    default=None,
    help="Encrypt the link with a password (creates a #P! link).",
)
@click.option(
    "--remove",
    is_flag=True,
    help="Remove the public link instead of creating one.",
)
@click.option("-a", "--account", default=None)
@click.option("--vault-passphrase", default=None)
@click.option("--mfa-code", default=None, help="2FA code if your account requires it.")
@click.pass_context
def share_cmd(
    ctx: click.Context,
    target: str,
    password: str | None,
    remove: bool,
    account: str | None,
    vault_passphrase: str | None,
    mfa_code: str | None,
) -> None:
    """Make TARGET (handle or path) publicly accessible by URL."""
    cfg = ctx.obj["config"]
    account_id = account or cfg.default_account
    if not account_id:
        print_error("No account specified.")
        return

    mgr = AccountManager(accounts_file())
    passphrase = vault_passphrase or ask_password("Vault passphrase")
    mgr.unlock(passphrase)
    try:
        acc = mgr.get_account(account_id)
        pwd = mgr.get_password(account_id)
    except AccountNotFound:
        print_error(f"Account not found: {account_id}")
        return

    from ..proxy.runtime import effective_pool

    proxy_pool = effective_pool(cfg)
    api = MegaAPIClient(
        timeout=cfg.timeout_seconds,
        proxy_pool=proxy_pool,
        force_proxy=cfg.force_smart_proxy,
    )
    client = MegaClient(api=api)
    try:
        client.login(acc.email, pwd, mfa_code=mfa_code, mfa_prompt=_mfa_prompt)
    except MegaError as exc:
        print_error(f"Login failed: {exc}")
        return

    try:
        node = client.find_node(handle=target) or client.find_node(path=target)
        if not node:
            print_error(f"Not found: {target}")
            return
        if remove:
            client.remove_export(node.handle)
            print_success(f"Public link removed for {node.name or node.handle}")
            return

        url = client.export_link(node.handle, password=password)
        print_success(f"{node.name or node.handle}:")
        click.echo(url)
    except MegaError as exc:
        print_error(f"share failed: {exc}")
    finally:
        client.logout()
