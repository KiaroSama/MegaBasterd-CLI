"""`mb share` — generate a public MEGA link from one of your files/folders."""

from __future__ import annotations

import click

from ..core.errors import MegaError
from ..ui.prompts import ask_password, print_error, print_success
from .cloud_cmd import login_client


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
    # `raises=False`: share reports failures and exits 0, where the cloud
    # commands abort with a UsageError. The helper releases the session on
    # every failing path, since the `finally` below is never reached.
    client = login_client(
        ctx,
        vault_passphrase,
        account,
        mfa_code,
        ask_passphrase=ask_password,
        raises=False,
    )
    if client is None:
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
