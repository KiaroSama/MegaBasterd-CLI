"""`mb account` - account management commands."""

from __future__ import annotations

import click

from ..accounts.manager import AccountManager, AccountNotFound
from ..config import Config, accounts_file
from ..core.api import MegaAPIClient
from ..core.client import MegaClient
from ..core.errors import MegaError
from ..proxy.runtime import effective_pool
from ..ui.prompts import ask, ask_password, confirm, print_error, print_info, print_success
from ..ui.tables import render_accounts
from ..utils.redaction import redact_text


def _mfa_prompt() -> str:
    return ask("Enter 6-digit 2FA code").strip()


def _api_for(cfg: Config) -> MegaAPIClient:
    """Build a MegaAPIClient that honours the user's smart-proxy settings."""
    return MegaAPIClient(
        timeout=cfg.timeout_seconds,
        proxy_pool=effective_pool(cfg),
        force_proxy=cfg.force_smart_proxy,
    )


@click.group("account", short_help="Manage MEGA accounts.")
def account() -> None:
    """Add, remove, list, switch MEGA accounts."""


def _open_manager(vault_passphrase: str | None) -> AccountManager:
    mgr = AccountManager(accounts_file())
    passphrase = vault_passphrase or ask_password("Vault passphrase")
    mgr.unlock(passphrase)
    return mgr


@account.command("list", short_help="List stored accounts.")
def account_list() -> None:
    mgr = AccountManager(accounts_file())
    render_accounts(mgr.list_accounts(), mgr.store.default_email)


@account.command("add", short_help="Add a new account.")
@click.argument("email")
@click.option("--password", "password", default=None, help="Account password (prompt if omitted).")
@click.option("--label", default=None, help="Friendly label.")
@click.option("--default", "make_default", is_flag=True, help="Make this the default account.")
@click.option(
    "--vault-passphrase", default=None, help="Vault passphrase for credential encryption."
)
@click.option("--verify/--no-verify", default=True, help="Verify by logging in once.")
@click.option("--mfa-code", default=None, help="2FA code if the account requires it.")
@click.pass_context
def account_add(
    ctx: click.Context,
    email: str,
    password: str | None,
    label: str | None,
    make_default: bool,
    vault_passphrase: str | None,
    verify: bool,
    mfa_code: str | None,
) -> None:
    cfg = ctx.obj["config"]
    if password is None:
        password = ask_password(f"Password for {email}")

    if verify:
        print_info("Verifying credentials...")
        client = MegaClient(api=_api_for(cfg))
        try:
            client.login(email, password, mfa_code=mfa_code, mfa_prompt=_mfa_prompt)
        except MegaError as e:
            print_error(f"Login verification failed: {redact_text(str(e))}")
            if not confirm("Add account anyway?", default=False):
                return
        finally:
            # `logout()` used to sit inside the try after `login()`, so a
            # failed verification - or a KeyboardInterrupt at the 2FA prompt -
            # never released the session it had just opened.
            client.logout()

    mgr = _open_manager(vault_passphrase)
    try:
        mgr.add_account(email, password, label=label, make_default=make_default)
        print_success(f"Account added: {email}")
    except ValueError as e:
        print_error(str(e))


@account.command("remove", short_help="Remove an account.")
@click.argument("email_or_label")
def account_remove(email_or_label: str) -> None:
    mgr = AccountManager(accounts_file())
    try:
        if not confirm(f"Really remove {email_or_label}?", default=False):
            return
        mgr.remove_account(email_or_label)
        print_success(f"Removed: {email_or_label}")
    except AccountNotFound:
        print_error(f"Account not found: {email_or_label}")


@account.command("default", short_help="Set the default account.")
@click.argument("email_or_label")
def account_default(email_or_label: str) -> None:
    mgr = AccountManager(accounts_file())
    try:
        mgr.set_default(email_or_label)
        print_success(f"Default account: {email_or_label}")
    except AccountNotFound:
        print_error(f"Account not found: {email_or_label}")


@account.command("info", short_help="Show quota for an account.")
@click.argument("email_or_label", required=False)
@click.option("--vault-passphrase", default=None)
@click.option("--mfa-code", default=None)
@click.pass_context
def account_info(
    ctx: click.Context,
    email_or_label: str | None,
    vault_passphrase: str | None,
    mfa_code: str | None,
) -> None:
    cfg = ctx.obj["config"]
    mgr = _open_manager(vault_passphrase)
    email = email_or_label or mgr.store.default_email
    if not email:
        print_error("No account specified.")
        return
    try:
        acc = mgr.get_account(email)
        password = mgr.get_password(email)
    except AccountNotFound:
        print_error(f"Account not found: {email}")
        return

    client = MegaClient(api=_api_for(cfg))
    try:
        client.login(acc.email, password, mfa_code=mfa_code, mfa_prompt=_mfa_prompt)
        quota = client.get_quota()
    except MegaError as e:
        print_error(f"Could not fetch quota: {redact_text(str(e))}")
        return
    finally:
        # logout() invalidates the session; close() releases the HTTP session
        # itself. Without the close, every refresh leaked a connection pool.
        client.logout()
        client.api.close()

    used = quota.get("cstrg", 0)
    total = quota.get("mstrg", 0)
    mgr.update_quota(acc.email, used, total)
    render_accounts([mgr.get_account(acc.email)], mgr.store.default_email)


@account.command("refresh-all", short_help="Update quota for every stored account.")
@click.option("--vault-passphrase", default=None)
@click.option("--mfa-code", default=None)
@click.pass_context
def account_refresh_all(
    ctx: click.Context,
    vault_passphrase: str | None,
    mfa_code: str | None,
) -> None:
    """Login to every stored account in turn and refresh its cached quota."""
    cfg = ctx.obj["config"]
    mgr = _open_manager(vault_passphrase)
    for acc in mgr.list_accounts():
        try:
            password = mgr.get_password(acc.email)
        except Exception as exc:  # noqa: BLE001
            print_error(f"{acc.email}: vault decrypt failed ({exc})")
            continue

        client = MegaClient(api=_api_for(cfg))
        try:
            client.login(acc.email, password, mfa_code=mfa_code, mfa_prompt=_mfa_prompt)
            quota = client.get_quota()
            mgr.update_quota(acc.email, quota.get("cstrg", 0), quota.get("mstrg", 0))
            print_success(f"{acc.email}: refreshed")
        except MegaError as e:
            print_error(f"{acc.email}: {redact_text(str(e))}")
        finally:
            # One HTTP session per account was leaked here before the close().
            client.logout()
            client.api.close()

    render_accounts(mgr.list_accounts(), mgr.store.default_email)
