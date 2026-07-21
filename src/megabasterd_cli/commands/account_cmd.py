"""`mb account` - account management commands."""

from __future__ import annotations

import sys

import click

from ..accounts.manager import AccountManager, AccountNotFound
from ..accounts.storage import VaultUnlockError
from ..config import accounts_file
from ..core.client import MegaClient
from ..core.errors import MegaError
from ..ui.prompts import (
    ask_mfa_code,
    ask_password,
    confirm,
    print_error,
    print_info,
    print_success,
)
from ..ui.tables import render_accounts
from ..utils.redaction import redact_text
from .api_support import api_for


@click.group("account", short_help="Manage MEGA accounts.")
def account() -> None:
    """Add, remove, list, switch MEGA accounts."""


def _stdin_is_interactive() -> bool:
    """Whether a `getpass` prompt could actually be answered.

    `isatty()` alone is not enough on Windows: `NUL` is a CHARACTER DEVICE, so
    `mb account info < NUL` reports a tty, the prompt runs, and `msvcrt` waits
    on the console for a human who is not there. Only a real console has a
    console mode, so that is what is asked.
    """
    stream = getattr(sys, "stdin", None)
    if stream is None or not stream.isatty():
        return False
    if sys.platform != "win32":
        return True
    import ctypes

    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    mode = ctypes.c_ulong()
    handle = kernel32.GetStdHandle(-10)  # STD_INPUT_HANDLE
    return bool(kernel32.GetConsoleMode(handle, ctypes.byref(mode)))


def require_vault_passphrase(vault_passphrase: str | None, *, machine: bool = False) -> str:
    """The passphrase, or a clear failure - never an unanswerable prompt.

    `getpass` on Windows reads the console through `msvcrt`, so a closed or
    redirected stdin does NOT raise EOF: the process blocked forever with no
    output at all. Machine output (`--json`) is the same trap even on a TTY,
    because stdout is already redirected by the time the prompt appears.
    """
    if vault_passphrase:
        return vault_passphrase
    if machine or not _stdin_is_interactive():
        print_error("Vault passphrase required: pass --vault-passphrase.")
        click.get_current_context().exit(1)
    return ask_password("Vault passphrase")


def _open_manager(vault_passphrase: str | None, *, require_accounts: bool = True) -> AccountManager:
    """Unlock the vault, refusing before the prompt when it cannot succeed.

    Mirrors the guard `queue_cmd._manager` already had: an empty vault makes
    every caller but `account add` fail anyway, so asking for a passphrase
    first only adds a hang.
    """
    mgr = AccountManager(accounts_file())
    if require_accounts and not mgr.list_accounts():
        print_error("No accounts found. Use `mb account add` first.")
        click.get_current_context().exit(1)
    mgr.unlock(require_vault_passphrase(vault_passphrase))
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
        # Same trap as the vault passphrase (round-21): on Windows `getpass`
        # reads the console through `msvcrt`, so a redirected/closed stdin never
        # raises EOF and the process blocks forever, silent. Refuse before the
        # prompt when it could not be answered.
        if not _stdin_is_interactive():
            print_error("Account password required: pass --password.")
            ctx.exit(1)
        password = ask_password(f"Password for {email}")

    if verify:
        print_info("Verifying credentials...")
        client = MegaClient(api=api_for(cfg))
        try:
            client.login(email, password, mfa_code=mfa_code, mfa_prompt=ask_mfa_code)
        except MegaError as e:
            print_error(f"Login verification failed: {redact_text(str(e))}")
            if not confirm("Add account anyway?", default=False):
                return
        finally:
            # `logout()` used to sit inside the try after `login()`, so a
            # failed verification - or a KeyboardInterrupt at the 2FA prompt -
            # never released the session it had just opened.
            client.logout()

    # `add` is the one command that must work on an EMPTY vault.
    mgr = _open_manager(vault_passphrase, require_accounts=False)
    try:
        mgr.add_account(email, password, label=label, make_default=make_default)
        print_success(f"Account added: {email}")
    except VaultUnlockError as e:
        # A wrong passphrase would encrypt this account under a key the others
        # do not share; refusing keeps the vault openable by one passphrase.
        print_error(str(e))
        ctx.exit(1)
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
    except VaultUnlockError as e:
        print_error(str(e))
        ctx.exit(1)

    client = MegaClient(api=api_for(cfg))
    try:
        client.login(acc.email, password, mfa_code=mfa_code, mfa_prompt=ask_mfa_code)
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

        client = MegaClient(api=api_for(cfg))
        try:
            client.login(acc.email, password, mfa_code=mfa_code, mfa_prompt=ask_mfa_code)
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
