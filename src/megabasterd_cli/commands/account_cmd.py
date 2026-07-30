"""`mb account` - account management commands."""

from __future__ import annotations

import sys

import click

from ..accounts.manager import AccountManager, AccountNotFound
from ..accounts.storage import VaultUnlockError
from ..config import accounts_file
from ..core.client import MegaClient
from ..core.errors import MegaError
from ..core.session_store import remember_session, restore_session
from ..ui.prompts import (
    ask_mfa_code,
    ask_password,
    confirmed,
    print_error,
    print_info,
    print_success,
    print_warn,
)
from ..ui.tables import render_accounts
from ..utils.redaction import redact_text
from .api_support import api_for, mfa_code_option, vault_passphrase_option


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


def _open_manager(
    vault_passphrase: str | None, *, require_accounts: bool = True
) -> tuple[AccountManager, str]:
    """Unlock the vault, refusing before the prompt when it cannot succeed.

    Mirrors the guard `queue_cmd._manager` already had: an empty vault makes
    every caller but `account add` fail anyway, so asking for a passphrase
    first only adds a hang - which is why the passphrase is resolved HERE and
    handed back rather than by the caller. The session cache is keyed on it,
    so a caller that needs it must not re-prompt or reorder those two steps.
    """
    mgr = AccountManager(accounts_file())
    if require_accounts and not mgr.list_accounts():
        print_error("No accounts found. Use `mb account add` first.")
        click.get_current_context().exit(1)
    passphrase = require_vault_passphrase(vault_passphrase)
    mgr.unlock(passphrase)
    return mgr, passphrase


@account.command("list", short_help="List stored accounts.")
def account_list() -> None:
    mgr = AccountManager(accounts_file())
    render_accounts(mgr.list_accounts(), mgr.store.default_email)


@account.command("add", short_help="Add a new account.")
@click.argument("email")
@click.option("--password", "password", default=None, help="Account password (prompt if omitted).")
@click.option("--label", default=None, help="Friendly label.")
@click.option("--default", "make_default", is_flag=True, help="Make this the default account.")
@vault_passphrase_option()
@click.option("--verify/--no-verify", default=True, help="Verify by logging in once.")
@mfa_code_option()
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

    verified: MegaClient | None = None
    if verify:
        print_info("Verifying credentials...")
        client = MegaClient(api=api_for(cfg))
        try:
            client.login(email, password, mfa_code=mfa_code, mfa_prompt=ask_mfa_code)
            verified = client
        except MegaError as e:
            print_error(f"Login verification failed: {redact_text(str(e))}")
            # `logout()` used to sit inside the try after `login()`, so a failed
            # verification - or a KeyboardInterrupt at the 2FA prompt - never
            # released the session it had just opened.
            client.logout()
            if not confirmed("Add account anyway?"):
                return
        except BaseException:
            client.logout()
            raise

    # `add` is the one command that must work on an EMPTY vault.
    mgr, passphrase = _open_manager(vault_passphrase, require_accounts=False)
    stored = False
    duplicate = False
    try:
        try:
            mgr.add_account(email, password, label=label, make_default=make_default)
            print_success(f"Account added: {email}")
            stored = True
        except VaultUnlockError as e:
            # A wrong passphrase would encrypt this account under a key the
            # others do not share; refusing keeps the vault openable by one
            # passphrase. Nothing is cached under a passphrase we just refused.
            print_error(str(e))
            ctx.exit(1)
        except ValueError as e:
            # Duplicate, or an invalid field. The vault is untouched either way.
            duplicate = "already exists" in str(e)
            if not duplicate:
                print_error(str(e))

        # Cache the session whether or not a NEW row was written. Verification
        # is the one moment the user has proven they hold the account, spending
        # a 2FA code to do it - and this used to sit after `add_account`, so
        # re-running `account add` for an account that already existed threw
        # that session away and the code was spent for nothing. The passphrase
        # is known to open the vault by now, which is what the cache is keyed
        # on, so storing it is correct in both cases.
        if verified is not None:
            from ..core.session_store import remember_session

            remember_session(verified, email, passphrase)
    finally:
        if verified is not None:
            # `close()`, not `logout()`: the session is cached for reuse now, so
            # ending it server-side would make the cache dead on arrival - the
            # same mistake the cloud commands were making.
            verified.close()

    if stored:
        return
    if duplicate and verified is not None:
        # Re-running the login for an account already in the vault is the
        # normal way to refresh an expired session, so reporting a red
        # "Account already exists" and exit 1 described the one thing that did
        # NOT happen. Nothing was added, but the login succeeded and the
        # session is cached - which is what the user came here for.
        print_success(f"Signed in: {email} (already stored; session refreshed)")
        return
    if duplicate:
        # No verification, so genuinely nothing happened.
        print_error(
            f"Account already exists: {email}. Drop --no-verify to sign in and "
            "refresh its session."
        )
    # `print_error` then falling through reported "Command completed
    # successfully" in the launcher for a command that changed nothing.
    ctx.exit(1)


@account.command("remove", short_help="Remove an account.")
@click.argument("email_or_label")
def account_remove(email_or_label: str) -> None:
    mgr = AccountManager(accounts_file())
    try:
        if not confirmed(f"Really remove {email_or_label}?"):
            return
        account = mgr.get_account(email_or_label)
        mgr.remove_account(email_or_label)
        # Drop the cached session too. Leaving it behind kept a token that
        # MEGA still honours until it expires, for an account the user has
        # just been told was removed - and no command can reach it any more to
        # log it out.
        from ..core.session_store import forget_session

        for key in {email_or_label, account.email, account.label or account.email}:
            forget_session(key)
        print_success(f"Removed: {email_or_label}")
    except AccountNotFound:
        print_error(f"Account not found: {email_or_label}")


@account.command("logout", short_help="End a stored MEGA session.")
@click.argument("email_or_label", required=False)
@click.option("--all", "all_accounts", is_flag=True, help="Log out every stored account.")
@vault_passphrase_option()
@click.pass_context
def account_logout(
    ctx: click.Context,
    email_or_label: str | None,
    all_accounts: bool,
    vault_passphrase: str | None,
) -> None:
    """Invalidate the session MEGA is holding and drop the local cache.

    Logging in caches an encrypted session so later commands do not have to
    re-authenticate (and re-prompt for 2FA). That session stays valid until
    something ends it, and nothing did: there was no way to close it short of
    waiting for MEGA to expire it.

    Both halves are needed. Deleting the file alone leaves a token MEGA still
    honours; calling logout alone leaves a dead file the next run has to probe
    and discard.
    """
    from ..core.session_store import forget_session, session_path

    cfg = ctx.obj["config"]
    mgr = AccountManager(accounts_file())
    if all_accounts:
        targets = [a.email for a in mgr.list_accounts()]
    elif email_or_label:
        targets = [email_or_label]
    else:
        from ..accounts.manager import resolve_account_id

        target = resolve_account_id(mgr, cfg.default_account)
        if not target:
            print_error("No account specified and no default set.")
            ctx.exit(1)
        targets = [target]

    cached = [t for t in targets if session_path(t).is_file()]
    if not cached:
        # Say what was NOT done, and name the command that does it. "No stored
        # session to end." alone reads as "nothing happened, and I do not know
        # why" - someone expecting the account to disappear then checks the
        # list, finds it there, and concludes logout is broken.
        print_info(
            "No stored session to end. The account and its stored credential are "
            "untouched; `mb account remove` deletes those."
        )
        return

    passphrase = vault_passphrase or ask_password("Vault passphrase")
    ended = 0
    for target in cached:
        client = MegaClient(api=api_for(cfg))
        try:
            session = client.load_session(session_path(target), passphrase)
            if session is None:
                # Unreadable under this passphrase: the token cannot be used
                # to log itself out, so the file is all we can clear. Say so
                # rather than reporting a logout that did not happen.
                forget_session(target)
                print_warn(f"{target}: cached session could not be read; file removed only.")
                continue
            client.session = session
            client.api.set_session(session.sid)
            client.logout()  # `{"a":"sml"}`, then releases the transport
            forget_session(target)
            ended += 1
        except MegaError as exc:
            # The server-side call is best effort; the local file is not.
            forget_session(target)
            print_warn(f"{target}: {redact_text(str(exc))}; cached session removed.")
        finally:
            client.api.close()
    if ended:
        print_success(f"Logged out {ended} account(s).")


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
@vault_passphrase_option()
@mfa_code_option()
@click.pass_context
def account_info(
    ctx: click.Context,
    email_or_label: str | None,
    vault_passphrase: str | None,
    mfa_code: str | None,
) -> None:
    cfg = ctx.obj["config"]
    mgr, passphrase = _open_manager(vault_passphrase)
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
        # Reuse the cached session: asking for a 2FA code just to read a quota
        # is the sort of thing that made every command feel like a fresh login.
        if not restore_session(client, acc.email, passphrase):
            client.login(acc.email, password, mfa_code=mfa_code, mfa_prompt=ask_mfa_code)
            remember_session(client, acc.email, passphrase)
        quota = client.get_quota()
    except MegaError as e:
        print_error(f"Could not fetch quota: {redact_text(str(e))}")
        return
    finally:
        # `close()`, not `logout()`: `logout()` sends `{"a":"sml"}` and
        # invalidates the cached session, so the next command re-authenticates
        # and re-prompts for 2FA. Ending it on purpose is `mb account logout`.
        client.close()

    used = quota.get("cstrg", 0)
    total = quota.get("mstrg", 0)
    mgr.update_quota(acc.email, used, total)
    render_accounts([mgr.get_account(acc.email)], mgr.store.default_email)


@account.command("refresh-all", short_help="Update quota for every stored account.")
@vault_passphrase_option()
@mfa_code_option()
@click.pass_context
def account_refresh_all(
    ctx: click.Context,
    vault_passphrase: str | None,
    mfa_code: str | None,
) -> None:
    """Login to every stored account in turn and refresh its cached quota."""
    cfg = ctx.obj["config"]
    mgr, passphrase = _open_manager(vault_passphrase)
    for acc in mgr.list_accounts():
        try:
            password = mgr.get_password(acc.email)
        except Exception as exc:  # noqa: BLE001
            print_error(f"{acc.email}: vault decrypt failed ({exc})")
            continue

        client = MegaClient(api=api_for(cfg))
        try:
            # Per account, and this command exists to touch every one of them -
            # a fresh login each time meant one 2FA prompt per stored account.
            if not restore_session(client, acc.email, passphrase):
                client.login(acc.email, password, mfa_code=mfa_code, mfa_prompt=ask_mfa_code)
                remember_session(client, acc.email, passphrase)
            quota = client.get_quota()
            mgr.update_quota(acc.email, quota.get("cstrg", 0), quota.get("mstrg", 0))
            print_success(f"{acc.email}: refreshed")
        except MegaError as e:
            print_error(f"{acc.email}: {redact_text(str(e))}")
        finally:
            # Per account, so this was invalidating every cached session in the
            # vault in one command. `close()` releases the transport and leaves
            # the sessions alone.
            client.close()

    render_accounts(mgr.list_accounts(), mgr.store.default_email)
