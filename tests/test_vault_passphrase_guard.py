"""`account add` must not mix the vault or hang on a missing password.

Two defects that only bite `account add`, the one mutating command that runs on
an empty vault and prompts for a *second* secret (the account password):

* BUG A - `AccountManager.unlock()` never decrypts anything, so `add_account`
  happily encrypts the new password with a *typo'd* passphrase and appends it
  next to accounts encrypted under a different one. No single passphrase then
  opens them all - the vault is corrupted.
* BUG B - the account-password prompt used an unguarded `getpass`. On Windows
  `getpass` reads the console through `msvcrt`, so a redirected/closed stdin
  does NOT raise EOF: the process blocks forever, silent. Round-21 guarded the
  VAULT passphrase this way but not the ACCOUNT password.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from megabasterd_cli.accounts.manager import AccountManager
from megabasterd_cli.accounts.storage import VaultUnlockError
from megabasterd_cli.cli import cli
from megabasterd_cli.commands import account_cmd as account_module
from megabasterd_cli.config import accounts_file

PASSPHRASE = "right-passphrase"
WRONG_PASSPHRASE = "wrong-passphrase"


@pytest.fixture()
def cli_env(tmp_path, monkeypatch):
    monkeypatch.setenv("MEGABASTERD_USER_DIR", str(tmp_path / "user"))
    monkeypatch.setenv("MEGABASTERD_LOG_DIR", str(tmp_path / "logs"))
    return tmp_path


@pytest.fixture()
def no_prompt(monkeypatch):
    """Any account-password prompt reached here would hang a real headless run."""
    asked: list[str] = []

    def fail(question: str = "Password") -> str:
        asked.append(question)
        raise AssertionError(f"interactive prompt reached: {question}")

    monkeypatch.setattr(account_module, "ask_password", fail)
    return asked


@pytest.fixture()
def stored_account(cli_env):
    mgr = AccountManager(accounts_file())
    mgr.unlock(PASSPHRASE)
    mgr.add_account("a@example.com", "account-password", make_default=True)
    return cli_env


def _run(*args, **kwargs):
    return CliRunner().invoke(cli, list(args), **kwargs)


def _assert_no_traceback(result) -> None:
    """A deliberate `ctx.exit()` surfaces as SystemExit; anything else leaked."""
    assert result.exception is None or isinstance(
        result.exception, SystemExit
    ), f"raised {result.exception!r}"


# ---------------------------------------------------------------------------
# BUG A - a wrong passphrase must not mix the vault
# ---------------------------------------------------------------------------


def test_add_with_wrong_passphrase_is_refused(stored_account):
    """The core data-integrity guard, at the manager level."""
    mgr = AccountManager(accounts_file())
    mgr.unlock(WRONG_PASSPHRASE)
    with pytest.raises(VaultUnlockError) as excinfo:
        mgr.add_account("b@example.com", "second-password")
    assert WRONG_PASSPHRASE not in str(excinfo.value)


def test_refused_add_leaves_the_vault_intact(stored_account):
    """Nothing was appended and the original still decrypts under its passphrase."""
    mgr = AccountManager(accounts_file())
    mgr.unlock(WRONG_PASSPHRASE)
    with pytest.raises(VaultUnlockError):
        mgr.add_account("b@example.com", "second-password")

    fresh = AccountManager(accounts_file())
    fresh.unlock(PASSPHRASE)
    assert [a.email for a in fresh.list_accounts()] == ["a@example.com"]
    assert fresh.get_password("a@example.com") == "account-password"


def test_cli_add_with_wrong_passphrase_exits_nonzero(stored_account, no_prompt):
    result = _run(
        "account",
        "add",
        "b@example.com",
        "--password",
        "second-password",
        "--no-verify",
        "--vault-passphrase",
        WRONG_PASSPHRASE,
    )
    _assert_no_traceback(result)
    assert result.exit_code == 1
    assert "passphrase" in result.output.lower()
    assert WRONG_PASSPHRASE not in result.output
    assert [a.email for a in AccountManager(accounts_file()).list_accounts()] == ["a@example.com"]


def test_add_with_the_right_passphrase_still_works(stored_account, no_prompt):
    result = _run(
        "account",
        "add",
        "b@example.com",
        "--password",
        "second-password",
        "--no-verify",
        "--vault-passphrase",
        PASSPHRASE,
    )
    assert result.exit_code == 0, result.output
    mgr = AccountManager(accounts_file())
    mgr.unlock(PASSPHRASE)
    assert {a.email for a in mgr.list_accounts()} == {"a@example.com", "b@example.com"}
    assert mgr.get_password("b@example.com") == "second-password"


# ---------------------------------------------------------------------------
# BUG B - never prompt for the account password where it cannot arrive
# ---------------------------------------------------------------------------


def test_add_without_a_tty_asks_for_the_flag(cli_env, no_prompt):
    result = _run("account", "add", "someone@example.com", "--no-verify")
    _assert_no_traceback(result)
    assert result.exit_code == 1
    assert "--password" in result.output
    assert not no_prompt, "the guard must fire before the getpass prompt"


def test_real_process_account_add_no_stdin_fails_instead_of_hanging(cli_env):
    """The reproduction: `mb account add someone@example.com </dev/null` -> exit 1.

    A REAL process, because this is a Windows console quirk an in-process test
    cannot show: `NUL` is a character device, so `isatty()` answers True, the
    `getpass` prompt runs, and `msvcrt` blocks on the console forever - no
    output, no EOF, nothing to end it but a timeout.
    """
    env = {
        **os.environ,
        "MEGABASTERD_USER_DIR": str(cli_env / "user"),
        "MEGABASTERD_LOG_DIR": str(cli_env / "logs"),
        "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
    }
    try:
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "megabasterd_cli.cli",
                "account",
                "add",
                "someone@example.com",
                "--no-verify",
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=60,
            env=env,
        )
    except subprocess.TimeoutExpired:  # pragma: no cover - the bug we are fixing
        pytest.fail("`mb account add` with no stdin blocked on the password prompt")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "--password" in proc.stdout + proc.stderr
