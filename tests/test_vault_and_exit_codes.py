"""Vault prompts, vault errors, and failure exit codes.

Four defects share one theme - a failure that does not look like one:

* `proxy list`/`proxy remove` printed `user:pass@host` verbatim when the stored
  URL had no scheme (`redact_text` only matches after a `scheme://`, and
  `urlsplit` misreads the schemeless form as `scheme='alice'`).
* the `getpass` vault prompt was reachable with an EMPTY vault and in `--json`
  mode; on Windows `getpass` reads the console directly, so a redirected or
  closed stdin does not raise EOF - the process blocks forever, silent.
* a wrong vault passphrase escaped as cryptography's `InvalidTag`, whose
  `str()` is empty, so the user's last line was literally `Error: `.
* `proxy fetch` and `proxy serve` reported a failure and exited 0.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
import requests
from click.testing import CliRunner

from megabasterd_cli.accounts.manager import AccountManager
from megabasterd_cli.accounts.storage import VaultUnlockError
from megabasterd_cli.cli import cli
from megabasterd_cli.commands import account_cmd as account_module
from megabasterd_cli.commands import proxy_cmd as proxy_module
from megabasterd_cli.config import accounts_file
from megabasterd_cli.ui.theme import make_console

PASSPHRASE = "right-passphrase"
WRONG_PASSPHRASE = "wrong-passphrase"
CRED_URL = "alice:hunter2@1.2.3.4:8080"  # exactly what `proxy add`/`import` stores


@pytest.fixture()
def cli_env(tmp_path, monkeypatch):
    monkeypatch.setenv("MEGABASTERD_USER_DIR", str(tmp_path / "user"))
    monkeypatch.setenv("MEGABASTERD_LOG_DIR", str(tmp_path / "logs"))
    monkeypatch.setattr(proxy_module, "_console", make_console(width=400))
    return tmp_path


@pytest.fixture()
def no_prompt(monkeypatch):
    """Any `getpass` prompt reached here would hang a real non-interactive run."""
    asked: list[str] = []

    def fail(question: str = "Password") -> str:
        asked.append(question)
        raise AssertionError(f"interactive prompt reached: {question}")

    # `upload` reaches the same prompt through `account_cmd`'s shared helper.
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
# L5 - schemeless proxy credentials must not reach the terminal
# ---------------------------------------------------------------------------


def test_proxy_list_redacts_schemeless_credentials(cli_env):
    assert _run("proxy", "add", CRED_URL).exit_code == 0
    result = _run("proxy", "list")
    assert result.exit_code == 0, result.output
    assert "1.2.3.4:8080" in result.output, "the host must stay visible"
    assert "hunter2" not in result.output
    assert "alice" not in result.output


def test_proxy_remove_redacts_schemeless_credentials(cli_env):
    assert _run("proxy", "add", CRED_URL).exit_code == 0
    result = _run("proxy", "remove", CRED_URL)
    assert result.exit_code == 0, result.output
    assert "hunter2" not in result.output
    assert "alice" not in result.output


def test_proxy_remove_not_found_also_redacts(cli_env):
    result = _run("proxy", "remove", CRED_URL)
    assert "hunter2" not in result.output


def test_scheme_qualified_credentials_stay_redacted(cli_env):
    assert _run("proxy", "add", f"socks5://{CRED_URL}").exit_code == 0
    result = _run("proxy", "list")
    assert "hunter2" not in result.output


# ---------------------------------------------------------------------------
# L6 - never prompt where the answer cannot arrive
# ---------------------------------------------------------------------------


def test_account_info_with_empty_vault_fails_without_prompting(cli_env, no_prompt):
    result = _run("account", "info")
    _assert_no_traceback(result)
    assert result.exit_code == 1
    assert "account" in result.output.lower()


def test_account_info_without_a_tty_asks_for_the_flag(stored_account, no_prompt):
    result = _run("account", "info")
    _assert_no_traceback(result)
    assert result.exit_code == 1
    assert "--vault-passphrase" in result.output


def test_account_refresh_all_with_empty_vault_fails_without_prompting(cli_env, no_prompt):
    result = _run("account", "refresh-all")
    _assert_no_traceback(result)
    assert result.exit_code == 1


def test_upload_json_mode_fails_without_prompting(stored_account, no_prompt, tmp_path):
    src = tmp_path / "f.txt"
    src.write_text("payload", encoding="utf-8")
    result = _run("upload", str(src), "--json")
    _assert_no_traceback(result)
    assert result.exit_code == 1
    assert "--vault-passphrase" in result.output


def test_real_process_with_no_stdin_fails_instead_of_hanging(stored_account):
    """The original reproduction: `mb account info </dev/null` -> exit 124.

    A REAL process, because this is a Windows console quirk an in-process test
    cannot show: `NUL` is a character device, so `isatty()` answers True, the
    `getpass` prompt runs, and `msvcrt` blocks on the console forever - no
    output, no EOF, nothing to kill it but a timeout.
    """
    env = {
        **os.environ,
        "MEGABASTERD_USER_DIR": str(stored_account / "user"),
        "MEGABASTERD_LOG_DIR": str(stored_account / "logs"),
        "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
    }
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "megabasterd_cli.cli", "account", "info"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=60,
            env=env,
        )
    except subprocess.TimeoutExpired:  # pragma: no cover - the bug we are fixing
        pytest.fail("`mb account info` with no stdin blocked on the vault prompt")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "--vault-passphrase" in proc.stdout + proc.stderr


def test_account_add_still_works_on_an_empty_vault(cli_env):
    """The empty-vault guard must not lock the user out of creating the first one."""
    result = _run(
        "account",
        "add",
        "first@example.com",
        "--password",
        "pw",
        "--no-verify",
        "--vault-passphrase",
        PASSPHRASE,
    )
    assert result.exit_code == 0, result.output
    assert AccountManager(accounts_file()).list_accounts()


# ---------------------------------------------------------------------------
# L7 - a wrong passphrase is a typed, readable error
# ---------------------------------------------------------------------------


def test_wrong_passphrase_raises_typed_error(stored_account):
    mgr = AccountManager(accounts_file())
    mgr.unlock(WRONG_PASSPHRASE)
    with pytest.raises(VaultUnlockError) as excinfo:
        mgr.get_password("a@example.com")
    message = str(excinfo.value)
    assert message.strip(), "an empty message renders as a bare `Error: ` line"
    assert WRONG_PASSPHRASE not in message


def test_account_info_reports_a_wrong_passphrase_cleanly(stored_account, no_prompt):
    result = _run("account", "info", "--vault-passphrase", WRONG_PASSPHRASE)
    _assert_no_traceback(result)
    assert result.exit_code == 1
    assert "passphrase" in result.output.lower()
    assert WRONG_PASSPHRASE not in result.output


# ---------------------------------------------------------------------------
# L8 - a reported failure must not exit 0
# ---------------------------------------------------------------------------


def test_proxy_fetch_failure_exits_nonzero(cli_env, monkeypatch):
    def boom(*args, **kwargs):
        raise requests.ConnectionError("unreachable")

    monkeypatch.setattr(requests, "get", boom)
    result = _run("proxy", "fetch")
    assert result.exit_code == 1, result.output
    assert "No proxies fetched" in result.output


def test_proxy_serve_without_password_exits_nonzero(cli_env):
    result = _run("proxy", "serve")
    assert result.exit_code == 1, result.output
    assert "password" in result.output.lower()
