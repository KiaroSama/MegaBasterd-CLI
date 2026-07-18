"""--auto-account re-planning after quota changes (Mandatory Fix 3)."""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from megabasterd_cli.cli import cli
from megabasterd_cli.core.api import MegaAPIClient
from megabasterd_cli.core.client import MegaClient, MegaSession
from megabasterd_cli.core.errors import QuotaError, TransferError
from megabasterd_cli.core.uploader import MegaUploader, UploadResult

GB = 1024**3


@pytest.fixture()
def cli_env(tmp_path, monkeypatch):
    monkeypatch.setenv("MEGABASTERD_USER_DIR", str(tmp_path / "user"))
    monkeypatch.setenv("MEGABASTERD_LOG_DIR", str(tmp_path / "logs"))

    from megabasterd_cli.accounts.manager import AccountManager
    from megabasterd_cli.config import accounts_file

    mgr = AccountManager(accounts_file())
    mgr.unlock("pp")
    mgr.add_account("a@example.com", "pw-a", make_default=True)
    mgr.add_account("b@example.com", "pw-b")
    mgr.update_quota("a@example.com", used=0, total=10 * GB)  # roomiest: picked first
    mgr.update_quota("b@example.com", used=0, total=5 * GB)

    def fake_login(self, email, password, mfa_code=None, mfa_prompt=None):
        self.session = MegaSession(sid=f"sid-{email}", master_key=b"\x00" * 16, email=email)
        return self.session

    monkeypatch.setattr(MegaClient, "login", fake_login)
    monkeypatch.setattr(MegaClient, "logout", lambda self: None)
    monkeypatch.setattr(
        MegaClient,
        "get_quota",
        lambda self: {"cstrg": 10 * GB, "mstrg": 10 * GB},  # live: account is FULL
    )
    return tmp_path


def test_file_rerouted_to_b_after_quota_error_on_a(cli_env, monkeypatch):
    attempts: list[str] = []

    def flaky_upload(self, source, **kwargs):
        email = self.client.session.email
        attempts.append(email)
        if email == "a@example.com":
            raise QuotaError(message="EOVERQUOTA")
        return UploadResult(file_handle="H", name=source.name, size=4, elapsed_seconds=0.1)

    monkeypatch.setattr(MegaUploader, "upload_file", flaky_upload)
    src = cli_env / "f.bin"
    src.write_bytes(b"data")
    runner = CliRunner()
    result = runner.invoke(
        cli, ["-q", "upload", str(src), "--auto-account", "--vault-passphrase", "pp"]
    )
    assert result.exit_code == 0, result.output
    assert attempts == [
        "a@example.com",
        "b@example.com",
    ], "the SAME file must be retried on another suitable account"


def test_future_files_avoid_exhausted_account(cli_env, monkeypatch):
    attempts: list[str] = []

    def flaky_upload(self, source, **kwargs):
        email = self.client.session.email
        attempts.append(f"{source.name}@{email}")
        if email == "a@example.com":
            raise QuotaError(message="EOVERQUOTA")
        return UploadResult(file_handle="H", name=source.name, size=4, elapsed_seconds=0.1)

    monkeypatch.setattr(MegaUploader, "upload_file", flaky_upload)
    f1 = cli_env / "f1.bin"
    f2 = cli_env / "f2.bin"
    f1.write_bytes(b"data")
    f2.write_bytes(b"data")
    runner = CliRunner()
    result = runner.invoke(
        cli, ["-q", "upload", str(f1), str(f2), "--auto-account", "--vault-passphrase", "pp"]
    )
    assert result.exit_code == 0, result.output
    # A is attempted exactly once; after the live-quota refresh (full), the
    # second file goes straight to B with no stale-quota attempt on A.
    a_attempts = [a for a in attempts if a.endswith("a@example.com")]
    assert len(a_attempts) == 1, attempts
    assert attempts[-1] == "f2.bin@b@example.com"


def test_retry_is_bounded_when_every_account_is_full(cli_env, monkeypatch):
    attempts: list[str] = []

    def always_quota(self, source, **kwargs):
        attempts.append(self.client.session.email)
        raise QuotaError(message="EOVERQUOTA")

    monkeypatch.setattr(MegaUploader, "upload_file", always_quota)
    src = cli_env / "f.bin"
    src.write_bytes(b"data")
    runner = CliRunner()
    result = runner.invoke(
        cli, ["-q", "upload", str(src), "--auto-account", "--vault-passphrase", "pp"]
    )
    assert result.exit_code == 1
    assert len(attempts) <= 2, "each account may be attempted at most once per file"


def test_keep_structure_tree_fails_clearly_not_distributed(cli_env, monkeypatch):
    calls: list[str] = []

    def failing_tree(self, source_dir, **kwargs):
        calls.append(self.client.session.email)
        self.last_directory_failures = [f"{source_dir}: quota exceeded mid-tree"]
        raise TransferError(message="1 upload item(s) failed: quota exceeded mid-tree")

    monkeypatch.setattr(MegaUploader, "upload_directory", failing_tree)
    tree = cli_env / "tree"
    (tree / "sub").mkdir(parents=True)
    (tree / "sub" / "x.bin").write_bytes(b"x" * 10)
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "-q",
            "upload",
            str(tree),
            "--keep-structure",
            "--auto-account",
            "--vault-passphrase",
            "pp",
        ],
    )
    assert result.exit_code == 1, "a partial tree is a clear failure"
    assert len(calls) == 1, "one tree is never silently re-planned/distributed mid-flight"


def test_all_temporary_clients_are_closed(cli_env, monkeypatch):
    closed: list[int] = []
    original_close = MegaAPIClient.close

    def counting_close(self):
        closed.append(id(self))
        original_close(self)

    monkeypatch.setattr(MegaAPIClient, "close", counting_close)

    def flaky_upload(self, source, **kwargs):
        if self.client.session.email == "a@example.com":
            raise QuotaError(message="EOVERQUOTA")
        return UploadResult(file_handle="H", name=source.name, size=4, elapsed_seconds=0.1)

    monkeypatch.setattr(MegaUploader, "upload_file", flaky_upload)
    src = cli_env / "f.bin"
    src.write_bytes(b"data")
    runner = CliRunner()
    result = runner.invoke(
        cli, ["-q", "upload", str(src), "--auto-account", "--vault-passphrase", "pp"]
    )
    assert result.exit_code == 0, result.output
    assert len(closed) >= 2, "both temporary account clients must be closed"
