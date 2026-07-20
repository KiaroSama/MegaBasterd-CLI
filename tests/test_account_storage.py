"""Tests for encrypted account storage."""

from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from megabasterd_cli.accounts.manager import AccountManager, AccountNotFound
from megabasterd_cli.accounts.storage import VaultUnlockError


def test_add_get_remove_account(tmp_path: Path):
    mgr = AccountManager(tmp_path / "accounts.json")
    mgr.unlock("test-passphrase")
    acc = mgr.add_account("u@example.com", "secret123", label="primary")
    assert acc.email == "u@example.com"
    assert mgr.get_password("u@example.com") == "secret123"

    mgr.remove_account("u@example.com")
    with pytest.raises(AccountNotFound):
        mgr.get_account("u@example.com")


def test_wrong_passphrase_fails_to_decrypt(tmp_path: Path):
    """Reopening the store with a different passphrase cannot decrypt the password."""
    mgr1 = AccountManager(tmp_path / "accounts.json")
    mgr1.unlock("right-pass")
    mgr1.add_account("u@example.com", "topsecret")

    mgr2 = AccountManager(tmp_path / "accounts.json")
    mgr2.unlock("wrong-pass")

    # The contract is now `VaultUnlockError`, which carries a message a user can
    # read - a bare `InvalidTag` stringifies to "" and reached the console as a
    # traceback ending in an empty `Error:` line. It still subclasses
    # `InvalidTag` so a 1.x caller that catches the cryptography exception keeps
    # working; both assertions below are the point, not one of them.
    with pytest.raises(VaultUnlockError) as caught:
        mgr2.get_password("u@example.com")
    assert "passphrase" in str(caught.value)
    assert isinstance(caught.value, InvalidTag)


def test_default_account_tracking(tmp_path: Path):
    mgr = AccountManager(tmp_path / "accounts.json")
    mgr.unlock("pass")
    mgr.add_account("a@x.com", "p1")
    mgr.add_account("b@x.com", "p2")
    assert mgr.store.default_email == "a@x.com"
    mgr.set_default("b@x.com")
    assert mgr.store.default_email == "b@x.com"
