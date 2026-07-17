"""Account manager: add/remove/list/switch accounts."""

from __future__ import annotations

import datetime as dt
import logging
from pathlib import Path

from .storage import Account, AccountStorage, AccountStore, CredentialVault

log = logging.getLogger(__name__)


class AccountNotFound(Exception):  # noqa: N818 - public CLI API name
    pass


_default_conflict_warned = False


def resolve_account_id(
    mgr: AccountManager,
    config_default: str | None,
    explicit: str | None = None,
) -> str | None:
    """One shared default-account resolution for upload/queue/share/cloud.

    Precedence:
      1. an explicit ``--account`` value;
      2. the account-vault default (``mb account default`` / ``add --default``);
      3. the legacy ``config.default_account`` fallback.

    When both writable defaults exist and disagree, the vault default wins and
    a warning is emitted once per process.
    """
    global _default_conflict_warned
    if explicit:
        return explicit
    vault_default = mgr.store.default_email
    if (
        vault_default
        and config_default
        and vault_default.lower() != config_default.lower()
        and not _default_conflict_warned
    ):
        log.warning(
            "Account-vault default (%s) and config default_account (%s) disagree; "
            "using the vault default. Clear one of them to silence this warning.",
            vault_default,
            config_default,
        )
        _default_conflict_warned = True
    return vault_default or config_default


class AccountManager:
    """High-level API for working with the account store.

    The constructor doesn't ask for the passphrase; the caller must supply one
    before calling methods that decrypt passwords.
    """

    def __init__(self, store_path: Path):
        self.storage = AccountStorage(store_path)
        self.store: AccountStore = self.storage.load()
        self._vault: CredentialVault | None = None

    # ------------------------------------------------------------------
    # Vault control
    # ------------------------------------------------------------------
    def unlock(self, passphrase: str) -> None:
        """Set the passphrase used to encrypt/decrypt stored credentials."""
        self._vault = CredentialVault(passphrase)

    def is_unlocked(self) -> bool:
        return self._vault is not None

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------
    def list_accounts(self) -> list[Account]:
        return list(self.store.accounts)

    def get_account(self, email_or_label: str) -> Account:
        for a in self.store.accounts:
            if a.email.lower() == email_or_label.lower():
                return a
            if a.label and a.label.lower() == email_or_label.lower():
                return a
        raise AccountNotFound(email_or_label)

    def add_account(
        self,
        email: str,
        password: str,
        label: str | None = None,
        make_default: bool = False,
    ) -> Account:
        if not self._vault:
            raise RuntimeError("Account store is locked; call unlock() first")
        # Check for duplicates
        for a in self.store.accounts:
            if a.email.lower() == email.lower():
                raise ValueError(f"Account already exists: {email}")

        enc = self._vault.encrypt(password)
        account = Account(email=email, enc_password=enc, label=label)
        self.store.accounts.append(account)
        if make_default or not self.store.default_email:
            self.store.default_email = email
        self.storage.save(self.store)
        return account

    def remove_account(self, email_or_label: str) -> None:
        account = self.get_account(email_or_label)
        self.store.accounts = [a for a in self.store.accounts if a.email != account.email]
        if self.store.default_email == account.email:
            self.store.default_email = self.store.accounts[0].email if self.store.accounts else None
        self.storage.save(self.store)

    def get_password(self, email_or_label: str) -> str:
        if not self._vault:
            raise RuntimeError("Account store is locked; call unlock() first")
        account = self.get_account(email_or_label)
        return self._vault.decrypt(account.enc_password)

    def set_default(self, email_or_label: str) -> None:
        account = self.get_account(email_or_label)
        self.store.default_email = account.email
        self.storage.save(self.store)

    def update_quota(self, email: str, used: int, total: int) -> None:
        for a in self.store.accounts:
            if a.email == email:
                a.quota_used = used
                a.quota_total = total
                a.last_used_iso = dt.datetime.now(dt.timezone.utc).isoformat()
                break
        self.storage.save(self.store)

    def pick_account_with_space(self, required_bytes: int) -> Account | None:
        """Find an account with enough free quota for a file of this size."""
        candidates = []
        for a in self.store.accounts:
            if a.quota_total is None or a.quota_used is None:
                continue
            free = a.quota_total - a.quota_used
            if free >= required_bytes:
                candidates.append((free, a))
        if not candidates:
            return None
        candidates.sort(key=lambda x: x[0], reverse=True)
        return candidates[0][1]
