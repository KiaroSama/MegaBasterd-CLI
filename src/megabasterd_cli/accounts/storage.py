"""Encrypted, on-disk storage of account credentials.

Accounts are stored in a JSON file. The credentials field of each account is
encrypted with AES-GCM using a key derived from a master passphrase via
scrypt. The passphrase is requested interactively the first time the CLI
needs an account in a session; it is then cached in memory for the rest of
the session (not on disk).

If the user prefers no encryption (development), an "obfuscated" mode stores
the credentials base64-encoded with a static key; this is NOT secure but
prevents casual reading.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import json
import logging
import os
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from ..queue.storage import atomic_write_text

log = logging.getLogger(__name__)


class VaultUnlockError(InvalidTag):
    """The stored credential did not decrypt with the supplied passphrase.

    AES-GCM signals this as `InvalidTag`, whose `str()` is the EMPTY STRING, so
    letting it escape gave the user a ~20-frame traceback ending in a bare
    `Error: ` line. The passphrase is deliberately never part of the message.

    It subclasses `InvalidTag` so callers (and tests) that already catch the
    cryptography exception keep working; new code catches this instead.
    """


@dataclass
class Account:
    """One stored MEGA account."""

    email: str
    enc_password: str  # base64(salt + nonce + ciphertext)
    label: str | None = None  # Friendly name
    quota_total: int | None = None
    quota_used: int | None = None
    last_used_iso: str | None = None
    notes: str | None = None


@dataclass
class AccountStore:
    """The on-disk container for accounts."""

    accounts: list[Account] = field(default_factory=list)
    default_email: str | None = None
    version: int = 1


class CredentialVault:
    """Wraps AES-GCM encryption of individual passwords with a scrypt-derived key."""

    SCRYPT_N = 2**14
    SCRYPT_R = 8
    SCRYPT_P = 1
    KEY_LEN = 32

    def __init__(self, passphrase: str):
        self._passphrase = passphrase.encode("utf-8")

    def _derive(self, salt: bytes) -> bytes:
        kdf = Scrypt(
            salt=salt,
            length=self.KEY_LEN,
            n=self.SCRYPT_N,
            r=self.SCRYPT_R,
            p=self.SCRYPT_P,
        )
        return kdf.derive(self._passphrase)

    def encrypt(self, plaintext: str) -> str:
        """Return base64(salt || nonce || ciphertext+tag)."""
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = self._derive(salt)
        ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
        return base64.b64encode(salt + nonce + ct).decode("ascii")

    def decrypt(self, encoded: str) -> str:
        raw = base64.b64decode(encoded)
        if len(raw) < 28:
            raise ValueError("Encrypted blob too short")
        salt, nonce, ct = raw[:16], raw[16:28], raw[28:]
        key = self._derive(salt)
        try:
            return AESGCM(key).decrypt(nonce, ct, None).decode("utf-8")
        except (InvalidTag, UnicodeDecodeError) as exc:
            raise VaultUnlockError(
                "Wrong vault passphrase (or the credential is corrupt)."
            ) from exc


class AccountCorruptionError(Exception):
    """The account vault is malformed and was preserved untouched.

    Mutations are blocked until the operator resolves it: silently starting
    from an EMPTY vault and then saving would destroy the user's stored MEGA
    credentials, which exist nowhere else.
    """


_MAX_QUOTA_BYTES = 1 << 60  # sane upper bound; larger values are corruption


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AccountCorruptionError(message)


def validate_account_document(data) -> AccountStore:
    """Validate a parsed accounts.json, or raise AccountCorruptionError.

    Each failure below previously produced either an empty vault - which the
    next save wrote over the real file - or a raw AttributeError/TypeError out
    of the CLI.
    """
    _require(
        isinstance(data, dict),
        f"account store root is {type(data).__name__}, expected an object",
    )

    version = data.get("version", 1)
    _require(
        isinstance(version, int) and not isinstance(version, bool),
        "account store 'version' must be an integer",
    )

    raw_accounts = data.get("accounts", [])
    _require(isinstance(raw_accounts, list), "account store 'accounts' must be a list")

    known = {f.name for f in fields(Account)}
    accounts: list[Account] = []
    seen_emails: set[str] = set()
    seen_labels: set[str] = set()
    for entry in raw_accounts:
        _require(isinstance(entry, dict), "account entry must be an object")
        unknown = set(entry) - known
        _require(not unknown, f"account entry has unknown field(s) {sorted(unknown)}")

        email = entry.get("email")
        _require(
            isinstance(email, str) and bool(email.strip()),
            "account 'email' must be a non-empty string",
        )
        canonical = email.strip().lower()
        _require(canonical not in seen_emails, f"duplicate account e-mail {canonical!r}")
        seen_emails.add(canonical)

        enc = entry.get("enc_password")
        _require(
            isinstance(enc, str) and bool(enc),
            "account 'enc_password' must be a non-empty string",
        )
        try:
            blob = base64.b64decode(enc, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise AccountCorruptionError(
                f"account {canonical!r} has a non-base64 encrypted password"
            ) from exc
        _require(len(blob) >= 28, f"account {canonical!r} has a truncated encrypted password")

        label = entry.get("label")
        _require(
            label is None or isinstance(label, str), "account 'label' must be a string or null"
        )
        if isinstance(label, str) and label.strip():
            key = label.strip().lower()
            _require(key not in seen_labels, f"ambiguous duplicate account label {key!r}")
            seen_labels.add(key)

        for name in ("quota_total", "quota_used"):
            value = entry.get(name)
            _require(
                value is None or (isinstance(value, int) and not isinstance(value, bool)),
                f"account {name!r} must be an integer or null",
            )
            if value is not None:
                _require(0 <= value <= _MAX_QUOTA_BYTES, f"account {name!r} is out of range")

        for name in ("last_used_iso", "notes"):
            value = entry.get(name)
            _require(
                value is None or isinstance(value, str),
                f"account {name!r} must be a string or null",
            )

        accounts.append(Account(**entry))

    default_email = data.get("default_email")
    _require(
        default_email is None or isinstance(default_email, str),
        "account store 'default_email' must be a string or null",
    )
    if isinstance(default_email, str) and default_email.strip():
        _require(
            default_email.strip().lower() in seen_emails,
            "account store 'default_email' names an account that does not exist",
        )

    return AccountStore(accounts=accounts, default_email=default_email, version=version)


class AccountStorage:
    """Read/write account list to disk."""

    def __init__(self, path: Path):
        self.path = path
        self._corrupt = False
        self._corrupt_reason = ""
        self._corrupt_backup: Path | None = None

    @property
    def is_corrupt(self) -> bool:
        return self._corrupt

    @property
    def corruption_reason(self) -> str:
        return self._corrupt_reason

    @property
    def corrupt_backup(self) -> Path | None:
        return self._corrupt_backup

    def _mark_corrupt(self, reason: str, data: bytes | None) -> None:
        from ..utils.corruption import preserve_corrupt_file

        self._corrupt = True
        self._corrupt_backup = preserve_corrupt_file(self.path, data) if data is not None else None
        where = (
            f"A backup was saved as {self._corrupt_backup.name}"
            if self._corrupt_backup is not None
            else "A backup could NOT be written"
        )
        self._corrupt_reason = (
            f"The account vault is corrupt and was preserved untouched: {reason}. {where}; "
            "move it aside or restore a good copy. Mutations are blocked so your stored "
            "credentials are not overwritten."
        )
        log.warning("%s", self._corrupt_reason)

    def _ensure_writable(self) -> None:
        if self._corrupt:
            raise AccountCorruptionError(self._corrupt_reason)

    def load(self) -> AccountStore:
        self._corrupt = False
        self._corrupt_reason = ""
        self._corrupt_backup = None
        if not self.path.exists():
            return AccountStore()
        try:
            raw = self.path.read_bytes()
        except OSError as exc:
            self._mark_corrupt(f"unreadable ({type(exc).__name__})", None)
            return AccountStore()
        try:
            data = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            self._mark_corrupt(f"not valid UTF-8 JSON ({type(exc).__name__})", raw)
            return AccountStore()
        try:
            return validate_account_document(data)
        except AccountCorruptionError as exc:
            self._mark_corrupt(str(exc), raw)
            return AccountStore()

    def save(self, store: AccountStore) -> None:
        # Re-read here, under the same call that replaces the file, so a vault
        # that became corrupt after this object was built is never overwritten
        # by an in-memory snapshot (the empty-vault data-loss path).
        self.load()
        self._ensure_writable()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "version": store.version,
            "default_email": store.default_email,
            "accounts": [asdict(a) for a in store.accounts],
        }
        # Unique temp file, fsync, bounded PermissionError retry (Windows AV
        # holding the vault open) and temp cleanup all live in the shared
        # helper. Losing a vault write is worse than losing a config write, so
        # the retry matters more here, but it is the same retry.
        atomic_write_text(self.path, json.dumps(data, indent=2))
        # Permission hardening on POSIX
        with contextlib.suppress(OSError, AttributeError):
            os.chmod(self.path, 0o600)
