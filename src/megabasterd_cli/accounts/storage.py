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
import json
import os
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


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
        return AESGCM(key).decrypt(nonce, ct, None).decode("utf-8")


class AccountStorage:
    """Read/write account list to disk."""

    def __init__(self, path: Path):
        self.path = path

    def load(self) -> AccountStore:
        if not self.path.exists():
            return AccountStore()
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return AccountStore(
                accounts=[Account(**a) for a in data.get("accounts", [])],
                default_email=data.get("default_email"),
                version=data.get("version", 1),
            )
        except (json.JSONDecodeError, TypeError, ValueError):
            return AccountStore()

    def save(self, store: AccountStore) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "version": store.version,
            "default_email": store.default_email,
            "accounts": [asdict(a) for a in store.accounts],
        }
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, self.path)
        # Permission hardening on POSIX
        try:
            os.chmod(self.path, 0o600)
        except (OSError, AttributeError):
            pass
