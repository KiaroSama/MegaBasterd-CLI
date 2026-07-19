"""At-rest encryption for queue job secrets (link passwords)."""

from __future__ import annotations

import base64
import contextlib
import logging
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import QueueKeyError

log = logging.getLogger(__name__)

# Associated data tag so a queue secret blob cannot be reused in another context.
_QUEUE_SECRET_AAD = b"megabasterd-cli/queue-secret"
_QUEUE_KEY_LEN = 32
_QUEUE_SECRET_VERSION = 1  # First byte of the decoded blob (self-identifying).


class QueueSecretBox:
    """Encrypts queue item secrets at rest with a locally stored random key.

    A 32-byte key is generated once and stored next to the queue file with
    restrictive permissions. Secrets are sealed with AES-256-GCM and stored as a
    self-identifying, versioned blob. This keeps plaintext passwords out of
    ``queue.json`` (and any backup/sync of it) while preserving non-interactive
    queue runs (no passphrase prompt).

    Threat model: this does NOT protect against an attacker who can read BOTH
    ``queue.json`` and the key file; possession of both allows recovery of the
    secret. On Windows the file is created with normal user permissions (no
    POSIX mode bits). For stronger protection, run the queue with an unlocked
    credential vault instead.
    """

    def __init__(self, key_path: Path):
        self.key_path = key_path
        self._key: bytes | None = None

    def load_key(self, create: bool) -> bytes | None:
        """Return the queue key, or None when it is absent and create is False.

        A non-empty key file of the wrong length is treated as corruption and
        is never silently replaced (that would orphan existing secrets). An
        empty/partial file is recreated only when ``create`` is True.
        """
        if self._key is not None:
            return self._key
        empty_recover = False
        if self.key_path.exists():
            data = self.key_path.read_bytes()
            if len(data) == _QUEUE_KEY_LEN:
                self._key = data
                return data
            if len(data) == 0:
                if not create:
                    return None
                log.warning("Queue key file is empty; generating a new key")
                empty_recover = True
            else:
                # Non-empty but wrong length means corruption; do not replace.
                raise QueueKeyError(
                    f"Queue key file has unexpected length {len(data)}; refusing to use it"
                )
        if not create:
            return None
        key = os.urandom(_QUEUE_KEY_LEN)
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        if empty_recover:
            # Overwrite the empty placeholder atomically.
            tmp = self.key_path.with_suffix(self.key_path.suffix + ".tmp")
            tmp.write_bytes(key)
            os.replace(tmp, self.key_path)
        else:
            # Race-safe exclusive create: if another process created the key
            # first, adopt the existing valid key instead of clobbering it.
            try:
                fd = os.open(str(self.key_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                existing = self.key_path.read_bytes()
                if len(existing) == _QUEUE_KEY_LEN:
                    self._key = existing
                    return existing
                raise QueueKeyError("Queue key file appeared but is invalid") from None
            with os.fdopen(fd, "wb") as f:
                f.write(key)
        with contextlib.suppress(OSError, AttributeError):
            os.chmod(self.key_path, 0o600)
        self._key = key
        return key

    def encrypt(self, plaintext: str, allow_create: bool = True) -> str:
        """Encrypt a queue secret. When ``allow_create`` is False and no valid
        key exists, raise instead of creating one (used when other encrypted
        secrets already exist, to avoid orphaning them)."""
        key = self.load_key(create=allow_create)
        if key is None:
            raise QueueKeyError(
                "No queue key is available to encrypt the secret and creating a new "
                "one is refused because encrypted queue secrets already exist"
            )
        nonce = os.urandom(12)
        ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), _QUEUE_SECRET_AAD)
        blob = bytes([_QUEUE_SECRET_VERSION]) + nonce + ct
        return base64.b64encode(blob).decode("ascii")

    def decrypt(self, token: str) -> str:
        # Decryption never creates a key; a missing key means the secret is
        # currently unrecoverable (the caller preserves the original blob).
        key = self.load_key(create=False)
        if key is None:
            raise QueueKeyError("Queue key is missing; cannot decrypt the stored secret")
        raw = base64.b64decode(token)
        # Accept the versioned blob (v1) and, for forward safety, an unversioned
        # legacy blob (nonce||ct) produced by an earlier build of this branch.
        if raw and raw[0] == _QUEUE_SECRET_VERSION and len(raw) >= 1 + 12 + 16:
            nonce, ct = raw[1:13], raw[13:]
        elif len(raw) >= 12 + 16:
            nonce, ct = raw[:12], raw[12:]
        else:
            raise ValueError("Queue secret blob too short")
        return AESGCM(key).decrypt(nonce, ct, _QUEUE_SECRET_AAD).decode("utf-8")
