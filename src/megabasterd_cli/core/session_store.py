"""Encrypted on-disk persistence of a MegaSession."""

from __future__ import annotations

import contextlib
import json
import logging
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag

from .auth import MegaSession
from .errors import AuthError, MegaError
from .responses import _expect_field

log = logging.getLogger(__name__)


def _atomic_write_private(path: Path, data: bytes) -> None:
    """Replace `path` with `data` in one step, owner-only from creation.

    The previous in-place `open(path, "w")` truncated the existing session
    before writing, so any failure mid-write destroyed a still-valid session,
    and `os.chmod(..., 0o600)` ran only AFTER the write - leaving the SID
    world-readable for that window. Same `O_CREAT | O_EXCL` + 0o600 pattern
    `utils.corruption` already uses.
    """
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    try:
        fd = os.open(str(tmp), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        # A restrictive umask already gave us 0o600; this covers a permissive
        # one without ever widening the mode. Ignored on Windows.
        with contextlib.suppress(OSError, AttributeError):
            os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise


class SessionPersistence:
    """Save and load the encrypted session file."""

    session: MegaSession | None

    def save_session(self, path: Path, passphrase: str | None = None) -> None:
        """Serialize the current session to `path` encrypted with `passphrase`."""
        if not self.session:
            raise AuthError(message="Not logged in")
        if not passphrase:
            raise AuthError(message="Saving sessions requires a passphrase")
        from ..accounts.storage import CredentialVault

        payload = {
            "sid": self.session.sid,
            "master_key": self.session.master_key.hex(),
            "rsa_private_key": (
                self.session.rsa_private_key.hex() if self.session.rsa_private_key else None
            ),
            "user_handle": self.session.user_handle,
            "email": self.session.email,
        }
        data = {
            "version": 2,
            "encrypted": CredentialVault(passphrase).encrypt(
                json.dumps(payload, separators=(",", ":"))
            ),
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write_private(path, json.dumps(data).encode("utf-8"))

    @staticmethod
    def load_session(path: Path, passphrase: str | None = None) -> MegaSession | None:
        """Read a saved session JSON. Returns None if the file is missing/corrupt."""
        if not path.exists():
            return None
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            # The file is attacker-reachable and user-editable, so its SHAPE is
            # checked before anything indexes it. `"encrypted" in data` used to
            # run against whatever json.load returned: a bare `"encrypted"`
            # string passed the substring test and then raised AttributeError
            # on `.get`, while `123`/`null` raised TypeError on the `in` itself
            # - neither caught, so "returns None if corrupt" was not true.
            if not isinstance(data, dict):
                log.warning("Refusing to load malformed session file: %s", path)
                return None
            if "encrypted" in data:
                if data.get("version") != 2:
                    log.warning("Refusing to load unsupported session file version: %s", path)
                    return None
                if not passphrase:
                    return None
                blob = data["encrypted"]
                if not isinstance(blob, str):
                    log.warning("Refusing to load malformed session file: %s", path)
                    return None
                from ..accounts.storage import CredentialVault

                data = json.loads(CredentialVault(passphrase).decrypt(blob))
                if not isinstance(data, dict):
                    log.warning("Refusing to load malformed session payload: %s", path)
                    return None
            elif os.environ.get("MEGABASTERD_ALLOW_PLAINTEXT_SESSION") != "1":
                log.warning("Refusing to load plaintext session file: %s", path)
                return None
            rsa = data.get("rsa_private_key")
            return MegaSession(
                sid=_expect_field(data, "sid", str, "saved session"),
                master_key=bytes.fromhex(_expect_field(data, "master_key", str, "saved session")),
                rsa_private_key=bytes.fromhex(rsa) if isinstance(rsa, str) and rsa else None,
                user_handle=_expect_field(data, "user_handle", str, "saved session", default=""),
                email=_expect_field(data, "email", str, "saved session", default=""),
            )
        except (json.JSONDecodeError, KeyError, ValueError, OSError, InvalidTag, MegaError):
            return None
