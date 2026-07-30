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


def session_path(account_id: str) -> Path:
    """The cache file for one account, under the user's data dir.

    Lives here rather than in the command that happened to need it first, so
    the command that WRITES the cache and the command that clears it cannot
    disagree about the name - the account id would then keep a session nobody
    could reach, still valid server-side.
    """
    from hashlib import sha256

    from ..config import session_dir

    # The id can be an email or a label; hash it so the filename never carries
    # the address around on disk.
    return session_dir() / f"{sha256(account_id.lower().encode('utf-8')).hexdigest()[:32]}.session"


def forget_session(account_id: str) -> bool:
    """Delete the cached session for `account_id`. True if one was there.

    Local only - this does not tell MEGA anything. Invalidating the session
    server-side is `MegaClient.logout()`, and both are needed: dropping the
    file alone leaves a token that stays valid until MEGA expires it, while
    calling logout alone leaves a dead file the next run has to probe and
    discard.
    """
    path = session_path(account_id)
    try:
        path.unlink()
        return True
    except FileNotFoundError:
        return False
    except OSError as exc:
        log.warning("Could not remove the cached session for %s: %s", account_id, exc)
        return False


def restore_session(client, account_id: str, passphrase: str) -> bool:
    """Reuse a cached session instead of logging in again. True when reused.

    The passphrase is the one already given to unlock the account vault, so
    reuse costs no extra prompt - and a new machine, or a changed passphrase,
    just falls through to a normal login.

    A cached session can be stale (MEGA expired it, or it was ended elsewhere),
    so it is PROVEN with one cheap authenticated call before being trusted. A
    dead session must never be handed to a command as though it worked.

    Here rather than in one command module because all three login paths need
    it: the cloud commands, `upload`, and `account add`. `upload` having its own
    login that skipped the cache is why 2FA was demanded on every single
    command even right after a successful, 2FA-answered `account add`.
    """
    path = session_path(account_id)
    if not path.is_file():
        return False
    session = client.load_session(path, passphrase)
    if session is None:
        return False
    client.session = session
    client.api.set_session(session.sid)
    try:
        client.api.request({"a": "ug"})
    except Exception:  # noqa: BLE001 - any failure means "log in properly"
        log.debug("Cached session for %s is no longer valid; logging in again", account_id)
        client.session = None
        client.invalidate_cache()
        # Also take the dead sid off the TRANSPORT. Clearing only `client.session`
        # left it attached to the api, so the login that follows carried it and
        # came back ESID (-15) - a stale cache turned into a hard login failure
        # instead of the silent fallback this function exists to provide.
        with contextlib.suppress(AttributeError):
            client.api.clear_session()
        forget_session(account_id)
        return False
    log.debug("Reused the cached session for %s", account_id)
    return True


def remember_session(client, account_id: str, passphrase: str) -> None:
    """Persist the session encrypted with the vault passphrase; never fatal.

    Losing the cache costs one extra login, so it must not turn a completed
    transfer into a failure.
    """
    from ..config import session_dir
    from .errors import MegaError

    try:
        session_dir().mkdir(parents=True, exist_ok=True)
        client.save_session(session_path(account_id), passphrase)
    except (OSError, MegaError) as exc:
        log.debug("Could not store the session for %s: %s", account_id, exc)


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
