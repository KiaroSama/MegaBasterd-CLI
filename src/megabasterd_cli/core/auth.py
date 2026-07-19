"""Login, the session model, RSA session-ID decoding, and session teardown."""

from __future__ import annotations

import contextlib
import logging
import os
from dataclasses import dataclass
from typing import Any, Callable

from .crypto import (
    a32_to_bytes,
    aes_cbc_decrypt,
    aes_cbc_decrypt_a32,
    b64_url_decode,
    b64_url_encode,
    bytes_to_a32,
    derive_key_legacy,
    derive_key_v2,
    str_to_a32,
    stringhash,
)
from .errors import AuthError, MegaError
from .nodes import NodeOperations
from .responses import _expect_field, _expect_mapping

log = logging.getLogger(__name__)


@dataclass
class MegaSession:
    """Active MEGA login session."""

    sid: str
    master_key: bytes  # 16 bytes
    rsa_private_key: bytes | None = None
    user_handle: str = ""
    email: str = ""


class AuthOperations(NodeOperations):
    """Authentication, session restoration, and end-of-life teardown."""

    def login_anonymous(self) -> MegaSession:
        """Login without an account (ephemeral session)."""
        master_key = os.urandom(16)
        result = _expect_mapping(self.api.request({"a": "us0"}), "anonymous login")
        sid = _expect_field(result, "tsid", str, "anonymous login", default="") or _expect_field(
            result, "csid", str, "anonymous login", default=""
        )

        self.session = MegaSession(sid=sid, master_key=master_key)
        self.api.set_session(sid)
        return self.session

    def login(
        self,
        email: str,
        password: str,
        mfa_code: str | None = None,
        mfa_prompt: Callable[[], str] | None = None,
    ) -> MegaSession:
        """Login with email and password.

        Tries account version 2 (PBKDF2) first, then falls back to legacy v1.
        If the account requires multi-factor authentication, `mfa_code` is used
        if supplied, otherwise `mfa_prompt()` is invoked to obtain a code.
        """
        # Step 1: get the account version and salt
        prelogin = _expect_mapping(
            self.api.request({"a": "us0", "user": email.lower()}), "prelogin"
        )
        version = _expect_field(prelogin, "v", int, "prelogin", default=1)
        salt_b64 = _expect_field(prelogin, "s", str, "prelogin", default="")

        if version == 2:
            salt = b64_url_decode(salt_b64)
            derived = derive_key_v2(password, salt)
            login_key = derived[:16]
            password_hash = b64_url_encode(derived[16:])
        else:
            derived_a32 = derive_key_legacy(password)
            login_key = a32_to_bytes(derived_a32)
            password_hash = stringhash(email.lower(), derived_a32)

        # Step 2: actual login (handle 2FA challenge)
        try:
            result = self.api.request({"a": "us", "user": email.lower(), "uh": password_hash})
        except MegaError as exc:
            if exc.code == -26:  # EMFAREQUIRED
                code = mfa_code
                if not code and mfa_prompt:
                    code = mfa_prompt()
                if not code:
                    raise AuthError(
                        code=-26,
                        message="Account requires 2FA; supply mfa_code or mfa_prompt",
                    ) from exc
                result = self.api.login_with_mfa(email, password_hash, code)
            else:
                raise

        # Steps 3 and 4: decrypt the master key, then derive the session ID.
        # The blobs come straight off the wire, so a wrong type, bad base64 or
        # a non-block-aligned payload is a malformed RESPONSE, not a bug here:
        # translate it into a typed AuthError instead of letting a raw
        # ValueError/binascii.Error reach the CLI catch-all.
        result = _expect_mapping(result, "login")
        try:
            encrypted_master_a32 = str_to_a32(_expect_field(result, "k", str, "login"))
            master_a32 = aes_cbc_decrypt_a32(encrypted_master_a32, bytes_to_a32(login_key))
            master_key = a32_to_bytes(master_a32)

            if "tsid" in result:
                sid = _expect_field(result, "tsid", str, "login")
                rsa_priv = None
            else:
                encrypted_rsa_priv = b64_url_decode(_expect_field(result, "privk", str, "login"))
                csid_encrypted = b64_url_decode(_expect_field(result, "csid", str, "login"))
                rsa_priv = aes_cbc_decrypt(encrypted_rsa_priv, master_key)
                sid = self._decode_session_id(csid_encrypted, rsa_priv)
        except MegaError:
            raise  # already typed and actionable
        except (ValueError, TypeError, IndexError) as exc:
            raise AuthError(
                message="MEGA returned malformed key material in the login response"
            ) from exc

        self.session = MegaSession(
            sid=sid,
            master_key=master_key,
            rsa_private_key=rsa_priv,
            user_handle=_expect_field(result, "u", str, "login", default=""),
            email=email,
        )
        self.api.set_session(sid)
        return self.session

    def restore_session(self, session: MegaSession) -> bool:
        """Restore a previously-saved session. Returns True if the SID still works."""
        self.api.set_session(session.sid)
        self.session = session
        try:
            self.api.get_user_info()
            return True
        except MegaError as exc:
            log.info("Saved session is no longer valid: %s", exc)
            self.api.clear_session()
            self.session = None
            return False

    def _decode_session_id(self, csid_encrypted: bytes, rsa_priv_blob: bytes) -> str:
        """Decode the session ID using the RSA private key (account v1/v2).

        The RSA private key is stored as four big-endian length-prefixed integers
        (p, q, d, u). We decrypt CSID with d/n and take the first 43 bytes.
        """
        parts = []
        cursor = 0
        for _ in range(4):
            if cursor + 2 > len(rsa_priv_blob):
                break
            bit_len = int.from_bytes(rsa_priv_blob[cursor : cursor + 2], "big")
            byte_len = (bit_len + 7) // 8
            cursor += 2
            parts.append(int.from_bytes(rsa_priv_blob[cursor : cursor + byte_len], "big"))
            cursor += byte_len

        if len(parts) < 4:
            raise AuthError(message="Malformed RSA private key in login response")

        p, q, d, _u = parts
        n = p * q
        decrypted = pow(int.from_bytes(csid_encrypted, "big"), d, n)
        decrypted_bytes = decrypted.to_bytes((n.bit_length() + 7) // 8, "big")
        if len(decrypted_bytes) < 43:
            raise AuthError(message="Malformed encrypted session ID in login response")
        return b64_url_encode(decrypted_bytes[:43])

    def close(self) -> None:
        """Release this client's HTTP resources WITHOUT invalidating the session.

        Used by parallel upload workers that share one server-side session:
        `logout()` would kill the sid for every other worker.
        """
        self.api.close()
        self.session = None
        self.invalidate_cache()

    def logout(self) -> None:
        """Invalidate the session AND release this client's HTTP resources.

        `logout()` is the end-of-life call: every caller discards the client
        immediately afterwards. It therefore closes the underlying
        `requests.Session` too, so the connection pool's sockets and TLS
        state are released rather than left to the garbage collector.

        Use `close()` instead when the server-side session must survive -
        parallel workers sharing one sid.
        """
        try:
            if self.session:
                with contextlib.suppress(MegaError):
                    self.api.request({"a": "sml"})
        finally:
            # Local cleanup is not conditional on the server cooperating. The
            # remote call can fail in ways that are not MegaError - Timeout,
            # ConnectionError, HTTPError, a non-JSON body, a crypto error -
            # and every one of those used to escape before the transport was
            # released, leaking the session logout() exists to free.
            self.api.clear_session()
            self.api.close()
            self.session = None
            self.invalidate_cache()

    # ------------------------------------------------------------------
    # User info / quota
    # ------------------------------------------------------------------
    def get_quota(self) -> dict[str, Any]:
        """Return storage and bandwidth quota for the current session."""
        if not self.session:
            raise AuthError(message="Not logged in")
        return self.api.get_account_quota()

    def get_user_info(self) -> dict[str, Any]:
        if not self.session:
            raise AuthError(message="Not logged in")
        return self.api.get_user_info()
