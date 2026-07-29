"""Login must unwrap the RSA private key the way MEGA wrapped it.

MEGA encrypts key material BLOCK BY BLOCK with a zero IV (ECB semantics), not
as one chained CBC stream. `login()` used chained `aes_cbc_decrypt` for `privk`,
so only the first 16 bytes came back correct and the rest was garbage: the four
length-prefixed MPIs no longer parsed and every real login died with
"Malformed RSA private key in login response".

It survived because the master key `k` is a single AES block, where chained and
per-block decryption are identical - so login appeared to work right up to the
point it used a multi-block blob. Nothing exercised the RSA branch: the live
account flows were never validated, and the rest of the codebase already used
`aes_key_wrap_decrypt` everywhere else (`nodes.py` even documents the rule).

These tests build a real RSA key, wrap it exactly as MEGA does, and drive the
real `login()` against a stub transport.
"""

from __future__ import annotations

import pytest
from Crypto.PublicKey import RSA

from megabasterd_cli.core.auth import AuthError
from megabasterd_cli.core.client import MegaClient
from megabasterd_cli.core.crypto import (
    a32_to_bytes,
    aes_key_wrap_encrypt,
    b64_url_encode,
    derive_key_legacy,
)

EMAIL = "user@example.com"
PASSWORD = "correct horse battery staple"


def _mpi(value: int) -> bytes:
    """MEGA's MPI encoding: 2-byte BIT length, big-endian, then the bytes."""
    byte_len = (value.bit_length() + 7) // 8
    return value.bit_length().to_bytes(2, "big") + value.to_bytes(byte_len, "big")


@pytest.fixture(scope="module")
def rsa_key():
    # 2048-bit so the decoded session id comfortably exceeds the 43-byte floor.
    return RSA.generate(2048)


def _csid_plaintext(rsa_key, session_id: bytes) -> bytes:
    """The block MEGA encrypts: the session id FIRST, filling the modulus.

    One byte short of the modulus so the value stays below n, and the leading
    byte is forced non-zero - that is what makes the sid land at offset 0 of the
    decrypted block, which is the whole reason the reader takes `[:43]`.
    """
    width = (rsa_key.n.bit_length() + 7) // 8 - 1
    assert len(session_id) <= width
    block = bytearray(session_id + b"\xab" * (width - len(session_id)))
    block[0] |= 0x80
    return bytes(block)


def _login_response(rsa_key, master_key: bytes, session_id: bytes) -> dict:
    """A login reply built the way the real server builds one."""
    login_key = a32_to_bytes(derive_key_legacy(PASSWORD))

    # p, q, d, u - each an MPI, the whole blob wrapped with the master key.
    blob = _mpi(rsa_key.p) + _mpi(rsa_key.q) + _mpi(rsa_key.d) + _mpi(rsa_key.u)
    blob += b"\x00" * (-len(blob) % 16)

    # CSID is that block encrypted to the account's PUBLIC key.
    plaintext = _csid_plaintext(rsa_key, session_id)
    csid = pow(int.from_bytes(plaintext, "big"), rsa_key.e, rsa_key.n)
    csid_bytes = csid.to_bytes((rsa_key.n.bit_length() + 7) // 8, "big")

    return {
        "k": b64_url_encode(aes_key_wrap_encrypt(master_key, login_key)),
        "privk": b64_url_encode(aes_key_wrap_encrypt(blob, master_key)),
        "csid": b64_url_encode(csid_bytes),
        "u": "user-handle",
    }


class _StubApi:
    """Just enough transport to drive `login()` offline."""

    def __init__(self, reply: dict):
        self._reply = reply
        self.session_set_to: str | None = None

    def request(self, payload, extra_params=None):
        if payload.get("a") == "us0":
            return {"v": 1, "s": ""}  # legacy account: no PBKDF2 salt
        if payload.get("a") == "us":
            return dict(self._reply)
        raise AssertionError(f"unexpected request: {payload}")

    def set_session(self, sid):
        self.session_set_to = sid

    def close(self):
        pass


def test_login_decodes_the_session_id_from_a_multi_block_rsa_key(rsa_key):
    """The regression: a real privk is ~41 AES blocks, not one."""
    master_key = bytes(range(16))
    session_id = bytes(range(43, 43 + 64))  # >43 bytes, as the server sends

    api = _StubApi(_login_response(rsa_key, master_key, session_id))
    client = MegaClient(api=api)

    session = client.login(EMAIL, PASSWORD)

    assert session.master_key == master_key
    # The sid is the first 43 bytes of the RSA-decrypted CSID block.
    expected = _csid_plaintext(rsa_key, session_id)[:43]
    assert session.sid == b64_url_encode(expected)
    assert api.session_set_to == session.sid
    assert session.email == EMAIL


def test_a_privk_wrapped_the_wrong_way_is_reported_not_silently_accepted(rsa_key):
    """Guard the failure path too: garbage must raise, never produce a bad sid."""
    from megabasterd_cli.core.crypto import aes_cbc_encrypt

    master_key = bytes(range(16))
    reply = _login_response(rsa_key, master_key, bytes(range(43, 43 + 64)))

    blob = _mpi(rsa_key.p) + _mpi(rsa_key.q) + _mpi(rsa_key.d) + _mpi(rsa_key.u)
    blob += b"\x00" * (-len(blob) % 16)
    # Chained CBC is exactly what a mismatched implementation produces.
    reply["privk"] = b64_url_encode(aes_cbc_encrypt(blob, master_key))

    client = MegaClient(api=_StubApi(reply))
    with pytest.raises(AuthError, match="RSA private key|malformed key material"):
        client.login(EMAIL, PASSWORD)
