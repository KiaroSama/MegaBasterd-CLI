"""A vault blob carries its own KDF parameters, so the cost can be raised.

The scrypt cost used to be a hard-coded constant, which meant it could never be
increased: every stored credential had been written under the old value and
nothing in the blob recorded that. A blob now starts with a version byte plus
`log2n, r, p`, and the default is raised to 2**15.

The pre-version layout is deliberately unsupported - re-adding an account takes
seconds, which is not worth a second decryption path forever. What these tests
do require is that such a blob is reported as an old FORMAT, not as a wrong
passphrase, so the user is not sent hunting for a problem that is not there.
"""

from __future__ import annotations

import base64
import os

import pytest

from megabasterd_cli.accounts.storage import CredentialVault, VaultUnlockError

PASSPHRASE = "correct horse battery staple"
SECRET = "my-mega-password"


def _legacy_blob(passphrase: str, plaintext: str) -> str:
    """The pre-version layout: bare base64(salt || nonce || ct), implicit 2**14."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    salt, nonce = os.urandom(16), os.urandom(12)
    key = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(passphrase.encode("utf-8"))
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(salt + nonce + ct).decode("ascii")


def test_a_credential_round_trips():
    vault = CredentialVault(PASSPHRASE)
    assert vault.decrypt(vault.encrypt(SECRET)) == SECRET


def test_the_blob_records_the_version_and_the_cost_it_was_written_with():
    """This header is the whole point: without it the cost can never change."""
    raw = base64.b64decode(CredentialVault(PASSPHRASE).encrypt(SECRET))
    assert raw[0] == CredentialVault.VERSION
    assert raw[1] == 15, "the default cost should be 2**15"
    assert (raw[2], raw[3]) == (8, 1)


def test_a_blob_written_at_a_different_cost_still_opens():
    """Proves the parameters are honoured, not assumed - the forward path."""
    writer = CredentialVault(PASSPHRASE)
    writer.SCRYPT_N = 2**12  # instance override, not the class default
    blob = writer.encrypt(SECRET)
    assert base64.b64decode(blob)[1] == 12
    # A reader on the current default must follow the blob, not its own constant.
    assert CredentialVault(PASSPHRASE).decrypt(blob) == SECRET


def test_an_older_format_blob_is_reported_as_such_not_as_a_bad_passphrase():
    with pytest.raises(VaultUnlockError, match="older vault format"):
        CredentialVault(PASSPHRASE).decrypt(_legacy_blob(PASSPHRASE, SECRET))


def test_the_wrong_passphrase_is_still_reported_as_a_wrong_passphrase():
    blob = CredentialVault(PASSPHRASE).encrypt(SECRET)
    with pytest.raises(VaultUnlockError, match="passphrase"):
        CredentialVault("not-the-passphrase").decrypt(blob)


@pytest.mark.parametrize("log2n", [0, 9, 23, 64, 255])
def test_a_hostile_cost_in_the_file_is_refused_before_deriving(log2n):
    """The vault file is user-writable, so its parameters are untrusted.

    `n = 1 << log2n` with an unchecked byte reaches 2**255 and would hang the
    process allocating - the same shape as a hostile PBKDF2 iteration count.
    """
    body = bytes([CredentialVault.VERSION, log2n, 8, 1]) + b"\x00" * 44
    with pytest.raises(ValueError, match="out of range"):
        CredentialVault(PASSPHRASE).decrypt(base64.b64encode(body).decode("ascii"))


@pytest.mark.parametrize(("r", "p"), [(0, 1), (33, 1), (8, 0), (8, 17)])
def test_hostile_r_and_p_are_refused_too(r, p):
    body = bytes([CredentialVault.VERSION, 15, r, p]) + b"\x00" * 44
    with pytest.raises(ValueError, match="out of range"):
        CredentialVault(PASSPHRASE).decrypt(base64.b64encode(body).decode("ascii"))


def test_the_derived_key_is_cached_per_parameter_set():
    """scrypt is expensive on purpose; one unlock decrypts a credential twice."""
    vault = CredentialVault(PASSPHRASE)
    blob = vault.encrypt(SECRET)
    seen = []
    original = vault._derive

    def counting(salt, n, r, p):
        seen.append((salt, n, r, p))
        return original(salt, n, r, p)

    vault._derive = counting  # type: ignore[method-assign]
    vault.decrypt(blob)
    vault.decrypt(blob)
    assert len(seen) == 2, "both reads go through _derive"
    assert len(set(seen)) == 1, "and share one parameter set, so scrypt runs once"
