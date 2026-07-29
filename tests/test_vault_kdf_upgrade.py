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
import re

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


def test_reading_a_stale_credential_still_names_the_format_not_the_passphrase(tmp_path):
    """Whoever asks for the password of a stale account gets the real reason.

    `add_account` no longer refuses over one of these - see
    `test_an_unreadable_credential_does_not_block_adding_a_new_one` - but the
    read path must still say "older format", never "wrong passphrase", or the
    user is sent hunting for a problem that is not there.
    """
    from megabasterd_cli.accounts.manager import AccountManager

    path = _vault_file(tmp_path, ("old@example.com", _legacy_blob(PASSPHRASE, SECRET)))
    manager = AccountManager(path)
    manager.unlock(PASSPHRASE)
    with pytest.raises(VaultUnlockError, match="older vault format"):
        manager.get_password("old@example.com")


def test_a_genuinely_wrong_passphrase_is_still_reported_as_one(tmp_path):
    """The generic message must survive for the case it was written for."""
    from megabasterd_cli.accounts.manager import AccountManager

    path = tmp_path / "accounts.json"
    writer = AccountManager(path)
    writer.unlock(PASSPHRASE)
    writer.add_account("a@example.com", "pw")

    reader = AccountManager(path)
    reader.unlock("not-the-passphrase")
    with pytest.raises(VaultUnlockError, match="Wrong vault passphrase"):
        reader.add_account("b@example.com", "pw")


# ---------------------------------------------------------------------------
# Recovering a vault whose credentials predate the format
# ---------------------------------------------------------------------------


def _vault_file(tmp_path, *entries):
    import json

    path = tmp_path / "accounts.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "default_email": entries[0][0] if entries else None,
                "accounts": [{"email": e, "enc_password": b} for e, b in entries],
            }
        ),
        encoding="utf-8",
    )
    return path


def test_the_old_format_is_not_reported_with_an_invented_version_number():
    """Byte 0 of a pre-v2 blob is a random SALT byte, not a version.

    Printing it as `v85`/`v56` - a different number every time, from the same
    file - reads like a real format generation and sends the reader looking for
    one that never existed.
    """
    with pytest.raises(VaultUnlockError) as excinfo:
        CredentialVault(PASSPHRASE).decrypt(_legacy_blob(PASSPHRASE, SECRET))
    assert "older vault format" in str(excinfo.value)
    assert not re.search(r"\(v\d+\)", str(excinfo.value)), str(excinfo.value)


def test_an_unreadable_credential_does_not_block_adding_a_new_one(tmp_path):
    """The guard exists to stop the vault splitting across two passphrases.

    A credential no passphrase can open is not evidence about the passphrase -
    there is nothing to be consistent WITH. Refusing on that basis leaves the
    vault unrecoverable through the normal path: the user cannot add anything
    until they have removed every stale entry one confirmation at a time.
    """
    from megabasterd_cli.accounts.manager import AccountManager

    path = _vault_file(tmp_path, ("old@example.com", _legacy_blob(PASSPHRASE, SECRET)))
    manager = AccountManager(path)
    manager.unlock(PASSPHRASE)

    manager.add_account("new@example.com", "pw")
    assert manager.get_password("new@example.com") == "pw"


def test_re_adding_the_account_you_can_no_longer_decrypt_replaces_it(tmp_path):
    """The exact recovery path: same email, dead credential.

    The duplicate check refused, so the advice "remove the account and add it
    again" was the ONLY way through - two commands and a confirmation prompt to
    repair something the second command already knows how to repair. Replacing
    is safe precisely because the stored credential is provably unusable.
    """
    from megabasterd_cli.accounts.manager import AccountManager

    path = _vault_file(tmp_path, ("me@example.com", _legacy_blob(PASSPHRASE, SECRET)))
    manager = AccountManager(path)
    manager.unlock(PASSPHRASE)

    manager.add_account("me@example.com", "new-password")

    assert len(manager.list_accounts()) == 1, "it must replace, not duplicate"
    assert manager.get_password("me@example.com") == "new-password"


def test_the_account_being_repaired_is_not_named_in_the_stale_warning(tmp_path, caplog):
    """Reported from a real repair, and the warning is the whole output.

    The count was taken BEFORE the replacement, so repairing the only stale
    credential still printed "add those accounts again to replace them" - about
    the very add in progress. The user reads that as "it did not work" and does
    it a second time.
    """
    import logging

    from megabasterd_cli.accounts.manager import AccountManager

    path = _vault_file(tmp_path, ("me@example.com", _legacy_blob(PASSPHRASE, SECRET)))
    manager = AccountManager(path)
    manager.unlock(PASSPHRASE)

    with caplog.at_level(logging.WARNING):
        manager.add_account("me@example.com", "new-password")

    assert "predate the current vault format" not in caplog.text, caplog.text


def test_a_stale_credential_left_behind_is_still_warned_about(tmp_path, caplog):
    """The warning must survive for the case it exists for."""
    import logging

    from megabasterd_cli.accounts.manager import AccountManager

    path = _vault_file(
        tmp_path,
        ("me@example.com", _legacy_blob(PASSPHRASE, SECRET)),
        ("other@example.com", _legacy_blob(PASSPHRASE, SECRET)),
    )
    manager = AccountManager(path)
    manager.unlock(PASSPHRASE)

    with caplog.at_level(logging.WARNING):
        manager.add_account("me@example.com", "new-password")

    assert "1 other stored credential(s) predate" in caplog.text, caplog.text


def test_a_readable_duplicate_is_still_refused(tmp_path):
    """Replacement is for dead credentials only, never a working one."""
    from megabasterd_cli.accounts.manager import AccountManager

    path = tmp_path / "accounts.json"
    manager = AccountManager(path)
    manager.unlock(PASSPHRASE)
    manager.add_account("me@example.com", "pw")

    with pytest.raises(ValueError, match="already exists"):
        manager.add_account("me@example.com", "other")


def test_a_readable_credential_still_guards_the_passphrase(tmp_path):
    """A stale entry must not disable the guard for the readable ones."""
    from megabasterd_cli.accounts.manager import AccountManager

    writer = CredentialVault(PASSPHRASE)
    path = _vault_file(
        tmp_path,
        ("old@example.com", _legacy_blob(PASSPHRASE, SECRET)),
        ("good@example.com", writer.encrypt(SECRET)),
    )
    manager = AccountManager(path)
    manager.unlock("not-the-passphrase")

    with pytest.raises(VaultUnlockError, match="Wrong vault passphrase"):
        manager.add_account("new@example.com", "pw")
