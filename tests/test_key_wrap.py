"""Regression tests for key-wrap encryption (the AES mode MEGA uses for node keys).

The bug this guards against: a 32-byte file key wrapped/unwrapped with
chained AES-CBC instead of the per-16-byte ECB-style key-wrap mode that
MEGA actually uses. With the wrong mode, the unpacked AES content key is
garbage and attribute decryption silently produces None, files appear with
their handle as filename, and CBC-MAC verification fails.
"""

import os

import pytest

from megabasterd_cli.core.crypto import (
    aes_cbc_encrypt,
    aes_key_wrap_decrypt,
    aes_key_wrap_encrypt,
)


def test_key_wrap_roundtrip_16_bytes():
    key = os.urandom(16)
    data = os.urandom(16)
    enc = aes_key_wrap_encrypt(data, key)
    assert aes_key_wrap_decrypt(enc, key) == data


def test_key_wrap_roundtrip_32_bytes():
    key = os.urandom(16)
    data = os.urandom(32)
    enc = aes_key_wrap_encrypt(data, key)
    assert aes_key_wrap_decrypt(enc, key) == data


def test_key_wrap_differs_from_chained_cbc_for_multiblock():
    """The whole point of the fix: for >16 bytes, key-wrap MUST differ from CBC."""
    key = os.urandom(16)
    data = os.urandom(32)
    wrap = aes_key_wrap_encrypt(data, key)
    cbc = aes_cbc_encrypt(data, key)
    # First 16 bytes are identical (first CBC block with zero IV == ECB).
    assert wrap[:16] == cbc[:16]
    # Second 16 bytes MUST differ: CBC XORs in the previous ciphertext block,
    # key-wrap encrypts independently with zero IV.
    assert wrap[16:] != cbc[16:]


def test_key_wrap_blocks_are_independent():
    """Each 16-byte block can be decrypted in isolation."""
    key = os.urandom(16)
    a = os.urandom(16)
    b = os.urandom(16)
    enc = aes_key_wrap_encrypt(a + b, key)
    assert aes_key_wrap_decrypt(enc[:16], key) == a
    assert aes_key_wrap_decrypt(enc[16:], key) == b


def test_key_wrap_rejects_non_block_aligned_input():
    key = os.urandom(16)
    with pytest.raises(ValueError):
        aes_key_wrap_encrypt(b"\x00" * 7, key)
    with pytest.raises(ValueError):
        aes_key_wrap_decrypt(b"\x00" * 7, key)
