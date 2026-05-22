"""Tests for the MEGA crypto helpers."""

import os

from megabasterd_cli.core.crypto import (
    a32_to_bytes,
    aes_cbc_decrypt,
    aes_cbc_encrypt,
    b64_url_decode,
    b64_url_encode,
    bytes_to_a32,
    decrypt_attributes,
    make_ctr_cipher,
    pack_file_key,
    unpack_file_key,
)


def test_a32_roundtrip():
    data = os.urandom(64)
    assert a32_to_bytes(bytes_to_a32(data)) == data


def test_b64_url_roundtrip():
    for _ in range(10):
        raw = os.urandom(33)
        assert b64_url_decode(b64_url_encode(raw)) == raw


def test_aes_cbc_roundtrip():
    key = os.urandom(16)
    plaintext = os.urandom(64)
    ct = aes_cbc_encrypt(plaintext, key)
    assert aes_cbc_decrypt(ct, key) == plaintext


def test_decrypt_attributes_rejects_wrong_length_blob():
    assert decrypt_attributes(b"hello", b"\0" * 16) is None


def test_file_key_pack_unpack():
    key_a32 = bytes_to_a32(os.urandom(32))
    aes_key, nonce, mac_iv = unpack_file_key(key_a32)
    repacked = pack_file_key(aes_key, nonce, mac_iv)
    assert repacked == key_a32


def test_ctr_cipher_basic():
    key = os.urandom(16)
    nonce = os.urandom(8)
    cipher_enc = make_ctr_cipher(key, nonce, initial_value=0)
    cipher_dec = make_ctr_cipher(key, nonce, initial_value=0)
    plaintext = b"A" * 64
    encrypted = cipher_enc.encrypt(plaintext)
    decrypted = cipher_dec.decrypt(encrypted)
    assert decrypted == plaintext


def test_ctr_offset_decryption():
    """Decrypting an offset chunk with the right counter yields the original bytes."""
    key = os.urandom(16)
    nonce = os.urandom(8)
    plaintext = b"X" * 256
    # Encrypt the whole thing
    full = make_ctr_cipher(key, nonce, initial_value=0).encrypt(plaintext)
    # Decrypt only the last 128 bytes with the corresponding counter
    decrypted_tail = make_ctr_cipher(
        key,
        nonce,
        initial_value=128 // 16,
    ).decrypt(full[128:])
    assert decrypted_tail == plaintext[128:]
