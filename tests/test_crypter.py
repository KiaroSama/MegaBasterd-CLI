"""Tests for the local Crypter (pre-upload encryption / post-download decryption)."""

import os
from pathlib import Path

import pytest

from megabasterd_cli.core.crypter import CrypterError, decrypt_file, encrypt_file


def test_crypter_roundtrip_small(tmp_path: Path) -> None:
    src = tmp_path / "input.bin"
    enc = tmp_path / "input.enc"
    dec = tmp_path / "output.bin"

    payload = b"Hello, MegaBasterd CLI! " * 100
    src.write_bytes(payload)

    encrypt_file(src, enc, "secret-pass")
    decrypt_file(enc, dec, "secret-pass")

    assert dec.read_bytes() == payload
    # Encrypted file should be larger than plaintext but not absurdly so
    assert enc.stat().st_size > src.stat().st_size
    assert enc.stat().st_size < src.stat().st_size + 1024


def test_crypter_roundtrip_multi_chunk(tmp_path: Path) -> None:
    src = tmp_path / "big.bin"
    enc = tmp_path / "big.enc"
    dec = tmp_path / "big.dec"

    # 300 KB of random data spans multiple 64 KB chunks
    payload = os.urandom(300 * 1024)
    src.write_bytes(payload)

    encrypt_file(src, enc, "pw", chunk_size=64 * 1024)
    decrypt_file(enc, dec, "pw")

    assert dec.read_bytes() == payload


def test_crypter_wrong_passphrase_fails(tmp_path: Path) -> None:
    src = tmp_path / "x.bin"
    enc = tmp_path / "x.enc"
    dec = tmp_path / "x.dec"

    src.write_bytes(b"some data")
    encrypt_file(src, enc, "right-pass")
    with pytest.raises(CrypterError):
        decrypt_file(enc, dec, "wrong-pass")


def test_crypter_corrupted_file_fails(tmp_path: Path) -> None:
    src = tmp_path / "y.bin"
    enc = tmp_path / "y.enc"
    dec = tmp_path / "y.dec"

    src.write_bytes(b"original content " * 50)
    encrypt_file(src, enc, "pw")

    # Flip a single byte in the middle of the ciphertext
    data = bytearray(enc.read_bytes())
    data[len(data) // 2] ^= 0xFF
    enc.write_bytes(bytes(data))

    with pytest.raises(CrypterError):
        decrypt_file(enc, dec, "pw")


def test_crypter_rejects_non_crypter_file(tmp_path: Path) -> None:
    src = tmp_path / "plain.txt"
    src.write_bytes(b"this is not a crypter blob")
    out = tmp_path / "out.bin"
    with pytest.raises(CrypterError, match="magic"):
        decrypt_file(src, out, "pw")
