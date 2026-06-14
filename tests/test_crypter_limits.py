"""MBCR v2 parser/KDF resource-limit tests (Issue 2).

The MBCR v2 format does not embed KDF parameters, so scrypt parameters are not
attacker-controlled; these tests validate the defensive parameter checks and
the header-field bounds that ARE attacker-controlled (chunk size, declared
chunk length, original length), proving validation happens before the KDF runs.
"""

import struct
from pathlib import Path

import pytest

from megabasterd_cli.core import crypter
from megabasterd_cli.core.crypter import (
    MAGIC,
    SALT_LEN,
    CrypterError,
    _validate_scrypt_params,
    decrypt_file,
    encrypt_file,
)

PW = "pw"


# ---------------------------------------------------------------------------
# scrypt parameter validation
# ---------------------------------------------------------------------------


def test_scrypt_params_valid_defaults_pass() -> None:
    _validate_scrypt_params(crypter.SCRYPT_N, crypter.SCRYPT_R, crypter.SCRYPT_P)


@pytest.mark.parametrize(
    "n,r,p",
    [
        (2**30, 8, 1),  # N too large
        (12345, 8, 1),  # N not a power of two
        (0, 8, 1),  # N zero
        (-1, 8, 1),  # N negative
        (2**14, 0, 1),  # r too small
        (2**14, 1000, 1),  # r too large
        (2**14, 8, 0),  # p too small
        (2**14, 8, 1000),  # p too large
        (2**20, 32, 16),  # combined memory cost too high
    ],
)
def test_scrypt_params_invalid_rejected(n: int, r: int, p: int) -> None:
    with pytest.raises(CrypterError):
        _validate_scrypt_params(n, r, p)


# ---------------------------------------------------------------------------
# header bound validation happens before the KDF / chunk processing
# ---------------------------------------------------------------------------


def _v2_header(chunk_size: int, orig_len: int, salt: bytes = b"\x00" * SALT_LEN) -> bytes:
    return MAGIC + bytes([2]) + salt + struct.pack(">I", chunk_size) + struct.pack(">Q", orig_len)


def test_impossible_original_length_rejected_before_kdf(tmp_path: Path, monkeypatch) -> None:
    # Header claims a plaintext far larger than the file itself.
    enc = tmp_path / "x.enc"
    enc.write_bytes(_v2_header(16, 2**40))

    called = {"derive": False}

    def boom(*a, **k):
        called["derive"] = True
        raise AssertionError("_derive_key must not run for an invalid header")

    monkeypatch.setattr(crypter, "_derive_key", boom)
    with pytest.raises(CrypterError, match="exceeds the encrypted file size"):
        decrypt_file(enc, tmp_path / "out", PW)
    assert called["derive"] is False


def test_zero_chunk_size_rejected_before_kdf(tmp_path: Path, monkeypatch) -> None:
    enc = tmp_path / "z.enc"
    enc.write_bytes(_v2_header(0, 0))
    monkeypatch.setattr(
        crypter,
        "_derive_key",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("KDF should not run")),
    )
    with pytest.raises(CrypterError, match="chunk size"):
        decrypt_file(enc, tmp_path / "out", PW)


def test_oversized_chunk_size_rejected_before_kdf(tmp_path: Path, monkeypatch) -> None:
    enc = tmp_path / "o.enc"
    enc.write_bytes(_v2_header((1 << 24) + 1, 0))
    monkeypatch.setattr(
        crypter,
        "_derive_key",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("KDF should not run")),
    )
    with pytest.raises(CrypterError, match="chunk size"):
        decrypt_file(enc, tmp_path / "out", PW)


def test_oversized_declared_chunk_length_rejected(tmp_path: Path) -> None:
    header = _v2_header(16, 0)
    blob = header + bytes([1]) + struct.pack(">I", 0xFFFFFFFF) + b"\x00" * 8
    enc = tmp_path / "huge.enc"
    enc.write_bytes(blob)
    with pytest.raises(CrypterError, match="exceeds header chunk size"):
        decrypt_file(enc, tmp_path / "out", PW)


def test_valid_roundtrip_unaffected(tmp_path: Path) -> None:
    src = tmp_path / "in.bin"
    src.write_bytes(b"payload " * 50)
    enc = tmp_path / "in.enc"
    dec = tmp_path / "in.dec"
    encrypt_file(src, enc, PW)
    decrypt_file(enc, dec, PW)
    assert dec.read_bytes() == src.read_bytes()
