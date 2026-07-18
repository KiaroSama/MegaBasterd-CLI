"""Regression tests: a failed encrypt/decrypt must not damage the destination.

P1-05: the crypter opened the destination with "wb" before doing any work, so a
wrong passphrase (or any mid-stream failure) truncated an existing destination
file to zero and left it destroyed. It also read a raw u32 length from a v1 blob
without bounding it against the header chunk size.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from megabasterd_cli.core.crypter import (
    MAGIC,
    NONCE_LEN,
    SALT_LEN,
    CrypterError,
    decrypt_file,
    encrypt_file,
)

PW = "correct horse battery staple"
IMPORTANT = b"irreplaceable user data\n" * 40


def _tmp_leftovers(directory: Path) -> list[Path]:
    return [p for p in directory.iterdir() if p.name.endswith(".mbcr-tmp")]


def test_failed_decrypt_preserves_destination(tmp_path: Path) -> None:
    """A wrong passphrase must leave the existing destination file intact."""
    plain = tmp_path / "plain.txt"
    plain.write_bytes(b"secret payload" * 100)
    enc = tmp_path / "blob.mbcr"
    encrypt_file(plain, enc, PW)

    dst = tmp_path / "important.txt"
    dst.write_bytes(IMPORTANT)

    with pytest.raises(CrypterError):
        decrypt_file(enc, dst, "wrong passphrase")

    assert dst.read_bytes() == IMPORTANT
    assert _tmp_leftovers(tmp_path) == []


def test_failed_v1_decrypt_preserves_destination(tmp_path: Path) -> None:
    """The legacy v1 path must be atomic too."""
    enc = tmp_path / "legacy.mbcr"
    # v1 header + one chunk record that fails authentication.
    enc.write_bytes(
        MAGIC
        + bytes([1])
        + b"\x00" * SALT_LEN
        + struct.pack(">I", 64)
        + struct.pack(">I", NONCE_LEN + 16)
        + b"\x00" * (NONCE_LEN + 16)
    )

    dst = tmp_path / "important.txt"
    dst.write_bytes(IMPORTANT)

    with pytest.raises(CrypterError):
        decrypt_file(enc, dst, PW)

    assert dst.read_bytes() == IMPORTANT
    assert _tmp_leftovers(tmp_path) == []


def test_failed_encrypt_preserves_destination(tmp_path: Path, monkeypatch) -> None:
    """A mid-stream encrypt failure must not clobber the destination either."""
    src = tmp_path / "src.bin"
    src.write_bytes(b"x" * (64 * 1024 * 3))

    dst = tmp_path / "important.txt"
    dst.write_bytes(IMPORTANT)

    import megabasterd_cli.core.crypter as crypter

    real_urandom = crypter.os.urandom
    calls = {"n": 0}

    def flaky_urandom(n: int) -> bytes:
        calls["n"] += 1
        if calls["n"] > 3:  # salt + a couple of nonces, then fail mid-stream
            raise OSError("entropy source failed")
        return real_urandom(n)

    monkeypatch.setattr(crypter.os, "urandom", flaky_urandom)

    with pytest.raises(OSError):
        encrypt_file(src, dst, PW)

    assert dst.read_bytes() == IMPORTANT
    assert _tmp_leftovers(tmp_path) == []


def test_successful_decrypt_still_overwrites(tmp_path: Path) -> None:
    """Atomicity must not break the normal overwrite path."""
    plain = tmp_path / "plain.txt"
    payload = b"new content" * 500
    plain.write_bytes(payload)
    enc = tmp_path / "blob.mbcr"
    encrypt_file(plain, enc, PW)

    dst = tmp_path / "existing.txt"
    dst.write_bytes(IMPORTANT)
    decrypt_file(enc, dst, PW)

    assert dst.read_bytes() == payload
    assert _tmp_leftovers(tmp_path) == []


def test_v1_oversized_declared_chunk_length_rejected(tmp_path: Path) -> None:
    """A v1 blob claiming a 4 GiB chunk must be rejected, not read into memory."""
    blob = (
        MAGIC
        + bytes([1])
        + b"\x00" * SALT_LEN
        + struct.pack(">I", 16)  # header chunk size
        + struct.pack(">I", 0xFFFFFFFF)  # declared block length
        + b"\x00" * 8  # but only 8 bytes actually present
    )
    assert len(blob) == 37  # tiny file, 4 GiB claim
    enc = tmp_path / "huge_v1.mbcr"
    enc.write_bytes(blob)

    with pytest.raises(CrypterError, match="exceeds header chunk size"):
        decrypt_file(enc, tmp_path / "out.bin", PW)
