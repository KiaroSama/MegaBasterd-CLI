"""Regression tests for Crypter v2 cross-chunk sequence integrity (Priority 2).

These verify the authenticated MBCR v2 format rejects whole-chunk tampering
(truncation, reorder, duplication, deletion, append, header edits) and that
legacy v1 files remain decryptable.
"""

import os
import struct
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from megabasterd_cli.core import crypter
from megabasterd_cli.core.crypter import (
    MAGIC,
    NONCE_LEN,
    SALT_LEN,
    CrypterError,
    decrypt_file,
    encrypt_file,
)

PW = "correct horse battery staple"


def _parse_v2(blob: bytes) -> tuple[bytes, list[bytes]]:
    """Split a v2 blob into (header, [raw_chunk_records])."""
    header = blob[: 4 + 1 + SALT_LEN + 4 + 8]
    rest = blob[len(header) :]
    chunks: list[bytes] = []
    off = 0
    while off < len(rest):
        flag = rest[off]
        blen = struct.unpack(">I", rest[off + 1 : off + 5])[0]
        record = rest[off : off + 5 + blen]
        chunks.append(record)
        off += 5 + blen
        if flag == 1:
            break
    return header, chunks


def _write(path: Path, header: bytes, chunks: list[bytes]) -> None:
    path.write_bytes(header + b"".join(chunks))


def _make_multi(tmp_path: Path) -> tuple[Path, bytes]:
    src = tmp_path / "in.bin"
    enc = tmp_path / "in.enc"
    payload = os.urandom(200)  # 200 bytes / 16-byte chunks -> 13 chunks
    src.write_bytes(payload)
    encrypt_file(src, enc, PW, chunk_size=16)
    return enc, payload


# ---------------------------------------------------------------------------
# Valid round-trips
# ---------------------------------------------------------------------------


def test_v2_empty_file(tmp_path: Path) -> None:
    src = tmp_path / "e.bin"
    src.write_bytes(b"")
    enc = tmp_path / "e.enc"
    dec = tmp_path / "e.dec"
    encrypt_file(src, enc, PW)
    decrypt_file(enc, dec, PW)
    assert dec.read_bytes() == b""


def test_v2_single_chunk(tmp_path: Path) -> None:
    src = tmp_path / "s.bin"
    src.write_bytes(b"hello")
    enc = tmp_path / "s.enc"
    dec = tmp_path / "s.dec"
    encrypt_file(src, enc, PW, chunk_size=64 * 1024)
    decrypt_file(enc, dec, PW)
    assert dec.read_bytes() == b"hello"


def test_v2_multi_chunk_partial_final(tmp_path: Path) -> None:
    src = tmp_path / "m.bin"
    payload = os.urandom(300 * 1024 + 123)  # final chunk not a multiple
    src.write_bytes(payload)
    enc = tmp_path / "m.enc"
    dec = tmp_path / "m.dec"
    encrypt_file(src, enc, PW, chunk_size=64 * 1024)
    decrypt_file(enc, dec, PW)
    assert dec.read_bytes() == payload


# ---------------------------------------------------------------------------
# Tamper detection
# ---------------------------------------------------------------------------


def test_truncate_drops_final_chunk(tmp_path: Path) -> None:
    enc, _ = _make_multi(tmp_path)
    header, chunks = _parse_v2(enc.read_bytes())
    _write(enc, header, chunks[:-1])  # remove the final chunk
    with pytest.raises(CrypterError):
        decrypt_file(enc, tmp_path / "out", PW)


def test_forged_zero_terminator(tmp_path: Path) -> None:
    enc, _ = _make_multi(tmp_path)
    header, chunks = _parse_v2(enc.read_bytes())
    # Keep only the first chunk, then append a legacy-style zero terminator.
    enc.write_bytes(header + chunks[0] + b"\x00\x00\x00\x00\x00")
    with pytest.raises(CrypterError):
        decrypt_file(enc, tmp_path / "out", PW)


def test_reorder_chunks(tmp_path: Path) -> None:
    enc, _ = _make_multi(tmp_path)
    header, chunks = _parse_v2(enc.read_bytes())
    chunks[0], chunks[1] = chunks[1], chunks[0]
    _write(enc, header, chunks)
    with pytest.raises(CrypterError):
        decrypt_file(enc, tmp_path / "out", PW)


def test_duplicate_chunk(tmp_path: Path) -> None:
    enc, _ = _make_multi(tmp_path)
    header, chunks = _parse_v2(enc.read_bytes())
    chunks.insert(1, chunks[1])
    _write(enc, header, chunks)
    with pytest.raises(CrypterError):
        decrypt_file(enc, tmp_path / "out", PW)


def test_delete_middle_chunk(tmp_path: Path) -> None:
    enc, _ = _make_multi(tmp_path)
    header, chunks = _parse_v2(enc.read_bytes())
    del chunks[2]
    _write(enc, header, chunks)
    with pytest.raises(CrypterError):
        decrypt_file(enc, tmp_path / "out", PW)


def test_append_data_after_final(tmp_path: Path) -> None:
    enc, _ = _make_multi(tmp_path)
    data = enc.read_bytes()
    enc.write_bytes(data + os.urandom(32))
    with pytest.raises(CrypterError):
        decrypt_file(enc, tmp_path / "out", PW)


def test_modified_header_salt(tmp_path: Path) -> None:
    enc, _ = _make_multi(tmp_path)
    data = bytearray(enc.read_bytes())
    data[6] ^= 0xFF  # flip a salt byte (inside header, bound into every AAD)
    enc.write_bytes(bytes(data))
    with pytest.raises(CrypterError):
        decrypt_file(enc, tmp_path / "out", PW)


def test_modified_original_length(tmp_path: Path) -> None:
    enc, _ = _make_multi(tmp_path)
    data = bytearray(enc.read_bytes())
    # original length is the last 8 bytes of the 33-byte header
    data[4 + 1 + SALT_LEN + 4] ^= 0xFF
    enc.write_bytes(bytes(data))
    with pytest.raises(CrypterError):
        decrypt_file(enc, tmp_path / "out", PW)


def test_modified_final_flag(tmp_path: Path) -> None:
    enc, _ = _make_multi(tmp_path)
    header, chunks = _parse_v2(enc.read_bytes())
    last = bytearray(chunks[-1])
    last[0] = 0  # flip final flag 1 -> 0
    chunks[-1] = bytes(last)
    _write(enc, header, chunks)
    with pytest.raises(CrypterError):
        decrypt_file(enc, tmp_path / "out", PW)


def test_bitflip_inside_chunk(tmp_path: Path) -> None:
    enc, _ = _make_multi(tmp_path)
    data = bytearray(enc.read_bytes())
    data[len(data) // 2] ^= 0xFF
    enc.write_bytes(bytes(data))
    with pytest.raises(CrypterError):
        decrypt_file(enc, tmp_path / "out", PW)


# ---------------------------------------------------------------------------
# Legacy v1 compatibility
# ---------------------------------------------------------------------------


def _make_v1(path: Path, payload: bytes, passphrase: str, chunk_size: int) -> None:
    salt = os.urandom(SALT_LEN)
    kdf = Scrypt(
        salt=salt,
        length=crypter.KEY_LEN,
        n=crypter.SCRYPT_N,
        r=crypter.SCRYPT_R,
        p=crypter.SCRYPT_P,
    )
    key = kdf.derive(passphrase.encode("utf-8"))
    aes = AESGCM(key)
    with open(path, "wb") as f:
        f.write(MAGIC + bytes([1]) + salt + struct.pack(">I", chunk_size))
        for i in range(0, len(payload), chunk_size):
            pt = payload[i : i + chunk_size]
            nonce = os.urandom(NONCE_LEN)
            block = nonce + aes.encrypt(nonce, pt, None)
            f.write(struct.pack(">I", len(block)))
            f.write(block)
        f.write(struct.pack(">I", 0))


def test_legacy_v1_still_decryptable(tmp_path: Path) -> None:
    payload = os.urandom(150)
    enc = tmp_path / "legacy.enc"
    dec = tmp_path / "legacy.dec"
    _make_v1(enc, payload, PW, chunk_size=16)
    decrypt_file(enc, dec, PW)
    assert dec.read_bytes() == payload


def test_unsupported_version_rejected(tmp_path: Path) -> None:
    enc = tmp_path / "future.enc"
    enc.write_bytes(MAGIC + bytes([99]) + b"\x00" * 40)
    with pytest.raises(CrypterError, match="version"):
        decrypt_file(enc, tmp_path / "out", PW)
