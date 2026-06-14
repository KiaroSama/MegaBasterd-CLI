"""Local file Crypter: encrypt local files before upload, decrypt after download.

This is the analogue of the "Crypter" feature in the original MegaBasterd: a
passphrase-based additional layer of encryption applied to files before they
are uploaded to MEGA (or any cloud). It does NOT replace MEGA's own AES-CTR
encryption — it stacks on top of it.

Two on-disk formats exist:

Version 2 (current, authenticated sequence)
-------------------------------------------
Header::

    +--------+--------+----------+-----------------+--------------------+
    | "MBCR" | ver=2  | salt(16) | chunk_size(4be) | orig_length(8be)   |
    +--------+--------+----------+-----------------+--------------------+

Then a sequence of chunks (no separate terminator; the final chunk is flagged)::

    +--------+-----------+-----------+--------------+
    | flag(1)| blen(4be) | nonce(12) | ct+tag       |
    +--------+-----------+-----------+--------------+

`flag` is 1 for the final chunk, 0 otherwise. `blen` is the length of
`nonce || ciphertext+tag`. Each chunk is AES-256-GCM encrypted with the
*associated data* ``header || pack(chunk_index, flag)``. Because the full
header (including the original file length), the monotonic chunk index, and
the final-chunk flag are all authenticated, the decryptor detects whole-chunk
truncation, reordering, duplication, omission, appended data, and any header
tampering — not just bit flips inside a single chunk. An empty file is encoded
as exactly one final chunk with empty plaintext.

Version 1 (legacy, read-only)
-----------------------------
Header ``"MBCR" | ver=1 | salt(16) | chunk_size(4be)`` followed by
``len(4be) | nonce(12) | ct+tag`` chunks terminated by a zero-length prefix.
Each chunk was authenticated individually with no associated data, so v1 files
have per-chunk authenticity but NOT whole-file sequence integrity. They remain
decryptable for backward compatibility; new files are always written as v2.

The key is derived from the passphrase via scrypt; the salt is stored in the
header so the same passphrase produces a different key for each file.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path
from typing import Callable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"MBCR"
VERSION = 2  # Version written by encrypt_file
VERSION_LEGACY = 1  # Still accepted by decrypt_file
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
DEFAULT_CHUNK_SIZE = 64 * 1024  # 64 KB plaintext per chunk

SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LEN = 32

_V1_HEADER_LEN = len(MAGIC) + 1 + SALT_LEN + 4
_V2_HEADER_LEN = len(MAGIC) + 1 + SALT_LEN + 4 + 8
# Associated data appended per chunk: chunk index (u64) + final flag (u8).
_CHUNK_AAD = struct.Struct(">QB")


class CrypterError(Exception):
    """Raised on any encrypt/decrypt failure."""


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_file(
    src: Path,
    dst: Path,
    passphrase: str,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    on_progress: Callable[[int, int], None] | None = None,
) -> None:
    """Encrypt `src` into `dst` with a passphrase using chunked AES-256-GCM (v2)."""
    if chunk_size <= 0 or chunk_size > (1 << 24):
        raise CrypterError("chunk_size must be between 1 and 16 MiB")

    salt = os.urandom(SALT_LEN)
    key = _derive_key(passphrase, salt)
    aes = AESGCM(key)

    src_size = src.stat().st_size
    header = MAGIC + bytes([VERSION]) + salt + struct.pack(">I", chunk_size) + struct.pack(
        ">Q", src_size
    )

    written = 0
    index = 0
    dst.parent.mkdir(parents=True, exist_ok=True)
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        fout.write(header)

        def _write_chunk(idx: int, final: bool, plaintext: bytes) -> None:
            nonce = os.urandom(NONCE_LEN)
            aad = header + _CHUNK_AAD.pack(idx, 1 if final else 0)
            ciphertext = aes.encrypt(nonce, plaintext, aad)
            block = nonce + ciphertext
            fout.write(bytes([1 if final else 0]))
            fout.write(struct.pack(">I", len(block)))
            fout.write(block)

        # Read one chunk ahead so we know which chunk is the last one. An empty
        # file becomes a single final chunk with empty plaintext.
        prev = fin.read(chunk_size)
        if not prev:
            _write_chunk(index, True, b"")
            if on_progress:
                on_progress(0, src_size)
            return
        while True:
            nxt = fin.read(chunk_size)
            final = not nxt
            _write_chunk(index, final, prev)
            written += len(prev)
            index += 1
            if on_progress:
                on_progress(written, src_size)
            if final:
                break
            prev = nxt


def _read_exact(fin, n: int, what: str) -> bytes:
    data = fin.read(n)
    if len(data) < n:
        raise CrypterError(f"Truncated file ({what})")
    return data


def _decrypt_v2(
    fin,
    dst: Path,
    passphrase: str,
    on_progress: Callable[[int, int], None] | None,
    src_size: int,
    header_prefix: bytes,
) -> None:
    """Decrypt a version-2 authenticated Crypter stream."""
    salt = _read_exact(fin, SALT_LEN, "missing salt")
    chunk_size_bytes = _read_exact(fin, 4, "missing chunk size")
    orig_len_bytes = _read_exact(fin, 8, "missing length")
    chunk_size = struct.unpack(">I", chunk_size_bytes)[0]
    original_length = struct.unpack(">Q", orig_len_bytes)[0]
    if chunk_size <= 0 or chunk_size > (1 << 24):
        raise CrypterError("Invalid chunk size in header")

    header = header_prefix + salt + chunk_size_bytes + orig_len_bytes
    key = _derive_key(passphrase, salt)
    aes = AESGCM(key)

    dst.parent.mkdir(parents=True, exist_ok=True)
    decrypted = 0
    index = 0
    seen_final = False
    with open(dst, "wb") as fout:
        while True:
            flag_byte = fin.read(1)
            if not flag_byte:
                # EOF before a chunk flagged final -> truncated/missing tail.
                raise CrypterError("Truncated file (missing final chunk)")
            flag = flag_byte[0]
            if flag not in (0, 1):
                raise CrypterError("Corrupt chunk flag")
            blen = struct.unpack(">I", _read_exact(fin, 4, "missing length prefix"))[0]
            if blen < NONCE_LEN + TAG_LEN:
                raise CrypterError("Corrupt chunk length")
            block = _read_exact(fin, blen, "short read")
            nonce = block[:NONCE_LEN]
            ciphertext = block[NONCE_LEN:]
            aad = header + _CHUNK_AAD.pack(index, flag)
            try:
                plaintext = aes.decrypt(nonce, ciphertext, aad)
            except Exception as exc:  # InvalidTag for tamper/reorder/truncation
                raise CrypterError(
                    "Decryption failed (wrong passphrase, corruption, or tampering)"
                ) from exc
            fout.write(plaintext)
            decrypted += len(plaintext)
            index += 1
            if on_progress:
                on_progress(decrypted, src_size)
            if flag == 1:
                seen_final = True
                break

    if not seen_final:
        raise CrypterError("Truncated file (missing final chunk)")
    # Reject any trailing bytes appended after the authenticated final chunk.
    if fin.read(1):
        raise CrypterError("Trailing data after final chunk")
    if decrypted != original_length:
        raise CrypterError("Decrypted length does not match authenticated header length")


def _decrypt_v1(
    fin,
    dst: Path,
    passphrase: str,
    on_progress: Callable[[int, int], None] | None,
    src_size: int,
) -> None:
    """Decrypt a legacy version-1 Crypter stream (per-chunk auth only)."""
    salt = _read_exact(fin, SALT_LEN, "missing salt")
    chunk_size = struct.unpack(">I", _read_exact(fin, 4, "missing chunk size"))[0]
    if chunk_size <= 0 or chunk_size > (1 << 24):
        raise CrypterError("Invalid chunk size in header")

    key = _derive_key(passphrase, salt)
    aes = AESGCM(key)

    dst.parent.mkdir(parents=True, exist_ok=True)
    decrypted = 0
    with open(dst, "wb") as fout:
        while True:
            length_bytes = fin.read(4)
            if len(length_bytes) < 4:
                raise CrypterError("Truncated file (missing length prefix)")
            length = struct.unpack(">I", length_bytes)[0]
            if length == 0:
                break
            block = _read_exact(fin, length, "short read")
            nonce = block[:NONCE_LEN]
            ciphertext = block[NONCE_LEN:]
            try:
                plaintext = aes.decrypt(nonce, ciphertext, None)
            except Exception as exc:  # InvalidTag is the common case
                raise CrypterError(
                    "Decryption failed (wrong passphrase or file corruption)"
                ) from exc
            fout.write(plaintext)
            decrypted += len(plaintext)
            if on_progress:
                on_progress(decrypted, src_size)


def decrypt_file(
    src: Path,
    dst: Path,
    passphrase: str,
    on_progress: Callable[[int, int], None] | None = None,
) -> None:
    """Decrypt a Crypter-encoded file back to plaintext (v1 or v2)."""
    src_size = src.stat().st_size
    with open(src, "rb") as fin:
        prefix = fin.read(len(MAGIC) + 1)
        if len(prefix) < len(MAGIC) + 1:
            raise CrypterError("File is too short or not a Crypter blob")
        magic = prefix[: len(MAGIC)]
        version = prefix[len(MAGIC)]
        if magic != MAGIC:
            raise CrypterError("Not a MegaBasterd Crypter file (bad magic)")
        if version == VERSION_LEGACY:
            _decrypt_v1(fin, dst, passphrase, on_progress, src_size)
        elif version == VERSION:
            _decrypt_v2(fin, dst, passphrase, on_progress, src_size, header_prefix=prefix)
        else:
            raise CrypterError(f"Unsupported Crypter version {version}")
