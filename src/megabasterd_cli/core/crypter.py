"""Local file Crypter: encrypt local files before upload, decrypt after download.

This is the analogue of the "Crypter" feature in the original MegaBasterd: a
passphrase-based additional layer of encryption applied to files before they
are uploaded to MEGA (or any cloud). It does NOT replace MEGA's own AES-CTR
encryption — it stacks on top of it.

File format (header + length-prefixed chunks):

    +---------+--------+-----------+-----------------+
    | "MBCR"  | ver(1) | salt(16)  | chunk_size(4be) |
    +---------+--------+-----------+-----------------+

Then a sequence of chunks until a zero-length sentinel:

    +-----------+--------------+--------------+--------+
    | len(4be)  | nonce(12)    | ciphertext   | tag(16)|
    +-----------+--------------+--------------+--------+

A trailing 4-byte zero terminator marks end-of-file. Each chunk is encrypted
with AES-256-GCM using a key derived from the passphrase via scrypt; the salt
is stored in the header so the same passphrase produces a different key for
each file.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path
from typing import Callable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


MAGIC = b"MBCR"
VERSION = 1
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
DEFAULT_CHUNK_SIZE = 64 * 1024  # 64 KB plaintext per chunk

SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LEN = 32


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
    """Encrypt `src` into `dst` with a passphrase using chunked AES-256-GCM."""
    if chunk_size <= 0 or chunk_size > (1 << 24):
        raise CrypterError("chunk_size must be between 1 and 16 MiB")

    salt = os.urandom(SALT_LEN)
    key = _derive_key(passphrase, salt)
    aes = AESGCM(key)

    src_size = src.stat().st_size
    written = 0
    dst.parent.mkdir(parents=True, exist_ok=True)
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        fout.write(MAGIC + bytes([VERSION]) + salt + struct.pack(">I", chunk_size))
        while True:
            plaintext = fin.read(chunk_size)
            if not plaintext:
                break
            nonce = os.urandom(NONCE_LEN)
            ciphertext = aes.encrypt(nonce, plaintext, None)
            block = nonce + ciphertext
            fout.write(struct.pack(">I", len(block)))
            fout.write(block)
            written += len(plaintext)
            if on_progress:
                on_progress(written, src_size)
        # Zero-length sentinel marks EOF
        fout.write(struct.pack(">I", 0))


def decrypt_file(
    src: Path,
    dst: Path,
    passphrase: str,
    on_progress: Callable[[int, int], None] | None = None,
) -> None:
    """Decrypt a Crypter-encoded file back to plaintext."""
    src_size = src.stat().st_size
    with open(src, "rb") as fin:
        header = fin.read(4 + 1 + SALT_LEN + 4)
        if len(header) < 4 + 1 + SALT_LEN + 4:
            raise CrypterError("File is too short or not a Crypter blob")
        magic = header[:4]
        version = header[4]
        if magic != MAGIC:
            raise CrypterError("Not a MegaBasterd Crypter file (bad magic)")
        if version != VERSION:
            raise CrypterError(f"Unsupported Crypter version {version}")
        salt = header[5:5 + SALT_LEN]
        chunk_size = struct.unpack(">I", header[5 + SALT_LEN:])[0]
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
                block = fin.read(length)
                if len(block) < length:
                    raise CrypterError("Truncated file (short read)")
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
