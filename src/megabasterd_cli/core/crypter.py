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

import contextlib
import os
import struct
import tempfile
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import BinaryIO

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

# Defensive scrypt parameter bounds. The MBCR format does NOT embed KDF
# parameters in the file (they are fixed constants below), so these values are
# not attacker-controlled today. Validating them anyway guards against an unsafe
# configuration and future format changes, and proves the parameters are sane
# before the (memory/CPU-expensive) KDF runs.
MIN_SCRYPT_N = 2**10
MAX_SCRYPT_N = 2**20
MAX_SCRYPT_R = 32
MAX_SCRYPT_P = 16
MAX_SCRYPT_MEMORY_BYTES = 256 * 1024 * 1024  # ~128 * N * r * p upper bound

_V1_HEADER_LEN = len(MAGIC) + 1 + SALT_LEN + 4
_V2_HEADER_LEN = len(MAGIC) + 1 + SALT_LEN + 4 + 8
# Associated data appended per chunk: chunk index (u64) + final flag (u8).
_CHUNK_AAD = struct.Struct(">QB")


class CrypterError(Exception):
    """Raised on any encrypt/decrypt failure."""


def _validate_scrypt_params(n: int, r: int, p: int) -> None:
    """Reject unsafe scrypt parameters before invoking the KDF."""
    if not (isinstance(n, int) and isinstance(r, int) and isinstance(p, int)):
        raise CrypterError("Invalid scrypt parameter types")
    if n < MIN_SCRYPT_N or n > MAX_SCRYPT_N:
        raise CrypterError(f"scrypt N out of range: {n}")
    if n & (n - 1) != 0:
        raise CrypterError("scrypt N must be a power of two")
    if r < 1 or r > MAX_SCRYPT_R:
        raise CrypterError(f"scrypt r out of range: {r}")
    if p < 1 or p > MAX_SCRYPT_P:
        raise CrypterError(f"scrypt p out of range: {p}")
    # Approximate memory cost is 128 * N * r * p bytes (checked, no overflow risk
    # in Python). Reject parameter sets that would demand excessive memory.
    if 128 * n * r * p > MAX_SCRYPT_MEMORY_BYTES:
        raise CrypterError("scrypt parameters exceed the memory budget")


@contextlib.contextmanager
def _atomic_output(dst: Path) -> Iterator[BinaryIO]:
    """Yield a writable temp file that replaces `dst` only after full success.

    Opening `dst` directly with "wb" truncates it before any work happens, so a
    wrong passphrase (or any mid-stream failure) destroys an existing file the
    caller never agreed to lose. Writing beside it and renaming on success keeps
    the destination untouched until the output is complete and durable.
    """
    dst.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=dst.parent, suffix=".mbcr-tmp")
    try:
        with os.fdopen(fd, "wb") as fout:
            yield fout
            fout.flush()
            os.fsync(fout.fileno())
        # Windows: replace can transiently fail while the destination is held
        # open (antivirus scan, a lingering handle). Retry briefly.
        for attempt in range(5):
            try:
                os.replace(tmp_name, dst)
                return
            except PermissionError:
                if attempt == 4:
                    raise
                time.sleep(0.05 * (attempt + 1))
    except BaseException:
        # Includes KeyboardInterrupt: never leave a partial blob behind.
        with contextlib.suppress(OSError):
            os.unlink(tmp_name)
        raise


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    _validate_scrypt_params(SCRYPT_N, SCRYPT_R, SCRYPT_P)
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
    header = (
        MAGIC
        + bytes([VERSION])
        + salt
        + struct.pack(">I", chunk_size)
        + struct.pack(">Q", src_size)
    )

    written = 0
    index = 0
    with open(src, "rb") as fin, _atomic_output(dst) as fout:
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


def _read_exact(fin: BinaryIO, n: int, what: str) -> bytes:
    data = fin.read(n)
    if len(data) < n:
        raise CrypterError(f"Truncated file ({what})")
    return data


def _decrypt_v2(
    fin: BinaryIO,
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
    # The plaintext can never exceed the encrypted file size; reject an absurd
    # declared original length before deriving the key or reading chunks.
    if original_length > src_size:
        raise CrypterError("Declared original length exceeds the encrypted file size")

    header = header_prefix + salt + chunk_size_bytes + orig_len_bytes
    key = _derive_key(passphrase, salt)
    aes = AESGCM(key)

    decrypted = 0
    index = 0
    seen_final = False
    with _atomic_output(dst) as fout:
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
            # Bound the declared length to the header chunk size so a hostile
            # header cannot force a huge read/allocation.
            if blen > NONCE_LEN + chunk_size + TAG_LEN:
                raise CrypterError("Declared chunk length exceeds header chunk size")
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

        # These checks stay inside the atomic block: a failure here must abort
        # the rename, not reject a destination that has already been replaced.
        if not seen_final:
            raise CrypterError("Truncated file (missing final chunk)")
        # Reject any trailing bytes appended after the authenticated final chunk.
        if fin.read(1):
            raise CrypterError("Trailing data after final chunk")
        if decrypted != original_length:
            raise CrypterError("Decrypted length does not match authenticated header length")


def _decrypt_v1(
    fin: BinaryIO,
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

    decrypted = 0
    with _atomic_output(dst) as fout:
        while True:
            length_bytes = fin.read(4)
            if len(length_bytes) < 4:
                raise CrypterError("Truncated file (missing length prefix)")
            length = struct.unpack(">I", length_bytes)[0]
            if length == 0:
                break
            # `length` is a raw u32 straight from an untrusted file. Bound it to
            # the header chunk size (as the v2 path does) so a hostile blob
            # cannot force a multi-gigabyte read/allocation.
            if length > NONCE_LEN + chunk_size + TAG_LEN:
                raise CrypterError("Declared chunk length exceeds header chunk size")
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
