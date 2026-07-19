"""Cryptographic helpers for the MEGA protocol.

MEGA uses:
- AES-128-CBC with zero IV for wrapping keys
- AES-128-CTR for file content encryption
- A custom chunked MAC for file integrity
- PBKDF2 (newer accounts) or a custom iterative AES-CBC derivation (legacy) for
  deriving the master key from a password

References:
- https://mega.nz/SecurityWhitePaper.pdf
- https://github.com/meganz/sdk
"""

from __future__ import annotations

import base64
import json
import struct
from collections.abc import Iterable
from typing import Any

from Crypto.Cipher import AES
from Crypto.Util import Counter

# ---------------------------------------------------------------------------
# Base64 (MEGA-flavoured, URL-safe without padding)
# ---------------------------------------------------------------------------


def b64_url_decode(data: str) -> bytes:
    """Decode MEGA's URL-safe base64 (no padding)."""
    data = data.replace("-", "+").replace("_", "/").replace(",", "")
    padding = "=" * ((4 - len(data) % 4) % 4)
    return base64.b64decode(data + padding)


def b64_url_encode(data: bytes) -> str:
    """Encode bytes to MEGA's URL-safe base64 (no padding)."""
    return base64.b64encode(data).decode("ascii").replace("+", "-").replace("/", "_").rstrip("=")


# ---------------------------------------------------------------------------
# int <-> a32 array conversions (MEGA represents keys as arrays of 32-bit ints)
# ---------------------------------------------------------------------------


def bytes_to_a32(data: bytes) -> list[int]:
    """Convert bytes to a list of unsigned 32-bit ints (big-endian)."""
    if len(data) % 4:
        data += b"\x00" * (4 - len(data) % 4)
    return list(struct.unpack(f">{len(data) // 4}I", data))


def a32_to_bytes(arr: Iterable[int]) -> bytes:
    """Convert a list of 32-bit ints (big-endian) to bytes."""
    arr = list(arr)
    return struct.pack(f">{len(arr)}I", *arr)


def a32_to_str(arr: Iterable[int]) -> str:
    """Encode an a32 array to MEGA's URL-safe base64."""
    return b64_url_encode(a32_to_bytes(arr))


def str_to_a32(s: str) -> list[int]:
    """Decode MEGA's URL-safe base64 into an a32 array."""
    return bytes_to_a32(b64_url_decode(s))


# ---------------------------------------------------------------------------
# AES-CBC (key wrapping)
# ---------------------------------------------------------------------------


def aes_cbc_encrypt(data: bytes, key: bytes) -> bytes:
    """AES-128-CBC encrypt with zero IV. Used for attribute encryption."""
    cipher = AES.new(key, AES.MODE_CBC, b"\x00" * 16)
    return cipher.encrypt(data)


def aes_cbc_decrypt(data: bytes, key: bytes) -> bytes:
    """AES-128-CBC decrypt with zero IV."""
    cipher = AES.new(key, AES.MODE_CBC, b"\x00" * 16)
    return cipher.decrypt(data)


def aes_key_wrap_encrypt(data: bytes, key: bytes) -> bytes:
    """AES key-wrap encrypt: each 16-byte block ECB-style (zero IV per block).

    MEGA wraps node keys block-by-block rather than chaining them: a 32-byte
    file key is two independent AES blocks encrypted with the master key. Use
    this — NOT `aes_cbc_encrypt` — anywhere you're wrapping a node key.
    """
    if len(data) % 16:
        raise ValueError(f"key-wrap input must be a multiple of 16 bytes, got {len(data)}")
    out = b""
    for i in range(0, len(data), 16):
        cipher = AES.new(key, AES.MODE_CBC, b"\x00" * 16)
        out += cipher.encrypt(data[i : i + 16])
    return out


def aes_key_wrap_decrypt(data: bytes, key: bytes) -> bytes:
    """Inverse of `aes_key_wrap_encrypt`: ECB-style 16-byte-block decryption."""
    if len(data) % 16:
        raise ValueError(f"key-wrap input must be a multiple of 16 bytes, got {len(data)}")
    out = b""
    for i in range(0, len(data), 16):
        cipher = AES.new(key, AES.MODE_CBC, b"\x00" * 16)
        out += cipher.decrypt(data[i : i + 16])
    return out


def aes_cbc_encrypt_a32(data_a32: list[int], key_a32: list[int]) -> list[int]:
    """Encrypt an a32 array with another a32 key."""
    return bytes_to_a32(aes_cbc_encrypt(a32_to_bytes(data_a32), a32_to_bytes(key_a32)))


def aes_cbc_decrypt_a32(data_a32: list[int], key_a32: list[int]) -> list[int]:
    """Decrypt an a32 array with another a32 key."""
    return bytes_to_a32(aes_cbc_decrypt(a32_to_bytes(data_a32), a32_to_bytes(key_a32)))


# ---------------------------------------------------------------------------
# Password-based key derivation
# ---------------------------------------------------------------------------


def derive_key_legacy(password: str) -> list[int]:
    """Legacy MEGA key derivation (account version 1).

    Iteratively encrypts a 16-byte buffer with chunks of the password 65536 times.
    """
    pkey = [0x93C467E3, 0x7DB0C7A4, 0xD1BE3F81, 0x0152CB56]
    password_a32 = bytes_to_a32(password.encode("utf-8"))
    for _ in range(65536):
        for j in range(0, len(password_a32), 4):
            key_chunk = [0, 0, 0, 0]
            for i in range(4):
                if i + j < len(password_a32):
                    key_chunk[i] = password_a32[i + j]
            pkey = aes_cbc_encrypt_a32(pkey, key_chunk)
    return pkey


def derive_key_v2(password: str, salt: bytes, iterations: int = 100_000) -> bytes:
    """Modern MEGA key derivation (account version 2). PBKDF2-HMAC-SHA512, 32 bytes."""
    from Crypto.Hash import SHA512
    from Crypto.Protocol.KDF import PBKDF2

    return PBKDF2(
        password.encode("utf-8"),  # type: ignore[arg-type]  # bytes ok at runtime
        salt,
        dkLen=32,
        count=iterations,
        hmac_hash_module=SHA512,
    )


def stringhash(string: str, aeskey_a32: list[int]) -> str:
    """MEGA-specific string hashing used for the login challenge (v1 accounts)."""
    s32 = bytes_to_a32(string.encode("utf-8"))
    h32 = [0, 0, 0, 0]
    for i in range(len(s32)):
        h32[i % 4] ^= s32[i]
    for _ in range(0x4000):
        h32 = aes_cbc_encrypt_a32(h32, aeskey_a32)
    return a32_to_str([h32[0], h32[2]])


# ---------------------------------------------------------------------------
# AES-CTR (file content)
# ---------------------------------------------------------------------------


def make_ctr_cipher(key: bytes, nonce: bytes, initial_value: int = 0) -> Any:
    """Create an AES-128-CTR cipher.

    MEGA uses a 64-bit nonce and a 64-bit counter that starts at byte_offset / 16.
    """
    if len(key) != 16:
        raise ValueError("AES-CTR key must be 16 bytes")
    if len(nonce) != 8:
        raise ValueError("MEGA nonce must be 8 bytes")
    ctr = Counter.new(64, prefix=nonce, initial_value=initial_value)
    return AES.new(key, AES.MODE_CTR, counter=ctr)


def ctr_offset_to_counter(byte_offset: int) -> int:
    """Convert a byte offset within a file to the AES-CTR block counter."""
    if byte_offset % 16 != 0:
        raise ValueError("CTR offset must be a multiple of 16 bytes")
    return byte_offset // 16


# ---------------------------------------------------------------------------
# File-key unpacking
# ---------------------------------------------------------------------------


def unpack_file_key(key_a32: list[int]) -> tuple[bytes, bytes, list[int]]:
    """Unpack an 8-int file key into (aes_key, nonce, mac_iv_a32).

    MEGA file keys are 256 bits (8 x uint32), structured as:
    - key_a32[0..3] XOR key_a32[4..7] = 128-bit AES key
    - key_a32[4..5] = 64-bit CTR nonce
    - key_a32[6..7] = 64-bit MAC IV
    """
    if len(key_a32) != 8:
        raise ValueError(f"File key must have 8 uint32 elements, got {len(key_a32)}")

    aes_key_a32 = [
        key_a32[0] ^ key_a32[4],
        key_a32[1] ^ key_a32[5],
        key_a32[2] ^ key_a32[6],
        key_a32[3] ^ key_a32[7],
    ]
    aes_key = a32_to_bytes(aes_key_a32)
    nonce = a32_to_bytes(key_a32[4:6])
    mac_iv = key_a32[6:8]
    return aes_key, nonce, mac_iv


def pack_file_key(aes_key: bytes, nonce: bytes, mac_iv: list[int]) -> list[int]:
    """Pack AES key, nonce, and MAC IV back into the 8-uint32 file key format."""
    aes_a32 = bytes_to_a32(aes_key)
    nonce_a32 = bytes_to_a32(nonce)
    return [
        aes_a32[0] ^ nonce_a32[0],
        aes_a32[1] ^ nonce_a32[1],
        aes_a32[2] ^ mac_iv[0],
        aes_a32[3] ^ mac_iv[1],
        nonce_a32[0],
        nonce_a32[1],
        mac_iv[0],
        mac_iv[1],
    ]


# ---------------------------------------------------------------------------
# Attribute encryption (file metadata)
# ---------------------------------------------------------------------------

ATTR_PREFIX = b"MEGA"


def encrypt_attributes(attrs: dict, key: bytes) -> bytes:
    """Encrypt the attribute dictionary (filename, etc.) for a file."""
    plaintext = ATTR_PREFIX + json.dumps(attrs, separators=(",", ":")).encode("utf-8")
    # Pad to 16-byte multiple
    pad_len = (-len(plaintext)) % 16
    plaintext += b"\x00" * pad_len
    return aes_cbc_encrypt(plaintext, key)


def decrypt_attributes(data: bytes, key: bytes) -> dict | None:
    """Decrypt and parse the attribute blob for a file."""
    if not data or len(data) % 16 != 0:
        return None
    plaintext = aes_cbc_decrypt(data, key)
    if not plaintext.startswith(ATTR_PREFIX):
        return None
    body = plaintext[len(ATTR_PREFIX) :].rstrip(b"\x00").decode("utf-8", errors="replace")
    try:
        return dict(json.loads(body))
    except json.JSONDecodeError:
        return None


# ---------------------------------------------------------------------------
# Password-protected link decoding
# ---------------------------------------------------------------------------


def derive_password_link_keys(password: str, salt: bytes, algo: int = 2) -> tuple[bytes, bytes]:
    """Derive (aes_xor_key, hmac_key) for a password-protected MEGA link.

    Algorithm 1: 64-byte PBKDF2-HMAC-SHA512 with 100k iterations (early variant).
    Algorithm 2: same but with the modern parameters used by current MEGA clients.

    Returns the AES XOR key and the HMAC verification key.
    """
    from Crypto.Hash import SHA512
    from Crypto.Protocol.KDF import PBKDF2

    if algo not in (1, 2):
        raise ValueError(f"Unsupported password-link algorithm {algo}")
    derived = PBKDF2(
        password.encode("utf-8"),  # type: ignore[arg-type]  # bytes ok at runtime
        salt,
        dkLen=64,
        count=100_000,
        hmac_hash_module=SHA512,
    )
    return derived[:32], derived[32:]


def decrypt_password_link(encoded_blob: str, password: str) -> tuple[int, bytes, bytes]:
    """Decrypt a MEGA password-protected link blob.

    Returns (node_type, public_handle, raw_key) where:
      - node_type: 0 = file, 1 = folder
      - public_handle: 6-byte handle for use in standard MEGA URLs
      - raw_key: 32-byte file key (files) or 16-byte folder key (folders)

    Raises ValueError if the password is wrong (HMAC mismatch) or the blob is
    malformed.
    """
    import hashlib
    import hmac as _hmac

    raw = b64_url_decode(encoded_blob)
    if len(raw) < 1 + 1 + 6 + 32 + 16 + 32:
        raise ValueError("Password link blob is too short")

    algo = raw[0]
    node_type = raw[1]
    public_handle = raw[2:8]
    salt = raw[8:40]
    key_len = 32 if node_type == 0 else 16
    encrypted_key = raw[40 : 40 + key_len]
    expected_hmac = raw[40 + key_len : 40 + key_len + 32]
    body = raw[: 40 + key_len]

    aes_xor_key, hmac_key = derive_password_link_keys(password, salt, algo=algo)

    # Verify HMAC-SHA256 over the body using the derived hmac key
    computed_hmac = _hmac.new(hmac_key, body, hashlib.sha256).digest()
    if not _hmac.compare_digest(computed_hmac, expected_hmac):
        raise ValueError("Wrong password (HMAC verification failed)")

    plain_key = bytes(a ^ b for a, b in zip(encrypted_key, aes_xor_key[:key_len]))
    return node_type, public_handle, plain_key


def encrypt_password_link(
    node_type: int, public_handle: bytes, raw_key: bytes, password: str, algo: int = 2
) -> str:
    """Build a MEGA `#P!` blob for a node so it can be shared with a password."""
    import hashlib
    import hmac as _hmac
    import os

    if node_type not in (0, 1):
        raise ValueError("node_type must be 0 (file) or 1 (folder)")
    expected_len = 32 if node_type == 0 else 16
    if len(raw_key) != expected_len:
        raise ValueError(f"Expected {expected_len}-byte key, got {len(raw_key)}")
    if len(public_handle) != 6:
        raise ValueError(f"Public handle must be 6 bytes, got {len(public_handle)}")

    salt = os.urandom(32)
    aes_xor_key, hmac_key = derive_password_link_keys(password, salt, algo=algo)
    enc_key = bytes(a ^ b for a, b in zip(raw_key, aes_xor_key[:expected_len]))

    body = bytes([algo, node_type]) + public_handle + salt + enc_key
    mac = _hmac.new(hmac_key, body, hashlib.sha256).digest()
    return b64_url_encode(body + mac)
