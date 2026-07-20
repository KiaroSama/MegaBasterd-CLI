"""MEGA chunking and per-chunk MAC computation.

MEGA splits files into variable-size chunks:
  128 KB, 256 KB, 384 KB, 512 KB, 640 KB, 768 KB, 896 KB, 1024 KB,
  then all subsequent chunks are 1024 KB.

Each chunk has a 128-bit MAC computed by:
  1. Encrypting the chunk with AES-CTR (the file content encryption)
  2. CBC-MAC of the *plaintext* chunk with the file key, starting from
     the chunk's MAC IV (the same nonce concatenated with itself).
The chunk MACs are then combined into the file MAC via CBC-MAC.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

from Crypto.Cipher import AES

# MEGA's chunk size progression: 128KB increments up to 1MB, then 1MB chunks.
CHUNK_SIZES_KB = [128, 256, 384, 512, 640, 768, 896, 1024]
MAX_CHUNK_SIZE = 1024 * 1024  # 1 MiB


@dataclass(frozen=True)
class Chunk:
    """One chunk of a file: a byte range [offset, offset + size)."""

    index: int
    offset: int
    size: int

    @property
    def end(self) -> int:
        return self.offset + self.size

    def __repr__(self) -> str:
        return f"Chunk(#{self.index}, {self.offset}-{self.end}, {self.size}B)"


def iter_chunks(file_size: int) -> Iterator[Chunk]:
    """Yield Chunk objects covering the entire file using MEGA's size progression."""
    offset = 0
    index = 0
    # First 8 chunks follow the increment pattern.
    for size_kb in CHUNK_SIZES_KB:
        size = size_kb * 1024
        if offset >= file_size:
            return
        actual = min(size, file_size - offset)
        yield Chunk(index, offset, actual)
        offset += actual
        index += 1
    # Remaining chunks are all 1 MiB.
    while offset < file_size:
        actual = min(MAX_CHUNK_SIZE, file_size - offset)
        yield Chunk(index, offset, actual)
        offset += actual
        index += 1


# Upper bound on the chunk list a single transfer may build. A Chunk costs
# ~172 bytes, so this keeps the materialised list around 33 MiB for a ~195 GiB
# file. It exists because the chunk count comes from a SERVER-DECLARED size: a
# hostile MegaCrypter host answering "1 PiB" would otherwise spend hours
# allocating ~1.07 billion Chunk objects (~172 GiB) before the first request.
MAX_CHUNKS = 200_000
# The largest file that still fits in MAX_CHUNKS chunks (~195 GiB): the first
# eight chunks are smaller than 1 MiB, so this is not a plain multiplication.
MAX_FILE_SIZE = (
    sum(kb * 1024 for kb in CHUNK_SIZES_KB) + (MAX_CHUNKS - len(CHUNK_SIZES_KB)) * MAX_CHUNK_SIZE
)


def chunk_count(file_size: int) -> int:
    """Total number of chunks for a file, computed WITHOUT building them.

    Counting by iteration is fine for a real file and catastrophic for a
    declared one: it is the same unbounded loop the size guard exists to
    prevent, so the guard cannot be allowed to depend on it.
    """
    if file_size <= 0:
        return 0
    offset = 0
    count = 0
    for size_kb in CHUNK_SIZES_KB:
        if offset >= file_size:
            return count
        offset += min(size_kb * 1024, file_size - offset)
        count += 1
    remaining = file_size - offset
    return count + (remaining + MAX_CHUNK_SIZE - 1) // MAX_CHUNK_SIZE


# ---------------------------------------------------------------------------
# CBC-MAC for chunk integrity
# ---------------------------------------------------------------------------


def chunk_mac(plaintext: bytes, aes_key: bytes, nonce: bytes) -> bytes:
    """Compute the 16-byte CBC-MAC of one chunk's plaintext.

    Starting IV is nonce || nonce (16 bytes). The chunk is padded to a 16-byte
    multiple with zeros. The MAC is the final CBC block.
    """
    if len(plaintext) == 0:
        return b"\x00" * 16

    iv = nonce + nonce
    # Pad with zeros to 16-byte multiple
    pad = (-len(plaintext)) % 16
    if pad:
        plaintext = plaintext + b"\x00" * pad

    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(plaintext)
    return encrypted[-16:]


def combine_chunk_macs(chunk_macs: list[bytes], aes_key: bytes) -> bytes:
    """Combine per-chunk MACs into the final file MAC via CBC-MAC.

    The chunks are XORed in order through an AES-CBC chain with zero IV.
    """
    state = b"\x00" * 16
    cipher_iv = b"\x00" * 16
    for mac in chunk_macs:
        # XOR state with chunk MAC, then AES-CBC encrypt one block.
        # strict: a short MAC would silently shorten the block and produce
        # a wrong file MAC rather than an error.
        block = bytes(a ^ b for a, b in zip(state, mac, strict=True))
        cipher = AES.new(aes_key, AES.MODE_CBC, cipher_iv)
        state = cipher.encrypt(block)
    return state


def condense_mac(file_mac: bytes) -> list[int]:
    """Condense a 16-byte file MAC into a 2-element a32 array.

    MEGA file keys store the MAC IV in 64 bits, so the final 128-bit MAC
    is folded by XORing the two 64-bit halves.
    """
    from .crypto import bytes_to_a32

    mac_a32 = bytes_to_a32(file_mac)
    return [mac_a32[0] ^ mac_a32[1], mac_a32[2] ^ mac_a32[3]]
