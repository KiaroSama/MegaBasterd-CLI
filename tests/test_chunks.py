"""Tests for chunking and per-chunk MACs."""

from megabasterd_cli.core.chunks import (
    chunk_count,
    chunk_mac,
    chunks_for_range,
    combine_chunk_macs,
    iter_chunks,
)


def test_chunk_progression():
    """First 8 chunks follow the 128KB increment pattern."""
    chunks = list(iter_chunks(8 * 1024 * 1024))  # 8 MiB
    sizes_kb = [c.size // 1024 for c in chunks[:8]]
    assert sizes_kb == [128, 256, 384, 512, 640, 768, 896, 1024]


def test_last_chunk_is_partial():
    """A small file gets exactly one short chunk."""
    chunks = list(iter_chunks(100))
    assert len(chunks) == 1
    assert chunks[0].size == 100


def test_chunk_count_consistent():
    """chunk_count agrees with len(list(iter_chunks))."""
    for size in [100, 1024, 1024 * 1024, 50 * 1024 * 1024]:
        assert chunk_count(size) == len(list(iter_chunks(size)))


def test_chunks_for_range():
    """Only chunks overlapping a byte range are returned."""
    size = 10 * 1024 * 1024  # 10 MiB
    overlapping = chunks_for_range(size, 200_000, 500_000)
    for c in overlapping:
        assert c.end > 200_000 and c.offset < 500_000


def test_chunk_mac_deterministic():
    """The same chunk yields the same MAC on repeated calls."""
    plaintext = b"A" * 1024
    key = b"K" * 16
    nonce = b"N" * 8
    mac1 = chunk_mac(plaintext, key, nonce)
    mac2 = chunk_mac(plaintext, key, nonce)
    assert mac1 == mac2
    assert len(mac1) == 16


def test_combine_chunk_macs_empty():
    """Combining zero MACs yields a zero block."""
    key = b"K" * 16
    result = combine_chunk_macs([], key)
    assert result == b"\x00" * 16
