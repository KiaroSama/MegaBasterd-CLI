"""Integrity verification must check the bytes on disk, not the stored MACs.

The per-chunk MACs kept in the resume state are computed from each chunk's
plaintext in memory as it is downloaded. Combining THOSE proves the download
decoded correctly - it says nothing about the file the user is actually left
with. A chunk written by an earlier run against a destination that was replaced
since, or a silent disk write fault, leaves the stored MAC describing bytes the
file no longer holds, and the old check passed anyway.

The destination file IS the decrypted plaintext (`fetch_chunk` writes each
chunk's plaintext at its offset), so reading it back and re-MACing is a true
check. These tests build a real file key whose embedded MAC matches a known
plaintext, then confirm a byte flipped ON DISK is caught even though no state
is consulted at all.
"""

from __future__ import annotations

import os

from megabasterd_cli.core.chunks import chunk_mac, combine_chunk_macs, condense_mac, iter_chunks
from megabasterd_cli.core.download_verify import _verify_file_on_disk

AES_KEY = bytes(range(16))
NONCE = bytes(range(8))


def _mac_iv_for(plaintext: bytes) -> list[int]:
    """The 2-int MAC IV a correct download of `plaintext` would embed in the key."""
    chunks = list(iter_chunks(len(plaintext)))
    macs = [chunk_mac(plaintext[c.offset : c.offset + c.size], AES_KEY, NONCE) for c in chunks]
    return condense_mac(combine_chunk_macs(macs, AES_KEY))


def test_a_correct_file_on_disk_verifies(tmp_path):
    # Larger than one chunk so several chunk MACs are combined.
    plaintext = bytes((i * 37) % 256 for i in range(300_000))
    dest = tmp_path / "movie.bin"
    dest.write_bytes(plaintext)

    chunks = list(iter_chunks(len(plaintext)))
    assert _verify_file_on_disk(chunks, AES_KEY, NONCE, _mac_iv_for(plaintext), dest) is True


def test_a_byte_flipped_on_disk_is_caught(tmp_path):
    """The whole point: the MAC IV is right, but the file no longer matches it.

    The old check read the MACs stored in the resume state and never touched the
    file, so this returned True. Reading the bytes back makes it False.
    """
    plaintext = bytes((i * 37) % 256 for i in range(300_000))
    mac_iv = _mac_iv_for(plaintext)  # computed from the ORIGINAL, correct bytes

    dest = tmp_path / "movie.bin"
    dest.write_bytes(plaintext)
    # Corrupt one byte deep in the file, as a swap or a bad write would.
    with open(dest, "r+b") as f:
        f.seek(150_000)
        f.write(bytes([plaintext[150_000] ^ 0x01]))

    chunks = list(iter_chunks(len(plaintext)))
    assert _verify_file_on_disk(chunks, AES_KEY, NONCE, mac_iv, dest) is False


def test_a_truncated_file_on_disk_is_caught(tmp_path):
    plaintext = bytes((i * 37) % 256 for i in range(300_000))
    mac_iv = _mac_iv_for(plaintext)

    dest = tmp_path / "movie.bin"
    dest.write_bytes(plaintext)
    with open(dest, "r+b") as f:
        f.truncate(len(plaintext) - 1)  # last chunk now short

    chunks = list(iter_chunks(len(plaintext)))
    assert _verify_file_on_disk(chunks, AES_KEY, NONCE, mac_iv, dest) is False


def test_a_missing_file_fails_closed(tmp_path):
    plaintext = b"\x00" * 100
    chunks = list(iter_chunks(len(plaintext)))
    dest = tmp_path / "gone.bin"  # never created
    assert _verify_file_on_disk(chunks, AES_KEY, NONCE, _mac_iv_for(plaintext), dest) is False


def test_the_zero_byte_file_verifies(tmp_path):
    dest = tmp_path / "empty.bin"
    dest.write_bytes(b"")
    chunks = list(iter_chunks(0))
    # iter_chunks(0) yields nothing; an empty combine matches the empty MAC IV.
    assert _verify_file_on_disk(chunks, AES_KEY, NONCE, _mac_iv_for(b""), dest) is True


def test_public_verify_file_integrity_keeps_its_1x_signature(tmp_path):
    """The 1.x public entry point takes `(state, all_chunks, aes_key, mac_iv)`
    and pulls the nonce and destination out of the state. It must stay callable
    that way AND now check the bytes on disk."""
    from megabasterd_cli.core.download_verify import verify_file_integrity
    from megabasterd_cli.core.state import TransferState

    plaintext = bytes((i * 37) % 256 for i in range(300_000))
    dest = tmp_path / "movie.bin"
    dest.write_bytes(plaintext)
    chunks = list(iter_chunks(len(plaintext)))
    state = TransferState(
        transfer_type="download",
        source="https://mega.nz/file/ID#<key>",
        destination=str(dest),
        total_size=len(plaintext),
        metadata={"nonce": NONCE.hex()},
    )

    # Exactly the old four-argument call.
    assert verify_file_integrity(state, chunks, AES_KEY, _mac_iv_for(plaintext)) is True

    with open(dest, "r+b") as f:
        f.seek(150_000)
        f.write(bytes([plaintext[150_000] ^ 0x01]))
    assert verify_file_integrity(state, chunks, AES_KEY, _mac_iv_for(plaintext)) is False


def test_public_verify_file_integrity_fails_closed_without_a_nonce(tmp_path):
    from megabasterd_cli.core.download_verify import verify_file_integrity
    from megabasterd_cli.core.state import TransferState

    dest = tmp_path / "movie.bin"
    dest.write_bytes(b"\x00" * 1024)
    state = TransferState(
        transfer_type="download",
        source="s",
        destination=str(dest),
        total_size=1024,
        metadata={},  # no nonce
    )
    assert verify_file_integrity(state, list(iter_chunks(1024)), AES_KEY, [0, 0]) is False


def _run_download_writing(monkeypatch, tmp_path, plaintext, *, corrupt):
    """Drive a real `_run_download` whose chunk fetch writes `plaintext` to the
    preallocated destination (optionally corrupting one byte), verify on."""
    import pytest

    from megabasterd_cli.core.downloader import MegaDownloader
    from megabasterd_cli.core.errors import IntegrityError

    dest = tmp_path / "movie.bin"
    downloader = MegaDownloader(api=None, verify_integrity=True, max_workers=1, auto_resume=False)

    def fake_fetch(self, chunk, aes_key, nonce, destination, state):
        data = plaintext[chunk.offset : chunk.offset + chunk.size]
        if corrupt and chunk.index == 0:
            data = bytes([data[0] ^ 0x01]) + data[1:]
        with open(destination, "r+b") as f:  # destination is preallocated by _run_claimed_download
            f.seek(chunk.offset)
            f.write(data)
        with self._lock:
            state.mark_chunk_done(chunk.index, chunk_mac(data, aes_key, nonce))

    monkeypatch.setattr(MegaDownloader, "_download_chunk", fake_fetch, raising=True)

    call = lambda: downloader._run_download(  # noqa: E731
        cdn_url="https://cdn.invalid/x",
        file_size=len(plaintext),
        aes_key=AES_KEY,
        nonce=NONCE,
        mac_iv_a32=_mac_iv_for(plaintext),
        destination=dest,
        source="https://mega.nz/file/ID#<key>",
        on_progress=None,
    )
    if corrupt:
        with pytest.raises(IntegrityError):
            call()
        return None
    return call()


def test_end_to_end_download_wires_disk_verification_on_the_happy_path(tmp_path, monkeypatch):
    """Proves the downloader passes the real destination and nonce through, not
    just that the free function works: a correct download verifies True."""
    plaintext = bytes((i * 37) % 256 for i in range(300_000))
    result = _run_download_writing(monkeypatch, tmp_path, plaintext, corrupt=False)
    assert result is not None and result.integrity_ok is True


def test_end_to_end_download_with_a_corrupt_chunk_raises(tmp_path, monkeypatch):
    """The same path, one byte wrong on disk: the download fails with an
    IntegrityError instead of returning a successful result."""
    plaintext = bytes((i * 37) % 256 for i in range(300_000))
    _run_download_writing(monkeypatch, tmp_path, plaintext, corrupt=True)


if __name__ == "__main__":  # quick self-check without pytest
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "f.bin"
        blob = os.urandom(200_000)
        p.write_bytes(blob)
        cs = list(iter_chunks(len(blob)))
        iv = condense_mac(
            combine_chunk_macs(
                [chunk_mac(blob[c.offset : c.offset + c.size], AES_KEY, NONCE) for c in cs],
                AES_KEY,
            )
        )
        assert _verify_file_on_disk(cs, AES_KEY, NONCE, iv, p) is True
        p.write_bytes(blob[:-1] + bytes([blob[-1] ^ 0x01]))
        assert _verify_file_on_disk(cs, AES_KEY, NONCE, iv, p) is False
        print("ok")
