"""Resume-safety regression tests (Priority 6).

A resume state must only be reused when it provably belongs to the same
transfer; otherwise a fresh state is used so an unrelated file is never
combined with stale chunk/MAC data.
"""

from pathlib import Path

from megabasterd_cli.core.chunks import iter_chunks
from megabasterd_cli.core.downloader import MegaDownloader
from megabasterd_cli.core.state import TransferState


def _state(dest: Path, **over) -> TransferState:
    base = {
        "transfer_type": "download",
        "source": "src",
        "destination": str(dest),
        "total_size": 1024,
        "completed_chunks": [0],
        "chunk_macs": {0: "aa" * 16},
        "metadata": {"aes_key": ("01" * 16), "nonce": ("02" * 8)},
    }
    base.update(over)
    return TransferState(**base)


def test_rejects_size_mismatch(tmp_path: Path) -> None:
    dest = tmp_path / "f.bin"
    dest.write_bytes(b"\0" * 1024)
    dl = MegaDownloader(api=None)
    chunks = list(iter_chunks(1024))
    state = _state(dest, total_size=2048)
    assert not dl._is_usable_download_state(
        state, dest, "src", 1024, b"\x01" * 16, b"\x02" * 8, chunks
    )


def test_rejects_destination_mismatch(tmp_path: Path) -> None:
    dest = tmp_path / "f.bin"
    dest.write_bytes(b"\0" * 1024)
    dl = MegaDownloader(api=None)
    chunks = list(iter_chunks(1024))
    state = _state(dest, destination=str(tmp_path / "other.bin"))
    assert not dl._is_usable_download_state(
        state, dest, "src", 1024, b"\x01" * 16, b"\x02" * 8, chunks
    )


def test_rejects_when_existing_file_size_differs_from_expected(tmp_path: Path) -> None:
    dest = tmp_path / "f.bin"
    dest.write_bytes(b"\0" * 512)  # on-disk size != total_size
    dl = MegaDownloader(api=None)
    chunks = list(iter_chunks(1024))
    state = _state(dest)
    assert not dl._is_usable_download_state(
        state, dest, "src", 1024, b"\x01" * 16, b"\x02" * 8, chunks
    )


def test_rejects_a_state_that_records_no_key(tmp_path: Path) -> None:
    """A resumable download state must record the crypto it belongs to.

    The check used to be `metadata.get("aes_key") and ...`, so a state that
    OMITTED the key skipped the match entirely and was reused - its completed
    chunks trusted without ever proving they were decrypted with this key. The
    downloader has written aes_key/nonce since v1.1.0, so a keyless state is
    tampered/planted, not a legacy shape."""
    dest = tmp_path / "f.bin"
    dest.write_bytes(b"\0" * 1024)
    dl = MegaDownloader(api=None)
    chunks = list(iter_chunks(1024))
    state = _state(dest, metadata={})  # completed chunk claimed, but no key recorded
    assert not dl._is_usable_download_state(
        state, dest, "src", 1024, b"\x01" * 16, b"\x02" * 8, chunks
    )


def test_rejects_a_key_mismatch(tmp_path: Path) -> None:
    dest = tmp_path / "f.bin"
    dest.write_bytes(b"\0" * 1024)
    dl = MegaDownloader(api=None)
    chunks = list(iter_chunks(1024))
    state = _state(dest, metadata={"aes_key": ("ff" * 16), "nonce": ("02" * 8)})
    assert not dl._is_usable_download_state(
        state, dest, "src", 1024, b"\x01" * 16, b"\x02" * 8, chunks
    )


def test_accepts_fully_matching_state(tmp_path: Path) -> None:
    dest = tmp_path / "f.bin"
    dest.write_bytes(b"\0" * 1024)
    dl = MegaDownloader(api=None)
    chunks = list(iter_chunks(1024))
    state = _state(dest)
    assert dl._is_usable_download_state(state, dest, "src", 1024, b"\x01" * 16, b"\x02" * 8, chunks)
