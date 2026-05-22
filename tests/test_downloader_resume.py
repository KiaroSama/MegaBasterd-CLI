from pathlib import Path

import pytest

from megabasterd_cli.core.chunks import iter_chunks
from megabasterd_cli.core.downloader import MegaDownloader
from megabasterd_cli.core.errors import IntegrityError
from megabasterd_cli.core.state import TransferState, save_state, state_path_for


def test_integrity_fails_when_completed_chunk_mac_is_missing(tmp_path: Path):
    chunks = list(iter_chunks(1024))
    state = TransferState(
        transfer_type="download",
        source="https://mega.nz/file/test#key",
        destination=str(tmp_path / "file.bin"),
        total_size=1024,
        completed_chunks=[0],
    )
    downloader = MegaDownloader(api=None)

    assert downloader._verify_integrity(state, chunks, b"\0" * 16, [0, 0]) is False


def test_resume_state_must_match_source_destination_and_crypto(tmp_path: Path):
    destination = tmp_path / "file.bin"
    destination.write_bytes(b"\0" * 1024)
    chunks = list(iter_chunks(1024))
    aes_key = b"\x01" * 16
    nonce = b"\x02" * 8
    state = TransferState(
        transfer_type="download",
        source="old-source",
        destination=str(destination),
        total_size=1024,
        completed_chunks=[0],
        chunk_macs={0: ("aa" * 16)},
        metadata={"aes_key": aes_key.hex(), "nonce": nonce.hex()},
    )
    downloader = MegaDownloader(api=None)

    assert not downloader._is_usable_download_state(
        state, destination, "new-source", 1024, aes_key, nonce, chunks
    )

    state.source = "new-source"
    assert downloader._is_usable_download_state(
        state, destination, "new-source", 1024, aes_key, nonce, chunks
    )

    state.metadata["aes_key"] = (b"\x03" * 16).hex()
    assert not downloader._is_usable_download_state(
        state, destination, "new-source", 1024, aes_key, nonce, chunks
    )


def test_integrity_failure_removes_state_when_configured(tmp_path: Path):
    destination = tmp_path / "file.bin"
    destination.write_bytes(b"x")
    aes_key = b"\0" * 16
    nonce = b"\0" * 8
    state = TransferState(
        transfer_type="download",
        source="source",
        destination=str(destination),
        total_size=1,
        completed_chunks=[0],
        chunk_macs={0: "00" * 16},
        metadata={"aes_key": aes_key.hex(), "nonce": nonce.hex()},
    )
    save_state(state)
    downloader = MegaDownloader(api=None, keep_state_files_on_error=False)

    with pytest.raises(IntegrityError, match="resume state was removed"):
        downloader._run_download(
            cdn_url="",
            file_size=1,
            aes_key=aes_key,
            nonce=nonce,
            mac_iv_a32=[1, 2],
            destination=destination,
            source="source",
            on_progress=None,
        )

    assert not state_path_for(destination).exists()
