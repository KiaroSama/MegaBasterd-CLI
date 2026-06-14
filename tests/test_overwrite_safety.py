"""Regression tests for safe existing-file handling on download (Priority 3/6).

An unrelated existing file must not be truncated by default; --overwrite forces
in-place replacement. A zero-byte transfer is used so the decision is exercised
without any network I/O.
"""

from pathlib import Path

from megabasterd_cli.core.downloader import MegaDownloader


def _run_empty(dl: MegaDownloader, dest: Path):
    return dl._run_download(
        cdn_url="",
        file_size=0,
        aes_key=b"\0" * 16,
        nonce=b"\0" * 8,
        mac_iv_a32=[0, 0],
        destination=dest,
        source="src",
        on_progress=None,
    )


def test_unrelated_existing_file_preserved_and_unique_name(tmp_path: Path) -> None:
    dest = tmp_path / "f.bin"
    dest.write_bytes(b"original-keepme")
    dl = MegaDownloader(api=None)  # overwrite defaults to False
    result = _run_empty(dl, dest)
    # Original file untouched.
    assert dest.read_bytes() == b"original-keepme"
    # A unique destination was used instead.
    assert result.path != dest
    assert result.path.name == "f (1).bin"
    assert result.path.exists()


def test_overwrite_flag_replaces_in_place(tmp_path: Path) -> None:
    dest = tmp_path / "f.bin"
    dest.write_bytes(b"original")
    dl = MegaDownloader(api=None, overwrite=True)
    result = _run_empty(dl, dest)
    assert result.path == dest
    assert dest.read_bytes() == b""  # truncated to the new (empty) content


def test_new_destination_uses_requested_name(tmp_path: Path) -> None:
    dest = tmp_path / "fresh.bin"
    dl = MegaDownloader(api=None)
    result = _run_empty(dl, dest)
    assert result.path == dest
    assert dest.exists()
