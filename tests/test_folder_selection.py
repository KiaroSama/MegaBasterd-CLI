"""Selective folder-link downloads (parity with MegaBasterd's FolderLinkDialog).

The original GUI lets the user pick which files inside a public folder share
actually get downloaded. The CLI equivalent is:

* ``--include``/``--exclude`` glob filters over the file's folder-relative
  path (and bare filename), case-insensitive, exclude wins;
* ``--select`` interactive numbered selection (``all`` / ``none`` / ``1,3-5``).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from megabasterd_cli.core.crypto import (
    a32_to_bytes,
    aes_key_wrap_encrypt,
    b64_url_encode,
    bytes_to_a32,
    encrypt_attributes,
    str_to_a32,
    unpack_file_key,
)
from megabasterd_cli.core.downloader import DownloadResult, MegaDownloader
from megabasterd_cli.core.errors import TransferError
from megabasterd_cli.core.folder_downloader import FolderNode, MegaFolderDownloader
from megabasterd_cli.utils.selection import (
    build_folder_file_filter,
    parse_selection_tokens,
)


def _job(name: str, rel_path: str, root: Path, size: int = 100) -> tuple[FolderNode, Path]:
    node = FolderNode(
        handle=f"h-{name}",
        parent="root",
        node_type=0,
        size=size,
        name=name,
        key=b"\0" * 32,
    )
    return node, root / Path(rel_path)


class TestBuildFolderFileFilter:
    def test_no_patterns_returns_none(self):
        assert build_folder_file_filter((), (), Path("out")) is None

    def test_include_by_extension(self, tmp_path):
        jobs = [
            _job("a.mkv", "Show/a.mkv", tmp_path),
            _job("a.srt", "Show/a.srt", tmp_path),
        ]
        keep = build_folder_file_filter(("*.mkv",), (), tmp_path)(jobs)
        assert [node.name for node, _ in keep] == ["a.mkv"]

    def test_include_by_subfolder_path(self, tmp_path):
        jobs = [
            _job("e1.mkv", "Show/Season 1/e1.mkv", tmp_path),
            _job("e2.mkv", "Show/Season 2/e2.mkv", tmp_path),
        ]
        keep = build_folder_file_filter(("Show/Season 1/*",), (), tmp_path)(jobs)
        assert [node.name for node, _ in keep] == ["e1.mkv"]

    def test_exclude_wins_over_include(self, tmp_path):
        jobs = [
            _job("e1.mkv", "Show/e1.mkv", tmp_path),
            _job("e1.sample.mkv", "Show/e1.sample.mkv", tmp_path),
        ]
        keep = build_folder_file_filter(("*.mkv",), ("*sample*",), tmp_path)(jobs)
        assert [node.name for node, _ in keep] == ["e1.mkv"]

    def test_matching_is_case_insensitive(self, tmp_path):
        jobs = [_job("E1.MKV", "Show/Season 1/E1.MKV", tmp_path)]
        keep = build_folder_file_filter(("season 1/*.mkv",), (), tmp_path)(jobs)
        assert len(keep) == 1

    def test_backslash_patterns_are_normalized(self, tmp_path):
        jobs = [_job("e1.mkv", "Show/Season 1/e1.mkv", tmp_path)]
        keep = build_folder_file_filter(("Show\\Season 1\\*",), (), tmp_path)(jobs)
        assert len(keep) == 1

    def test_exclude_only(self, tmp_path):
        jobs = [
            _job("e1.mkv", "Show/e1.mkv", tmp_path),
            _job("readme.txt", "Show/readme.txt", tmp_path),
        ]
        keep = build_folder_file_filter((), ("*.txt",), tmp_path)(jobs)
        assert [node.name for node, _ in keep] == ["e1.mkv"]


class TestParseSelectionTokens:
    def test_all_keywords_and_default(self):
        assert parse_selection_tokens("all", 4) == {1, 2, 3, 4}
        assert parse_selection_tokens("", 3) == {1, 2, 3}
        assert parse_selection_tokens("  a  ", 2) == {1, 2}

    def test_none_returns_empty(self):
        assert parse_selection_tokens("none", 4) == set()
        assert parse_selection_tokens("n", 4) == set()

    def test_single_indexes_and_ranges(self):
        assert parse_selection_tokens("1,3-5", 6) == {1, 3, 4, 5}
        assert parse_selection_tokens("2 4", 5) == {2, 4}
        assert parse_selection_tokens("1, 2-2", 3) == {1, 2}

    @pytest.mark.parametrize("bad", ["junk", "0", "7", "2-9", "5-3", "1,,x"])
    def test_invalid_input_raises(self, bad):
        with pytest.raises(ValueError):
            parse_selection_tokens(bad, 6)


class _StubFolderAPI:
    """Serves one crafted public-folder listing; no network."""

    def __init__(self, listing: dict):
        self._listing = listing

    def get_public_folder_listing(self, public_id: str) -> dict:
        return self._listing


def _craft_share(tmp_path):
    """Build a REAL encrypted folder listing with the project's own crypto."""
    folder_key = bytes(range(16))

    def wrap(key_bytes: bytes) -> str:
        return b64_url_encode(aes_key_wrap_encrypt(key_bytes, folder_key))

    def folder_raw(handle: str, parent: str, name: str) -> dict:
        key = bytes(range(16, 32))
        return {
            "h": handle,
            "p": parent,
            "t": 1,
            "k": f"own:{wrap(key)}",
            "a": b64_url_encode(encrypt_attributes({"n": name}, key)),
        }

    def file_raw(handle: str, parent: str, name: str, size: int) -> dict:
        full_key = bytes((i * 7 + len(name)) % 256 for i in range(32))
        aes_key, _, _ = unpack_file_key(bytes_to_a32(full_key))
        return {
            "h": handle,
            "p": parent,
            "t": 0,
            "s": size,
            "k": f"own:{wrap(full_key)}",
            "a": b64_url_encode(encrypt_attributes({"n": name}, aes_key)),
        }

    listing = {
        "f": [
            folder_raw("root", "ext", "Show"),
            folder_raw("s1", "root", "Season 1"),
            file_raw("f1", "s1", "e1.mkv", 111),
            file_raw("f2", "s1", "e2.mkv", 222),
            file_raw("f3", "root", "notes.txt", 33),
        ]
    }
    url = f"https://mega.nz/folder/SHARE123#{b64_url_encode(folder_key)}"
    # Sanity: the key must round-trip through the link-parsing path.
    assert a32_to_bytes(str_to_a32(b64_url_encode(folder_key))) == folder_key
    downloader = MegaDownloader(api=_StubFolderAPI(listing))
    return downloader, url


class TestDownloadFolderSelection:
    def test_file_filter_limits_manifest_and_downloads(self, tmp_path, monkeypatch):
        downloader, url = _craft_share(tmp_path)
        folder_dl = MegaFolderDownloader(downloader)
        downloaded: list[str] = []

        def fake_download(folder_public_id, node, destination, on_progress):
            downloaded.append(node.name)
            return DownloadResult(
                path=destination, size=node.size, elapsed_seconds=0.0, integrity_ok=True
            )

        monkeypatch.setattr(folder_dl, "_download_owned_file", fake_download)
        manifests: list[list[str]] = []
        results = folder_dl.download_folder(
            url,
            tmp_path,
            on_folder_manifest=lambda jobs: manifests.append([n.name for n, _ in jobs]),
            file_filter=build_folder_file_filter(("*.mkv",), ("*e2*",), tmp_path),
        )
        assert downloaded == ["e1.mkv"]
        assert manifests == [["e1.mkv"]]
        assert [r.size for r in results] == [111]

    def test_filter_matching_nothing_raises(self, tmp_path):
        downloader, url = _craft_share(tmp_path)
        folder_dl = MegaFolderDownloader(downloader)
        with pytest.raises(TransferError, match="matched no files"):
            folder_dl.download_folder(
                url,
                tmp_path,
                file_filter=build_folder_file_filter(("*.iso",), (), tmp_path),
            )
