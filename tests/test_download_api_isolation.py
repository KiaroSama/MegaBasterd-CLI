"""Parallel download API-client isolation (Mandatory Fix 1).

Historical bug: `download` created ONE shared `MegaAPIClient` (one mutable
`requests.Session`, one `_seq`, one SID slot) and handed it to every parallel
`MegaDownloader`; folder workers also reused the parent's API object.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

from megabasterd_cli.cli import cli
from megabasterd_cli.core.api import MegaAPIClient
from megabasterd_cli.core.downloader import DownloadResult, MegaDownloader
from megabasterd_cli.core.errors import TransferError
from megabasterd_cli.core.folder_downloader import MegaFolderDownloader

FILE_URL = "https://mega.nz/file/abc123#xyz"
FILE_URL_2 = "https://mega.nz/file/def456#uvw"


@pytest.fixture()
def cli_env(tmp_path, monkeypatch):
    monkeypatch.setenv("MEGABASTERD_USER_DIR", str(tmp_path / "user"))
    monkeypatch.setenv("MEGABASTERD_LOG_DIR", str(tmp_path / "logs"))
    return tmp_path


def test_clone_isolates_session_and_sequence_but_carries_sid():
    base = MegaAPIClient(timeout=42)
    base.set_session("SID-VALUE")
    dup = base.clone()
    assert dup is not base
    assert dup._session is not base._session, "clone must own its own requests.Session"
    assert dup.session_id == "SID-VALUE"
    assert dup.timeout == 42
    before = base._seq
    dup._build_url()
    assert base._seq == before, "clone sequence must not advance the base sequence"


def test_parallel_downloads_use_distinct_api_objects_and_all_close(cli_env, monkeypatch):
    seen: list[tuple[int, int]] = []
    closed: list[int] = []

    def record(self, url, output_dir, **kwargs):
        seen.append((id(self.api), id(self.api._session)))
        if "def456" in url:
            raise TransferError(message="one worker fails")
        path = Path(output_dir) / f"{len(seen)}.bin"
        path.write_bytes(b"x")
        return DownloadResult(path=path, size=1, elapsed_seconds=0.1, integrity_ok=True)

    original_close = MegaAPIClient.close

    def counting_close(self):
        closed.append(id(self))
        original_close(self)

    monkeypatch.setattr(MegaDownloader, "download_link", record)
    monkeypatch.setattr(MegaAPIClient, "close", counting_close)
    runner = CliRunner()
    result = runner.invoke(
        cli, ["-q", "download", FILE_URL, FILE_URL_2, "-P", "2", "-o", str(cli_env / "out")]
    )
    # One worker failed -> exit 1; the OTHER worker was not poisoned.
    assert result.exit_code == 1
    assert len(seen) == 2
    api_ids = {pair[0] for pair in seen}
    session_ids = {pair[1] for pair in seen}
    assert len(api_ids) == 2, "each parallel transfer needs its own MegaAPIClient"
    assert len(session_ids) == 2, "each parallel transfer needs its own requests.Session"
    assert api_ids <= set(closed), "every created API client must be closed"


def test_folder_parallel_workers_clone_and_close_apis(monkeypatch):
    base_api = MegaAPIClient()
    parent = MegaDownloader(api=base_api, max_workers=2)
    folder = MegaFolderDownloader(parent)

    worker_api_ids: list[int] = []
    closed_ids: list[int] = []

    def fake_owned(self, folder_public_id, node, destination, on_progress):
        worker_api_ids.append(id(self.downloader.api))
        return DownloadResult(path=destination, size=1, elapsed_seconds=0.1, integrity_ok=True)

    original_close = MegaAPIClient.close

    def counting_close(self):
        closed_ids.append(id(self))
        original_close(self)

    monkeypatch.setattr(MegaFolderDownloader, "_download_owned_file", fake_owned)
    monkeypatch.setattr(MegaAPIClient, "close", counting_close)

    node = SimpleNamespace(name="n", handle="h", size=1, raw_key_a32=None)
    jobs = [(node, Path("a.bin")), (node, Path("b.bin"))]
    results = folder._download_file_jobs("PUBID", jobs, parallel_files=2)

    assert len(results) == 2
    assert len(set(worker_api_ids)) == 2, "each folder worker needs its own API clone"
    assert id(base_api) not in worker_api_ids, "workers must not reuse the parent API"
    assert set(worker_api_ids) <= set(closed_ids), "worker API clones must be closed"


def test_worker_downloaders_share_the_command_limiter(cli_env, monkeypatch):
    limiter_ids: list[int] = []

    def record(self, url, output_dir, **kwargs):
        limiter_ids.append(id(self.limiter))
        path = Path(output_dir) / f"{len(limiter_ids)}.bin"
        path.write_bytes(b"x")
        return DownloadResult(path=path, size=1, elapsed_seconds=0.1, integrity_ok=True)

    monkeypatch.setattr(MegaDownloader, "download_link", record)
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "-q",
            "download",
            FILE_URL,
            FILE_URL_2,
            "-P",
            "2",
            "-l",
            "1024",
            "-o",
            str(cli_env / "out"),
        ],
    )
    assert result.exit_code == 0
    assert len(limiter_ids) == 2
    assert len(set(limiter_ids)) == 1, "the aggregate TokenBucket must stay shared"
