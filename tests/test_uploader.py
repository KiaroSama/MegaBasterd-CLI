from pathlib import Path

import pytest

from megabasterd_cli.core.errors import TransferError
from megabasterd_cli.core.uploader import MegaUploader, UploadResult


class DummyClient:
    def find_root(self):
        return "root"

    def mkdir(self, name, parent_handle=None):
        return f"folder-{name}"


class FailingMkdirClient(DummyClient):
    def mkdir(self, name, parent_handle=None):
        if name == "broken":
            raise TransferError(message="mkdir failed")
        return super().mkdir(name, parent_handle=parent_handle)


def _directory_uploader(tmp_path: Path) -> tuple[MegaUploader, Path]:
    source_dir = tmp_path / "photos"
    source_dir.mkdir()
    (source_dir / "ok.txt").write_text("ok", encoding="utf-8")
    (source_dir / "bad.txt").write_text("bad", encoding="utf-8")

    uploader = MegaUploader.__new__(MegaUploader)
    uploader.client = DummyClient()

    def upload_file(path, target_handle=None, on_progress=None):
        if path.name == "bad.txt":
            raise TransferError(message="boom")
        return UploadResult(
            file_handle="handle",
            name=path.name,
            size=path.stat().st_size,
            elapsed_seconds=0.1,
        )

    uploader.upload_file = upload_file
    return uploader, source_dir


def test_upload_directory_keep_going_returns_successes_after_file_failure(tmp_path: Path):
    uploader, source_dir = _directory_uploader(tmp_path)

    results = uploader.upload_directory(source_dir, keep_going=True)

    assert [r.name for r in results] == ["ok.txt"]
    assert len(uploader.last_directory_failures) == 1
    assert "bad.txt" in uploader.last_directory_failures[0]


def test_upload_directory_strict_mode_raises_after_file_failure(tmp_path: Path):
    uploader, source_dir = _directory_uploader(tmp_path)

    with pytest.raises(TransferError, match="upload item"):
        uploader.upload_directory(source_dir)


def test_upload_directory_keep_going_records_children_of_failed_folder(tmp_path: Path):
    source_dir = tmp_path / "photos"
    broken = source_dir / "broken"
    broken.mkdir(parents=True)
    (broken / "child.txt").write_text("child", encoding="utf-8")
    uploader = MegaUploader.__new__(MegaUploader)
    uploader.client = FailingMkdirClient()
    uploader.upload_file = lambda path, target_handle=None, on_progress=None: UploadResult(
        file_handle="handle",
        name=path.name,
        size=path.stat().st_size,
        elapsed_seconds=0.1,
    )

    assert uploader.upload_directory(source_dir, keep_going=True) == []
    assert len(uploader.last_directory_failures) == 2
    assert "mkdir failed" in uploader.last_directory_failures[0]
    assert "parent folder creation failed" in uploader.last_directory_failures[1]
