"""Tests for the file splitter / merger."""

import hashlib
import os
from pathlib import Path

import pytest

from megabasterd_cli.core.splitter import SplitterError, merge_parts, split_file


def _sha1(p: Path) -> str:
    h = hashlib.sha1()
    with open(p, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def test_split_then_merge_roundtrip(tmp_path: Path) -> None:
    src = tmp_path / "data.bin"
    payload = os.urandom(3 * 1024 * 1024 + 17)  # ~3MiB + odd tail
    src.write_bytes(payload)

    result = split_file(src, part_size_mb=1, output_dir=tmp_path)
    assert len(result.parts) == 4  # 3 full MiB + tail
    assert result.sha1 == _sha1(src)

    merged = merge_parts(result.parts[0], output=tmp_path / "merged.bin")
    assert merged.read_bytes() == payload


def test_merge_rejects_bad_filename(tmp_path: Path) -> None:
    bad = tmp_path / "not-a-part.bin"
    bad.write_bytes(b"x")
    with pytest.raises(SplitterError):
        merge_parts(bad)


def test_merge_detects_sha1_mismatch(tmp_path: Path) -> None:
    src = tmp_path / "foo.bin"
    src.write_bytes(b"hello world " * 1000)
    result = split_file(src, part_size_mb=1, output_dir=tmp_path)

    # Corrupt the sha1 file
    (tmp_path / "foo.bin.sha1").write_text("0" * 40 + "\n")

    with pytest.raises(SplitterError, match="SHA-1 mismatch"):
        merge_parts(result.parts[0], output=tmp_path / "merged.bin")


def test_split_empty_file_rejected(tmp_path: Path) -> None:
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    with pytest.raises(SplitterError):
        split_file(empty, part_size_mb=1)


def test_delete_parts_on_merge(tmp_path: Path) -> None:
    src = tmp_path / "x.bin"
    src.write_bytes(b"abcdefgh" * 100_000)  # 800 KB
    result = split_file(src, part_size_mb=1, output_dir=tmp_path)
    merged = merge_parts(
        result.parts[0], output=tmp_path / "out.bin", delete_parts=True,
    )
    assert merged.is_file()
    for p in result.parts:
        assert not p.exists()
