"""Regression tests: split/merge must never destroy their own inputs.

B5 (P1-06) + C13. `merge` opened the output with "wb" *before* reading any
input, so pointing `-o` at one of the input parts truncated that part and then
fed the file its own tail: read -> write -> grow -> read, an unbounded loop that
destroyed the part and filled the disk. Every file here is a few KiB and every
assertion fires before a byte is written, so nothing can run away.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from megabasterd_cli.core.splitter import (
    SplitterAliasError,
    SplitterError,
    merge_parts,
    split_file,
)

PAYLOAD = b"abcdefgh" * 40_000  # 320 KiB -> 1 part at 1 MiB, cheap to hash


def _tmp_leftovers(d: Path) -> list[Path]:
    return [p for p in d.iterdir() if "tmp" in p.name.lower()]


def _split(tmp_path: Path, payload: bytes = PAYLOAD, part_size_mb: int = 1) -> list[Path]:
    src = tmp_path / "data.bin"
    src.write_bytes(payload)
    return split_file(src, part_size_mb=part_size_mb, output_dir=tmp_path).parts


def test_merge_refuses_output_that_is_an_input_part(tmp_path: Path) -> None:
    """The reproduced data-loss case: -o names one of the parts."""
    parts = _split(tmp_path)
    victim = parts[0]
    before = victim.read_bytes()

    with pytest.raises(SplitterAliasError):
        merge_parts(victim, output=victim)

    assert victim.read_bytes() == before  # not truncated, not grown
    assert not _tmp_leftovers(tmp_path)


def test_merge_refuses_output_aliasing_a_part_through_a_messy_path(tmp_path: Path) -> None:
    """Same file, different spelling: `sub/../part1-2` must be caught too."""
    parts = _split(tmp_path, PAYLOAD * 4, part_size_mb=1)
    assert len(parts) > 1
    (tmp_path / "sub").mkdir()
    alias = tmp_path / "sub" / ".." / parts[1].name
    before = parts[1].read_bytes()

    with pytest.raises(SplitterAliasError):
        merge_parts(parts[0], output=alias)

    assert parts[1].read_bytes() == before


def test_merge_leaves_a_pre_existing_target_intact_on_sha1_mismatch(tmp_path: Path) -> None:
    """Verification happens before the rename, so a bad checksum costs nothing."""
    parts = _split(tmp_path)
    (tmp_path / "data.bin.sha1").write_text("0" * 40 + "\n")

    target = tmp_path / "out.bin"
    target.write_bytes(b"precious")

    with pytest.raises(SplitterError, match="SHA-1 mismatch"):
        merge_parts(parts[0], output=target)

    assert target.read_bytes() == b"precious"
    assert not _tmp_leftovers(tmp_path)


def test_merge_leaves_no_partial_target_when_interrupted(tmp_path: Path) -> None:
    parts = _split(tmp_path)

    def boom(done: int, total: int) -> None:
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        merge_parts(parts[0], output=tmp_path / "out.bin", on_progress=boom)

    assert not (tmp_path / "out.bin").exists()
    assert not _tmp_leftovers(tmp_path)


def test_split_refuses_to_write_a_part_over_its_own_source(tmp_path: Path) -> None:
    """A hard link makes a part path resolve to the source file itself."""
    src = tmp_path / "data.bin"
    src.write_bytes(PAYLOAD)
    out_dir = tmp_path / "parts"
    out_dir.mkdir()
    try:
        os.link(src, out_dir / f"{src.name}.part1-1")
    except (OSError, NotImplementedError, AttributeError) as exc:
        pytest.skip(f"hard links unavailable: {exc}")

    with pytest.raises(SplitterAliasError):
        split_file(src, part_size_mb=1, output_dir=out_dir)

    assert src.read_bytes() == PAYLOAD


def test_split_leaves_no_partial_part_when_interrupted(tmp_path: Path) -> None:
    src = tmp_path / "data.bin"
    src.write_bytes(os.urandom(3 * 1024 * 1024 + 5))  # 4 parts at 1 MiB

    def boom(done: int, total: int) -> None:
        if done > 1024 * 1024:  # somewhere inside part 2
            raise RuntimeError("interrupted")

    with pytest.raises(RuntimeError):
        split_file(src, part_size_mb=1, output_dir=tmp_path, on_progress=boom)

    assert (tmp_path / "data.bin.part1-4").stat().st_size == 1024 * 1024
    assert not (tmp_path / "data.bin.part2-4").exists()  # no truncated part
    assert not _tmp_leftovers(tmp_path)
