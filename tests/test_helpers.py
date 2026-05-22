"""Tests for utility helpers."""

from pathlib import Path

from megabasterd_cli.utils.helpers import (
    ensure_unique_path,
    format_bytes,
    format_eta,
    sanitize_filename,
)


def test_sanitize_filename_strips_invalid_chars():
    assert sanitize_filename('a<b>c:d"e/f\\g|h?i*j') == "a_b_c_d_e_f_g_h_i_j"


def test_sanitize_filename_handles_reserved_names():
    assert sanitize_filename("CON.txt").startswith("_CON")
    assert sanitize_filename("LPT1.dat").startswith("_LPT1")


def test_sanitize_filename_empty_input():
    assert sanitize_filename("") == "unnamed"


def test_sanitize_filename_preserves_extension_when_truncated():
    result = sanitize_filename(("a" * 260) + ".mkv")

    assert len(result) <= 240
    assert result.endswith(".mkv")


def test_format_bytes_small():
    assert format_bytes(0) == "0 B"
    assert format_bytes(1023) == "1023 B"


def test_format_bytes_units():
    assert "KB" in format_bytes(2048)
    assert "MB" in format_bytes(5 * 1024 * 1024)
    assert "GB" in format_bytes(2 * 1024**3)


def test_format_eta():
    assert format_eta(65) == "01:05"
    assert format_eta(3725) == "1:02:05"
    assert format_eta(-1) == "--:--"


def test_ensure_unique_path(tmp_path: Path):
    target = tmp_path / "file.txt"
    assert ensure_unique_path(target) == target
    target.touch()
    assert ensure_unique_path(target) == tmp_path / "file (1).txt"
