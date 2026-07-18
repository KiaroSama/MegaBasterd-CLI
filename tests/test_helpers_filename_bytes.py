"""Regression tests: filename sanitization must cap BYTES, not characters."""

from __future__ import annotations

from megabasterd_cli.utils.helpers import sanitize_filename

# ext4/APFS NAME_MAX is 255 bytes; the sanitizer keeps a margin below it.
NAME_MAX_BYTES = 255


def _enc_len(name: str) -> int:
    return len(name.encode("utf-8"))


def test_cjk_name_fits_byte_limit():
    # 240 CJK chars is ~720 UTF-8 bytes -> ENAMETOOLONG on Linux/macOS.
    result = sanitize_filename("漢" * 300 + ".mkv")
    assert _enc_len(result) <= NAME_MAX_BYTES
    assert result.endswith(".mkv")


def test_emoji_name_fits_byte_limit():
    # 4-byte astral characters must not be split mid-character.
    result = sanitize_filename("\U0001f600" * 200 + ".mp4")
    assert _enc_len(result) <= NAME_MAX_BYTES
    # Round-trips cleanly: no lone surrogate / partial sequence survived.
    assert result.encode("utf-8").decode("utf-8") == result
    assert "�" not in result


def test_truncation_never_splits_a_character():
    for repeat in range(60, 130):
        result = sanitize_filename("é中\U0001f600" * repeat)
        assert _enc_len(result) <= NAME_MAX_BYTES
        assert result.encode("utf-8").decode("utf-8") == result


def test_truncation_does_not_reintroduce_trailing_dot_or_space():
    # Long ASCII name whose cut point lands exactly on a dot / space.
    for pad in range(230, 246):
        for tail in (".", " "):
            result = sanitize_filename("a" * pad + tail + "b" * 50)
            assert not result.endswith((" ", ".")), result


def test_long_extension_is_not_preserved_but_name_still_fits():
    result = sanitize_filename("漢" * 300 + "." + "x" * 60)
    assert _enc_len(result) <= NAME_MAX_BYTES


def test_short_unicode_name_is_untouched():
    assert sanitize_filename("漢字.mkv") == "漢字.mkv"
