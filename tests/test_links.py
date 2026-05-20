"""Tests for MEGA link parsing."""

import pytest

from megabasterd_cli.core.links import LinkType, is_mega_url, parse_link


@pytest.mark.parametrize("url,expected_type", [
    ("https://mega.nz/file/abc123#xyz", LinkType.FILE),
    ("https://mega.nz/folder/abc123#xyz", LinkType.FOLDER),
    ("https://mega.nz/folder/abc123#xyz/file/inner", LinkType.FILE_IN_FOLDER),
    ("https://mega.nz/#!abc123!xyz", LinkType.FILE),
    ("https://mega.nz/#F!abc123!xyz", LinkType.FOLDER),
])
def test_parse_link_types(url, expected_type):
    parsed = parse_link(url)
    assert parsed.type == expected_type


def test_parse_link_extracts_id_and_key():
    parsed = parse_link("https://mega.nz/file/MyFileID#MyKeyValue")
    assert parsed.public_id == "MyFileID"
    assert parsed.key == "MyKeyValue"


def test_parse_link_rejects_non_mega():
    with pytest.raises(ValueError):
        parse_link("https://example.com/file/abc")


def test_is_mega_url():
    assert is_mega_url("https://mega.nz/file/abc")
    assert is_mega_url("https://mega.co.nz/file/abc")
    assert not is_mega_url("https://example.com")
