"""Tests for every MEGA URL flavour the parser must accept."""

import base64

import pytest

from megabasterd_cli.core.links import (
    LinkType,
    is_mega_url,
    parse_link,
    resolve_encrypted_container_link,
    ParsedLink,
)


@pytest.mark.parametrize(
    "url, expected_type, expected_id, expected_key, expected_sub",
    [
        # Modern
        ("https://mega.nz/file/ABC#KEY",                  LinkType.FILE,           "ABC", "KEY", None),
        ("https://mega.nz/folder/ABC#KEY",                LinkType.FOLDER,         "ABC", "KEY", None),
        ("https://mega.nz/folder/ABC#KEY/file/XYZ",       LinkType.FILE_IN_FOLDER, "ABC", "KEY", "XYZ"),
        ("https://mega.nz/folder/ABC#KEY/folder/SUB",     LinkType.FOLDER_IN_FOLDER, "ABC", "KEY", "SUB"),
        # Legacy file & folder
        ("https://mega.nz/#!ABC!KEY",                     LinkType.FILE,           "ABC", "KEY", None),
        ("https://mega.nz/#F!ABC!KEY",                    LinkType.FOLDER,         "ABC", "KEY", None),
        # Legacy: folder + subfolder
        ("https://mega.nz/#F!ABC@SUB!KEY",                LinkType.FOLDER_IN_FOLDER, "ABC", "KEY", "SUB"),
        # Legacy: folder + file trailer
        ("https://mega.nz/#F!ABC!KEY!FILE",               LinkType.FILE_IN_FOLDER, "ABC", "KEY", "FILE"),
        # Legacy compact file-in-folder (#F*)
        ("https://mega.nz/#F*FILE!FOLDER!KEY",            LinkType.FILE_IN_FOLDER, "FOLDER", "KEY", "FILE"),
        # Alternate node form (#N!)
        ("https://mega.nz/#N!FILE!FOLDER!KEY",            LinkType.FILE_IN_FOLDER, "FOLDER", "KEY", "FILE"),
    ],
)
def test_parse_link_types(url, expected_type, expected_id, expected_key, expected_sub):
    p = parse_link(url)
    assert p.type == expected_type, f"{url} -> {p.type}"
    assert p.public_id == expected_id
    assert p.key == expected_key
    assert p.subpath == expected_sub


def test_parse_encrypted_container():
    blob = base64.b64encode(b"X" * 32).decode("ascii")
    p = parse_link(f"mega://enc?{blob}")
    assert p.type == LinkType.ENCRYPTED_CONTAINER
    assert p.container_variant == "enc"
    assert p.container_blob == blob


def test_parse_encrypted_container_variants():
    blob = base64.b64encode(b"X" * 32).decode("ascii")
    for variant in ("enc", "enc2", "fenc", "fenc2"):
        p = parse_link(f"mega://{variant}?{blob}")
        assert p.type == LinkType.ENCRYPTED_CONTAINER
        assert p.container_variant == variant


def test_parse_elc_container():
    p = parse_link("mega://elc?abc_DEF,123")
    assert p.type == LinkType.ELC_CONTAINER
    assert p.elc_blob == "abc_DEF,123"


def test_is_mega_url_accepts_all_flavors():
    assert is_mega_url("https://mega.nz/file/ABC#KEY")
    assert is_mega_url("https://mega.co.nz/folder/ABC#KEY")
    assert is_mega_url("mc://server.example/token")
    assert is_mega_url("mega://enc?xxx")
    assert is_mega_url("mega://fenc2?xxx")
    assert is_mega_url("mega://elc?xxx")
    assert not is_mega_url("https://example.com/file")


def test_parse_link_rejects_garbage():
    with pytest.raises(ValueError):
        parse_link("not a url")
    with pytest.raises(ValueError):
        parse_link("https://example.com/file/ABC#KEY")


def test_resolve_encrypted_container_roundtrip():
    """Encrypt a real MEGA URL with the published static key, then decrypt
    through the parser; confirm we recover the original target."""
    from Crypto.Cipher import AES

    # Same constants the parser uses
    key = bytes.fromhex(
        "6B316F36416C2D316B7A3F217A30357958585858585858585858585858585858"
    )
    iv = bytes.fromhex("79F10A01844A0B27FF5B2D4E0ED3163E")
    inner = "https://mega.nz/file/ABC123#KEY-456"
    # AES-CBC NoPadding — pad with null bytes
    padded = inner.encode("utf-8") + b"\x00" * (16 - len(inner) % 16)
    if len(padded) % 16:
        padded += b"\x00" * (16 - len(padded) % 16)
    ct = AES.new(key, AES.MODE_CBC, iv).encrypt(padded)
    blob = base64.b64encode(ct).decode("ascii")

    container = ParsedLink(
        type=LinkType.ENCRYPTED_CONTAINER,
        public_id="",
        container_variant="enc",
        container_blob=blob,
    )
    resolved = resolve_encrypted_container_link(container)
    assert resolved.type == LinkType.FILE
    assert resolved.public_id == "ABC123"
    assert resolved.key == "KEY-456"


def test_resolve_encrypted_container_uses_variant_hint():
    """A `mega://enc2?...` blob should be tried with key #2 first."""
    from Crypto.Cipher import AES

    key2 = bytes.fromhex(
        "ED1F4C200B35139806B260563B3D3876F011B4750F3A1A4A5EFD0BBE67554B44"
    )
    iv = bytes.fromhex("79F10A01844A0B27FF5B2D4E0ED3163E")
    inner = "https://mega.nz/file/F2#K2"
    padded = inner.encode("utf-8") + b"\x00" * (16 - len(inner) % 16)
    if len(padded) % 16:
        padded += b"\x00" * (16 - len(padded) % 16)
    ct = AES.new(key2, AES.MODE_CBC, iv).encrypt(padded)
    blob = base64.b64encode(ct).decode("ascii")

    container = ParsedLink(
        type=LinkType.ENCRYPTED_CONTAINER,
        public_id="",
        container_variant="enc2",
        container_blob=blob,
    )
    resolved = resolve_encrypted_container_link(container)
    assert resolved.public_id == "F2"
    assert resolved.key == "K2"
