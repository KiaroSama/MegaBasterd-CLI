"""Tests for password-protected MEGA link encoding/decoding."""

import os

import pytest

from megabasterd_cli.core.crypto import (
    decrypt_password_link,
    encrypt_password_link,
)
from megabasterd_cli.core.links import LinkType, parse_link, resolve_password_link


def test_password_link_roundtrip_file():
    """Encode then decode a file link with a password."""
    raw_key = os.urandom(32)
    public_handle = os.urandom(6)
    password = "correct horse battery staple"

    blob = encrypt_password_link(0, public_handle, raw_key, password)
    assert blob and isinstance(blob, str)

    node_type, decoded_handle, decoded_key = decrypt_password_link(blob, password)
    assert node_type == 0
    assert decoded_handle == public_handle
    assert decoded_key == raw_key


def test_password_link_roundtrip_folder():
    raw_key = os.urandom(16)
    public_handle = os.urandom(6)
    password = "another secret"

    blob = encrypt_password_link(1, public_handle, raw_key, password)
    node_type, decoded_handle, decoded_key = decrypt_password_link(blob, password)
    assert node_type == 1
    assert decoded_handle == public_handle
    assert decoded_key == raw_key


def test_password_link_wrong_password_rejected():
    raw_key = os.urandom(32)
    public_handle = os.urandom(6)

    blob = encrypt_password_link(0, public_handle, raw_key, "right")
    with pytest.raises(ValueError, match="HMAC"):
        decrypt_password_link(blob, "wrong")


def test_password_link_resolve_to_normal():
    raw_key = os.urandom(32)
    public_handle = os.urandom(6)
    password = "x"

    blob = encrypt_password_link(0, public_handle, raw_key, password)
    url = f"https://mega.nz/#P!{blob}"
    parsed = parse_link(url)
    assert parsed.type == LinkType.PASSWORD_PROTECTED

    resolved = resolve_password_link(parsed, password)
    assert resolved.type == LinkType.FILE
    # public_id should base64-decode back to the original public_handle
    from megabasterd_cli.core.crypto import b64_url_decode

    assert b64_url_decode(resolved.public_id) == public_handle


def test_megacrypter_link_parsed():
    url = "mc://example.com/abcdef"
    parsed = parse_link(url)
    assert parsed.type == LinkType.MEGACRYPTER
    assert parsed.crypter_server == "example.com"
    assert parsed.crypter_token == "abcdef"
