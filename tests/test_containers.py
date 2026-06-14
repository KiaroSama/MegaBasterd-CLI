"""Tests for ELC and DLC container resolution."""

import base64

import pytest
from Crypto.Cipher import AES

from megabasterd_cli.core.crypto import b64_url_encode
from megabasterd_cli.core.links import (
    LinkType,
    decrypt_dlc_container,
    parse_link,
    resolve_elc_links,
)


class DummyResponse:
    def __init__(self, body, text=""):
        self._body = body
        self.text = text

    def raise_for_status(self):
        return None

    def json(self):
        return self._body


def _pad_spaces(data: bytes) -> bytes:
    return data + b" " * ((16 - len(data) % 16) % 16)


def test_resolve_elc_links(monkeypatch):
    key = b"0123456789abcdef"
    iv_prefix = b"12345678"
    iv = iv_prefix + b"\x00" * 8
    link_text = "#!FILE!KEY|#F!FOLDER!FKEY"
    encrypted_links = AES.new(key, AES.MODE_CBC, iv).encrypt(_pad_spaces(link_text.encode()))

    service_url = "https://elc.example/api"
    token = "opaque-token"
    payload = (
        bytes([0xB9])
        + len(encrypted_links).to_bytes(4, "little")
        + encrypted_links
        + len(service_url).to_bytes(2, "little")
        + service_url.encode()
        + len(token).to_bytes(2, "little")
        + token.encode()
    )
    parsed = parse_link("mega://elc?" + b64_url_encode(payload))

    def fake_post(url, data, headers, timeout, proxies):
        assert url == service_url
        assert data["USER"] == "alice"
        assert data["APIKEY"] == "secret"
        assert data["DATA"] == token
        return DummyResponse({"d": base64.b64encode(key + iv_prefix).decode()})

    monkeypatch.setattr("requests.post", fake_post)
    links = resolve_elc_links(
        parsed,
        accounts={"elc.example": {"user": "alice", "api_key": "secret"}},
    )

    assert links == [
        "https://mega.nz/#!FILE!KEY",
        "https://mega.nz/#F!FOLDER!FKEY",
    ]


def test_decrypt_dlc_container(monkeypatch):
    dlc_key = b"abcdefghijklmnop"
    dlc_key_b64 = base64.b64encode(dlc_key)
    enc_key = AES.new(bytes.fromhex("447E787351E60E2C6A96B3964BE0C9BD"), AES.MODE_ECB).encrypt(
        _pad_spaces(dlc_key_b64)
    )

    url = "https://mega.nz/file/ABC#KEY"
    encoded_url = base64.b64encode(url.encode()).decode()
    xml = f"<dlc><file><url>{encoded_url}</url></file></dlc>"
    xml_b64 = base64.b64encode(xml.encode())
    enc_data = AES.new(dlc_key, AES.MODE_CBC, dlc_key).encrypt(_pad_spaces(xml_b64))
    dlc_id = "A" * 88
    dlc_data = base64.b64encode(enc_data).decode() + dlc_id

    def fake_post(url, data, headers, timeout, proxies, allow_redirects=None):
        assert "srcType=dlc" in data
        return DummyResponse({}, text=f"<rc>{base64.b64encode(enc_key).decode()}</rc>")

    monkeypatch.setattr("requests.post", fake_post)
    assert decrypt_dlc_container(dlc_data) == [url]


def test_elc_without_credentials_fails():
    service_url = "https://elc.example/api"
    payload = (
        bytes([0xB9])
        + (0).to_bytes(4, "little")
        + len(service_url).to_bytes(2, "little")
        + service_url.encode()
        + (1).to_bytes(2, "little")
        + b"x"
    )
    parsed = parse_link("mega://elc?" + b64_url_encode(payload))
    assert parsed.type == LinkType.ELC_CONTAINER
    with pytest.raises(ValueError, match="No ELC credentials"):
        resolve_elc_links(parsed)
