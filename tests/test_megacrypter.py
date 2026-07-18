"""MegaCrypter API compatibility tests."""

import base64

import pytest
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad

from megabasterd_cli.core.crypto import b64_url_decode
from megabasterd_cli.core.link_services import (
    _decrypt_megacrypter_password_info,
    get_megacrypter_download_url,
    get_megacrypter_info,
    resolve_megacrypter_link,
)
from megabasterd_cli.core.links import parse_link
from megabasterd_cli.proxy.selector import ProxySelector


class DummyResponse:
    def __init__(self, body):
        self._body = body

    def raise_for_status(self):
        return None

    def json(self):
        return self._body


def test_resolve_megacrypter_inline_url(monkeypatch):
    parsed = parse_link("mc://mc.example/token")

    def fake_post(url, json, timeout, proxies=None):
        assert url == "https://mc.example/api"
        assert json["m"] == "info"
        return DummyResponse({"mega_url": "https://mega.nz/file/ABC#KEY"})

    monkeypatch.setattr("requests.post", fake_post)
    resolved = resolve_megacrypter_link(parsed, selector=ProxySelector(force=False))
    assert resolved.public_id == "ABC"
    assert resolved.key == "KEY"


def test_megacrypter_password_metadata_and_url(monkeypatch):
    parsed = parse_link("mc://mc.example/token")
    password = "secret"
    salt = b"1234567890abcdef"
    iv = b"abcdef1234567890"
    iterations_power = 1
    info_key = PBKDF2(
        password.encode(),
        salt,
        dkLen=32,
        count=2**iterations_power,
        hmac_hash_module=SHA256,
    )

    raw_file_key = b"0123456789abcdef0123456789abcdef"
    encrypted_key = AES.new(info_key, AES.MODE_CBC, iv).encrypt(pad(raw_file_key, 16))
    encrypted_name = AES.new(info_key, AES.MODE_CBC, iv).encrypt(pad(b"movie.mkv", 16))
    key_check = AES.new(info_key, AES.MODE_CBC, iv).encrypt(pad(info_key, 16))
    pass_descriptor = "#".join(
        [
            str(iterations_power),
            base64.b64encode(key_check).decode(),
            base64.b64encode(salt).decode(),
            base64.b64encode(iv).decode(),
        ]
    )

    cdn_url = "https://gfs.example/file"
    encrypted_url = AES.new(info_key, AES.MODE_CBC, iv).encrypt(pad(cdn_url.encode(), 16))

    def fake_post(url, json, timeout, proxies=None):
        if json["m"] == "info":
            return DummyResponse(
                {
                    "name": base64.b64encode(encrypted_name).decode(),
                    "size": "1234",
                    "key": base64.b64encode(encrypted_key).decode(),
                    "pass": pass_descriptor,
                    "expire": "noexpire#token-1",
                }
            )
        if json["m"] == "dl":
            assert json["noexpire"] == "token-1"
            return DummyResponse(
                {
                    "url": base64.b64encode(encrypted_url).decode(),
                    "pass": base64.b64encode(iv).decode(),
                }
            )
        raise AssertionError(json)

    monkeypatch.setattr("requests.post", fake_post)
    info = get_megacrypter_info(parsed, password=password, selector=ProxySelector(force=False))
    assert info.name == "movie.mkv"
    assert info.size == 1234
    assert b64_url_decode(info.key) == raw_file_key
    assert info.noexpire_token == "token-1"
    assert (
        get_megacrypter_download_url(parsed, info=info, selector=ProxySelector(force=False))
        == cdn_url
    )


def test_megacrypter_rejects_unbounded_password_iterations():
    with pytest.raises(ValueError, match="too many iterations"):
        _decrypt_megacrypter_password_info({"pass": "30#a#b#c"}, password="secret")


def test_megacrypter_rejects_non_string_password_descriptor():
    with pytest.raises(ValueError, match="Malformed"):
        _decrypt_megacrypter_password_info({"pass": 12345}, password="secret")
