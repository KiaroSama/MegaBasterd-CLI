from megabasterd_cli.core.crypto import b64_url_encode
from megabasterd_cli.core.links import MegaCrypterInfo
from megabasterd_cli.streaming.server import _content_disposition, _StreamSource


def test_content_disposition_escapes_untrusted_filename():
    value = _content_disposition('bad"name\r\n.mkv')

    assert "\r" not in value
    assert "\n" not in value
    assert 'filename="bad\\"name__.mkv"' in value
    assert "filename*=" in value


def test_stream_source_tolerates_missing_file_attrs():
    class DummyAPI:
        def get_public_file_info(self, public_id):
            assert public_id == "FILEID"
            return {"g": "https://example.invalid/file", "s": 1}

    key = b64_url_encode(b"\0" * 32)
    source = _StreamSource(f"https://mega.nz/file/FILEID#{key}", DummyAPI())

    assert source.filename == "FILEID"
    assert source.size == 1


def test_megacrypter_stream_refresh_uses_configured_proxies(monkeypatch):
    import megabasterd_cli.core.links as links

    calls = []
    proxies = {"https": "socks5://127.0.0.1:9050"}

    def fake_resolve(parsed, password=None):
        raise ValueError("no inline link")

    def fake_info(parsed, password=None, proxies=None):
        calls.append(("info", proxies))
        return MegaCrypterInfo(name="video.mkv", size=1, key=b64_url_encode(b"\0" * 32))

    def fake_download_url(parsed, info=None, password=None, proxies=None):
        calls.append(("download", proxies))
        return "https://example.invalid/cdn"

    monkeypatch.setattr(links, "resolve_megacrypter_link", fake_resolve)
    monkeypatch.setattr(links, "get_megacrypter_info", fake_info)
    monkeypatch.setattr(links, "get_megacrypter_download_url", fake_download_url)

    source = _StreamSource("mc://example.invalid/token", api=object(), proxies=proxies)
    source.refresh_cdn_url()

    assert calls == [
        ("info", proxies),
        ("download", proxies),
        ("download", proxies),
    ]
