"""Regression tests for DLC resolver transport hardening (Priority 4)."""

import pytest

from megabasterd_cli.core.links import (
    DLC_SERVICE_URL,
    MAX_DLC_RESPONSE_BYTES,
    decrypt_dlc_container,
)


class _Resp:
    def __init__(self, text: str):
        self.text = text

    def raise_for_status(self) -> None:
        return None


def test_default_endpoint_is_https() -> None:
    assert DLC_SERVICE_URL.startswith("https://")


def test_no_silent_http_downgrade(monkeypatch) -> None:
    import contextlib

    used = {}

    def fake_post(url, data, headers, timeout, proxies):
        used["url"] = url
        return _Resp("<rc>x</rc>")

    monkeypatch.setattr("requests.post", fake_post)
    # Downstream decode may fail; we only assert the transport URL is HTTPS.
    with contextlib.suppress(Exception):
        decrypt_dlc_container("B" * 100)
    assert used["url"].startswith("https://")


def test_oversized_response_rejected(monkeypatch) -> None:
    def fake_post(url, data, headers, timeout, proxies):
        return _Resp("<rc>" + ("A" * (MAX_DLC_RESPONSE_BYTES + 10)) + "</rc>")

    monkeypatch.setattr("requests.post", fake_post)
    with pytest.raises(ValueError, match="too short|large"):
        decrypt_dlc_container("B" * 100)


def test_missing_rc_rejected(monkeypatch) -> None:
    def fake_post(url, data, headers, timeout, proxies):
        return _Resp("<html>no key here</html>")

    monkeypatch.setattr("requests.post", fake_post)
    with pytest.raises(ValueError, match="did not return a key"):
        decrypt_dlc_container("B" * 100)
