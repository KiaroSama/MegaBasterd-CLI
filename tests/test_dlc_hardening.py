"""Regression tests for DLC resolver transport hardening (Priority 4 / Issue 1).

The resolver must never follow an HTTPS->HTTP redirect, and must never send a
request to a rejected insecure destination.
"""

import contextlib

import pytest

from megabasterd_cli.core import links as links_mod
from megabasterd_cli.core.links import (
    DLC_SERVICE_URL,
    MAX_DLC_REDIRECTS,
    MAX_DLC_RESPONSE_BYTES,
    decrypt_dlc_container,
)


class _Resp:
    """Minimal response double. status_code defaults to 200 (final response)."""

    def __init__(self, text: str = "", status_code: int = 200, headers: dict | None = None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}

    def raise_for_status(self) -> None:
        return None

    def close(self) -> None:
        return None


def _install_posts(monkeypatch, responses):
    """Install a fake requests.post that records every URL it is asked to hit."""
    calls = []
    seq = list(responses)

    def fake_post(url, data=None, headers=None, timeout=None, proxies=None, allow_redirects=None):
        calls.append(url)
        return seq.pop(0)

    monkeypatch.setattr("requests.post", fake_post)
    return calls


def test_default_endpoint_is_https() -> None:
    assert DLC_SERVICE_URL.startswith("https://")


def test_normal_https_response(monkeypatch) -> None:
    calls = _install_posts(monkeypatch, [_Resp("<rc>x</rc>")])
    # Downstream key decode fails on dummy data; we only care it reached HTTPS once.
    with contextlib.suppress(Exception):
        decrypt_dlc_container("B" * 100)
    assert len(calls) == 1
    assert calls[0].startswith("https://")


def test_same_origin_absolute_https_redirect_followed(monkeypatch) -> None:
    calls = _install_posts(
        monkeypatch,
        [
            _Resp(
                status_code=302,
                headers={"Location": "https://service.jdownloader.org/mirror"},
            ),
            _Resp("<rc>x</rc>"),
        ],
    )
    with contextlib.suppress(Exception):
        decrypt_dlc_container("B" * 100)
    assert calls == [DLC_SERVICE_URL, "https://service.jdownloader.org/mirror"]


def test_cross_host_https_redirect_rejected_without_contact(monkeypatch) -> None:
    calls = _install_posts(
        monkeypatch,
        [_Resp(status_code=302, headers={"Location": "https://evil.example/dlcrypt"})],
    )
    with pytest.raises(ValueError, match="cross-origin"):
        decrypt_dlc_container("B" * 100)
    # Critical: the foreign host is never contacted.
    assert calls == [DLC_SERVICE_URL]


def test_scheme_relative_cross_host_redirect_rejected(monkeypatch) -> None:
    calls = _install_posts(
        monkeypatch,
        [_Resp(status_code=302, headers={"Location": "//evil.example/x"})],
    )
    with pytest.raises(ValueError, match="cross-origin"):
        decrypt_dlc_container("B" * 100)
    assert calls == [DLC_SERVICE_URL]


def test_unexpected_port_redirect_rejected(monkeypatch) -> None:
    calls = _install_posts(
        monkeypatch,
        [_Resp(status_code=302, headers={"Location": "https://service.jdownloader.org:8443/x"})],
    )
    with pytest.raises(ValueError, match="cross-origin"):
        decrypt_dlc_container("B" * 100)
    assert calls == [DLC_SERVICE_URL]


def test_embedded_credentials_redirect_rejected(monkeypatch) -> None:
    calls = _install_posts(
        monkeypatch,
        [
            _Resp(
                status_code=302,
                headers={"Location": "https://user:pass@service.jdownloader.org/x"},
            )
        ],
    )
    with pytest.raises(ValueError, match="credentials"):
        decrypt_dlc_container("B" * 100)
    assert calls == [DLC_SERVICE_URL]


@pytest.mark.parametrize(
    "location",
    [
        "https://localhost/x",
        "https://127.0.0.1/x",
        "https://[::1]/x",
        "https://10.0.0.1/x",
        "https://192.168.1.5/x",
        "https://169.254.0.1/x",
        "https://[fd00::1]/x",
        "https://[fe80::1]/x",
    ],
)
def test_internal_host_redirects_rejected(monkeypatch, location: str) -> None:
    calls = _install_posts(monkeypatch, [_Resp(status_code=302, headers={"Location": location})])
    with pytest.raises(ValueError, match="non-global IP|cross-origin"):
        decrypt_dlc_container("B" * 100)
    assert calls == [DLC_SERVICE_URL]


def test_https_to_http_redirect_rejected_without_contacting_http(monkeypatch) -> None:
    calls = _install_posts(
        monkeypatch,
        [_Resp(status_code=302, headers={"Location": "http://evil.example/dlcrypt"})],
    )
    with pytest.raises(ValueError, match="non-HTTPS"):
        decrypt_dlc_container("B" * 100)
    # Critical: only the original HTTPS URL was contacted; the HTTP target never was.
    assert calls == [DLC_SERVICE_URL]
    assert all(u.startswith("https://") for u in calls)


def test_relative_https_redirect_resolved(monkeypatch) -> None:
    calls = _install_posts(
        monkeypatch,
        [
            _Resp(status_code=307, headers={"Location": "/elsewhere/service.php"}),
            _Resp("<rc>x</rc>"),
        ],
    )
    with contextlib.suppress(Exception):
        decrypt_dlc_container("B" * 100)
    assert calls[1] == "https://service.jdownloader.org/elsewhere/service.php"


def test_caller_supplied_internal_ip_service_url_rejected(monkeypatch) -> None:
    _install_posts(monkeypatch, [_Resp("<rc>x</rc>")])
    with pytest.raises(ValueError, match="non-global IP"):
        decrypt_dlc_container("B" * 100, service_url="https://127.0.0.1/dlcrypt")


def test_redirect_without_location_rejected(monkeypatch) -> None:
    _install_posts(monkeypatch, [_Resp(status_code=302, headers={})])
    with pytest.raises(ValueError, match="missing a Location"):
        decrypt_dlc_container("B" * 100)


def test_malformed_location_rejected(monkeypatch) -> None:
    # A Location carrying a foreign scheme is returned verbatim by urljoin and
    # must be rejected (only https destinations are followed).
    calls = _install_posts(
        monkeypatch, [_Resp(status_code=302, headers={"Location": "data:text/plain,x"})]
    )
    with pytest.raises(ValueError, match="non-HTTPS"):
        decrypt_dlc_container("B" * 100)
    assert calls == [DLC_SERVICE_URL]


def test_non_http_scheme_redirect_rejected(monkeypatch) -> None:
    _install_posts(
        monkeypatch, [_Resp(status_code=302, headers={"Location": "ftp://evil.example/x"})]
    )
    with pytest.raises(ValueError, match="non-HTTPS"):
        decrypt_dlc_container("B" * 100)


def test_redirect_loop_bounded(monkeypatch) -> None:
    loop = [
        _Resp(status_code=302, headers={"Location": "https://service.jdownloader.org/loop"})
        for _ in range(MAX_DLC_REDIRECTS + 5)
    ]
    calls = _install_posts(monkeypatch, loop)
    with pytest.raises(ValueError, match="maximum number of redirects"):
        decrypt_dlc_container("B" * 100)
    # Bounded: original request + at most MAX_DLC_REDIRECTS follow-ups.
    assert len(calls) == MAX_DLC_REDIRECTS + 1
    assert all(u.startswith("https://") for u in calls)


def test_caller_supplied_http_service_url_rejected(monkeypatch) -> None:
    _install_posts(monkeypatch, [_Resp("<rc>x</rc>")])
    with pytest.raises(ValueError, match="non-HTTPS"):
        decrypt_dlc_container("B" * 100, service_url="http://insecure.example/dlcrypt")


def test_oversized_response_rejected(monkeypatch) -> None:
    _install_posts(monkeypatch, [_Resp("<rc>" + ("A" * (MAX_DLC_RESPONSE_BYTES + 10)) + "</rc>")])
    with pytest.raises(ValueError, match="too short|large"):
        decrypt_dlc_container("B" * 100)


def test_missing_rc_rejected(monkeypatch) -> None:
    _install_posts(monkeypatch, [_Resp("<html>no key here</html>")])
    with pytest.raises(ValueError, match="did not return a key"):
        decrypt_dlc_container("B" * 100)


def test_tls_verification_not_disabled() -> None:
    # The resolver must never pass verify=False. Inspect the source for safety.
    import inspect

    src = inspect.getsource(links_mod._dlc_post)
    assert "verify=False" not in src
    assert "allow_redirects=False" in src
