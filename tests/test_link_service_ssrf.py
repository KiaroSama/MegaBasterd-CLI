"""ELC and MegaCrypter must not aim credentials at attacker-chosen hosts.

Both take their service URL from the LINK PAYLOAD, which is untrusted input. A
crafted link therefore used to make the resolver POST the user's ELC
USER/APIKEY - or a link password - to `http://127.0.0.1`, to the cloud metadata
address `169.254.169.254`, to an RFC1918 host, or to a URL carrying its own
userinfo.

Every transport below records what was sent, so each test proves the request
was NEVER MADE rather than merely that an error came back afterwards.
"""

from __future__ import annotations

import pytest

from megabasterd_cli.core import link_services as ls
from megabasterd_cli.core.link_services import UnsafeTargetError, validate_safe_target
from megabasterd_cli.core.links import ElcPayload
from megabasterd_cli.proxy.selector import ProxySelector

ELC_USER = "elc-sentinel-user"
ELC_KEY = "elc-sentinel-apikey"

DANGEROUS = {
    "http-downgrade": "http://service.example/api",
    "ipv4-loopback": "https://127.0.0.1/api",
    "ipv4-loopback-alt": "https://127.9.9.9/api",
    "ipv6-loopback": "https://[::1]/api",
    "cloud-metadata": "https://169.254.169.254/latest/meta-data",
    "link-local-v6": "https://[fe80::1]/api",
    "rfc1918-10": "https://10.0.0.5/api",
    "rfc1918-192": "https://192.168.1.5/api",
    "rfc1918-172": "https://172.16.0.5/api",
    "unique-local-v6": "https://[fd00::1]/api",
    "unspecified": "https://0.0.0.0/api",
    "userinfo": "https://user:pass@service.example/api",
    "no-host": "https:///api",
}

SAFE = "https://elc.example.com/api"


@pytest.fixture()
def transport(monkeypatch):
    """Capture every outbound request instead of performing it."""
    sent: list[tuple] = []

    def spy(url, *args, **kwargs):
        sent.append((url, kwargs.get("data"), kwargs.get("json")))
        raise AssertionError(f"REQUEST SENT TO {url}")

    import requests

    monkeypatch.setattr(requests, "post", spy)
    monkeypatch.setattr(requests, "get", spy)
    return sent


def _elc_payload(monkeypatch, service_url: str):
    monkeypatch.setattr(
        ls,
        "decode_elc_payload",
        lambda parsed: ElcPayload(
            encrypted_links=b"x" * 16, service_url=service_url, data_token="tok"
        ),
    )
    return object()


# ---------------------------------------------------------------------------
# The policy itself
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("url", DANGEROUS.values(), ids=list(DANGEROUS))
def test_dangerous_targets_are_rejected(url):
    with pytest.raises(UnsafeTargetError):
        validate_safe_target(url, what="test")


def test_an_ordinary_public_https_target_is_allowed():
    validate_safe_target(SAFE, what="test")  # must not raise


# ---------------------------------------------------------------------------
# ELC: credentials must never leave for a rejected destination
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("url", DANGEROUS.values(), ids=list(DANGEROUS))
def test_elc_sends_no_credentials_to_a_rejected_target(monkeypatch, transport, url):
    parsed = _elc_payload(monkeypatch, url)
    with pytest.raises(UnsafeTargetError):
        ls.resolve_elc_links(
            parsed,
            user=ELC_USER,
            api_key=ELC_KEY,
            selector=ProxySelector(force=False),
        )
    assert transport == [], f"a credential-bearing request was sent to {url}"


def test_elc_credentials_are_not_even_looked_up_for_a_rejected_target(monkeypatch, transport):
    """Validation happens before the account lookup, so nothing is assembled."""
    parsed = _elc_payload(monkeypatch, "https://127.0.0.1/api")
    accounts = {"127.0.0.1": {"user": ELC_USER, "api_key": ELC_KEY}}
    with pytest.raises(UnsafeTargetError):
        ls.resolve_elc_links(parsed, accounts=accounts, selector=ProxySelector(force=False))
    assert transport == []


def test_elc_still_reaches_an_ordinary_public_endpoint(monkeypatch):
    seen: list[str] = []

    class _Resp:
        status_code = 200
        headers: dict = {}
        text = "{}"

        def json(self):
            return {}

        def raise_for_status(self):
            return None

        def close(self):
            return None

    def transport_ok(url, *args, **kwargs):
        seen.append(url)
        return _Resp()

    import requests

    monkeypatch.setattr(requests, "post", transport_ok)
    parsed = _elc_payload(monkeypatch, SAFE)
    with pytest.raises(Exception):  # noqa: B017 - the fake body is not a real ELC reply
        ls.resolve_elc_links(
            parsed, user=ELC_USER, api_key=ELC_KEY, selector=ProxySelector(force=False)
        )
    assert seen == [SAFE], "a legitimate public ELC host must still be reachable"


# ---------------------------------------------------------------------------
# MegaCrypter: the server name also comes from the link
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "server",
    ["127.0.0.1", "169.254.169.254", "10.0.0.5", "[::1]", "192.168.0.9"],
)
def test_megacrypter_refuses_a_dangerous_server_from_the_link(transport, server):
    from megabasterd_cli.core.links import parse_link

    parsed = parse_link(f"mc://{server}/sometoken")
    with pytest.raises(UnsafeTargetError):
        ls.get_megacrypter_info(
            parsed, password="link-password-sentinel", selector=ProxySelector(force=False)
        )
    assert transport == [], f"a password-bearing request was sent to {server}"


def test_megacrypter_password_never_reaches_a_rejected_host(transport):
    from megabasterd_cli.core.links import parse_link

    parsed = parse_link("mc://127.0.0.1/sometoken")
    with pytest.raises(UnsafeTargetError):
        ls.resolve_megacrypter_link(
            parsed, password="link-password-sentinel", selector=ProxySelector(force=False)
        )
    assert transport == []
    blob = repr(transport)
    assert "link-password-sentinel" not in blob
