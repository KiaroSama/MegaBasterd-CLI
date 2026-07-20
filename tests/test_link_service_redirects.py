"""Link-service targets stay validated after the FIRST hop.

`validate_safe_target()` used to run once, on the initial URL, while
`requests.post` was left with `allow_redirects=True`. An attacker-named host
could therefore answer 307 and have the credential body - the ELC USER/APIKEY,
or the MegaCrypter password and sid - re-POSTed by `requests` to a destination
that `validate_safe_target` had already refused: loopback, link-local, RFC1918.
The DLC resolver already validated every hop; ELC and MegaCrypter now share
that one loop.

Also covered here: the MegaCrypter *download* URL (the service's own answer,
which two fetchers hand straight to `requests.get`) and the PBKDF2 iteration
bound, which was enforced only after the attacker-chosen exponent had already
been materialised.
"""

from __future__ import annotations

import json
import time

import pytest

from megabasterd_cli.core import link_services as ls
from megabasterd_cli.core.link_services import UnsafeTargetError
from megabasterd_cli.core.links import ElcPayload, parse_link
from megabasterd_cli.proxy.selector import ProxySelector

ELC_SERVICE = "https://elc.example.com/api"
ELC_USER = "victim@example.com"
ELC_KEY = "SUPER-SECRET-ELC-KEY"
# The sink an attacker-controlled service tries to redirect the credentials to.
SINK = "http://127.0.0.1:8931/"
HTTPS_SINK = "https://127.0.0.1:8931/"


class _Resp:
    """Response double: a redirect (with Location) or a final body."""

    def __init__(self, body=None, status_code: int = 200, headers: dict | None = None):
        self._body = {} if body is None else body
        self.status_code = status_code
        self.headers = headers or {}
        self.closed = False

    def iter_content(self, chunk_size=65536):
        yield json.dumps(self._body).encode()

    def raise_for_status(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True


def _install(monkeypatch, responses):
    """Record every outbound POST; return the recorded calls."""
    calls: list[dict] = []
    seq = list(responses)

    def fake_post(url, **kwargs):
        calls.append({"url": url, **kwargs})
        if not seq:
            raise AssertionError(f"unexpected extra request to {url}")
        return seq.pop(0)

    monkeypatch.setattr("requests.post", fake_post)
    return calls


def _elc(monkeypatch, service_url: str = ELC_SERVICE):
    monkeypatch.setattr(
        ls,
        "decode_elc_payload",
        lambda parsed: ElcPayload(
            encrypted_links=b"x" * 16, service_url=service_url, data_token="tok"
        ),
    )
    return object()


def _resolve_elc(parsed):
    return ls.resolve_elc_links(
        parsed, user=ELC_USER, api_key=ELC_KEY, selector=ProxySelector(force=False)
    )


# ---------------------------------------------------------------------------
# N1 - redirects must never be followed by `requests` itself
# ---------------------------------------------------------------------------


def test_elc_disables_automatic_redirects(monkeypatch):
    parsed = _elc(monkeypatch)
    calls = _install(monkeypatch, [_Resp({"d": ""})])
    with pytest.raises(Exception):  # noqa: B017 - the reply is not a usable ELC body
        _resolve_elc(parsed)
    assert calls, "the ELC request was never made"
    assert calls[0]["allow_redirects"] is False


def test_megacrypter_disables_automatic_redirects(monkeypatch):
    # info + dl: two POSTs, both of which must refuse to be redirected silently.
    calls = _install(monkeypatch, [_Resp({}), _Resp({"url": "https://cdn.example.com/f"})])
    ls.get_megacrypter_download_url(
        parse_link("mc://mc.example.com/token"), selector=ProxySelector(force=False)
    )
    assert [c["allow_redirects"] for c in calls] == [False, False]


@pytest.mark.parametrize("location", [SINK, HTTPS_SINK, "https://169.254.169.254/latest"])
def test_elc_credentials_never_follow_a_redirect_to_a_rejected_host(monkeypatch, location):
    parsed = _elc(monkeypatch)
    calls = _install(monkeypatch, [_Resp(status_code=307, headers={"Location": location})])
    with pytest.raises(UnsafeTargetError):
        _resolve_elc(parsed)
    assert [c["url"] for c in calls] == [ELC_SERVICE], f"credentials were re-sent to {location}"
    assert calls[0]["data"]["APIKEY"] == ELC_KEY  # sent once, to the validated host only


@pytest.mark.parametrize("location", [SINK, HTTPS_SINK, "https://10.0.0.5/api"])
def test_megacrypter_password_never_follows_a_redirect_to_a_rejected_host(monkeypatch, location):
    calls = _install(monkeypatch, [_Resp(status_code=307, headers={"Location": location})])
    with pytest.raises(UnsafeTargetError):
        ls.get_megacrypter_info(
            parse_link("mc://mc.example.com/token"),
            password="link-password-sentinel",
            selector=ProxySelector(force=False),
        )
    assert [c["url"] for c in calls] == ["https://mc.example.com/api"]


def test_elc_follows_a_safe_public_redirect(monkeypatch):
    parsed = _elc(monkeypatch)
    calls = _install(
        monkeypatch,
        [
            _Resp(status_code=307, headers={"Location": "https://mirror.example.com/api"}),
            _Resp({"d": ""}),
        ],
    )
    with pytest.raises(Exception):  # noqa: B017 - body is not a usable ELC reply
        _resolve_elc(parsed)
    assert [c["url"] for c in calls] == [ELC_SERVICE, "https://mirror.example.com/api"]


def test_elc_resolves_a_relative_redirect_against_the_current_url(monkeypatch):
    parsed = _elc(monkeypatch)
    calls = _install(
        monkeypatch,
        [_Resp(status_code=302, headers={"Location": "/v2/api"}), _Resp({"d": ""})],
    )
    with pytest.raises(Exception):  # noqa: B017
        _resolve_elc(parsed)
    assert calls[1]["url"] == "https://elc.example.com/v2/api"


def test_elc_redirect_chain_is_bounded(monkeypatch):
    parsed = _elc(monkeypatch)
    loop = [_Resp(status_code=302, headers={"Location": ELC_SERVICE}) for _ in range(20)]
    calls = _install(monkeypatch, loop)
    with pytest.raises(ValueError, match="maximum number of redirects"):
        _resolve_elc(parsed)
    assert len(calls) <= 10


# ---------------------------------------------------------------------------
# N3 - the download URL the service returns is itself untrusted
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "dl_url",
    [
        "http://127.0.0.1:8931/x",
        "https://127.0.0.1/x",
        "https://169.254.169.254/latest/meta-data",
        "https://192.168.1.5/x",
        "http://cdn.example.com/x",
    ],
)
def test_megacrypter_download_url_is_validated_before_it_reaches_a_fetcher(monkeypatch, dl_url):
    _install(monkeypatch, [_Resp({}), _Resp({"url": dl_url})])
    with pytest.raises(UnsafeTargetError):
        ls.get_megacrypter_download_url(
            parse_link("mc://mc.example.com/token"), selector=ProxySelector(force=False)
        )


def test_megacrypter_ordinary_download_url_still_returned(monkeypatch):
    _install(monkeypatch, [_Resp({}), _Resp({"url": "https://gfs.example.com/dl/abc"})])
    assert (
        ls.get_megacrypter_download_url(
            parse_link("mc://mc.example.com/token"), selector=ProxySelector(force=False)
        )
        == "https://gfs.example.com/dl/abc"
    )


# ---------------------------------------------------------------------------
# C1 - the PBKDF2 bound must gate the EXPONENT, not the materialised value
# ---------------------------------------------------------------------------


def test_pbkdf2_bound_refuses_before_computing_the_exponent():
    """`2**iteration_power` was evaluated BEFORE the cap was consulted.

    The exponent comes from the attacker-chosen host, so the refusal has to be
    a comparison on the exponent itself. Timing is the observable: computing
    `2**10**9` allocates ~125 MB and takes seconds, a bounds check takes none.
    """
    start = time.perf_counter()
    with pytest.raises(ValueError, match="too many iterations"):
        ls._decrypt_megacrypter_password_info({"pass": f"{10**9}#a#b#c"}, password="secret")
    assert time.perf_counter() - start < 1.0, "the huge exponent was materialised before refusal"


def test_pbkdf2_bound_still_refuses_a_modest_overshoot():
    # 2**18 = 262144 > MAX (200_000): the exact bound is still enforced.
    with pytest.raises(ValueError, match="too many iterations"):
        ls._decrypt_megacrypter_password_info({"pass": "18#a#b#c"}, password="secret")
