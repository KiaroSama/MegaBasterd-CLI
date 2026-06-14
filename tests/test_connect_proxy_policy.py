"""Regression tests for unified CONNECT proxy destination policy (Priority 7)."""

import pytest

from megabasterd_cli.proxy.connect_proxy import ALLOWED_HOST_RE, check_destination


@pytest.mark.parametrize(
    "host,allowed",
    [
        ("mega.nz", True),
        ("g.api.mega.nz", True),
        ("eu.static.mega.nz", True),
        ("mega.co.nz", True),
        ("cdn.mega.co.nz", True),
        ("evil.com", False),
        ("notmega.nz", False),
        ("mega.nz.evil.com", False),
        ("evilmega.nz", False),
    ],
)
def test_host_allow_list(host: str, allowed: bool) -> None:
    assert bool(ALLOWED_HOST_RE.match(host)) is allowed


def test_connect_only_443_by_default() -> None:
    assert check_destination("mega.nz", 443, is_connect=True, allow_any_port=False) is None
    assert check_destination("mega.nz", 8080, is_connect=True, allow_any_port=False) == (
        "Forbidden port"
    )
    assert check_destination("mega.nz", 80, is_connect=True, allow_any_port=False) == (
        "Forbidden port"
    )


def test_http_forward_only_80_443_by_default() -> None:
    assert check_destination("mega.nz", 80, is_connect=False, allow_any_port=False) is None
    assert check_destination("mega.nz", 443, is_connect=False, allow_any_port=False) is None
    # The previously unrestricted HTTP-forward path now rejects arbitrary ports.
    assert check_destination("mega.nz", 8080, is_connect=False, allow_any_port=False) == (
        "Forbidden port"
    )
    assert check_destination("mega.nz", 1234, is_connect=False, allow_any_port=False) == (
        "Forbidden port"
    )


def test_forbidden_host_takes_precedence() -> None:
    assert check_destination("evil.com", 443, is_connect=True, allow_any_port=False) == (
        "Forbidden host"
    )
    assert check_destination("evil.com", 443, is_connect=True, allow_any_port=True) == (
        "Forbidden host"
    )


def test_any_port_allows_other_ports_on_allowed_host() -> None:
    assert check_destination("mega.nz", 8080, is_connect=True, allow_any_port=True) is None
    assert check_destination("mega.nz", 8080, is_connect=False, allow_any_port=True) is None
