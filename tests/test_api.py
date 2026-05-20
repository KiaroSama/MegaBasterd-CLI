"""Tests for low-level MEGA API request construction."""

from megabasterd_cli.core.api import DEFAULT_APP_KEY, MegaAPIClient


def test_api_url_includes_default_app_key():
    api = MegaAPIClient(api_base="https://example.invalid")
    url = api._build_url()
    assert f"ak={DEFAULT_APP_KEY}" in url
