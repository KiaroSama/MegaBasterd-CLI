"""Commit 4624348 moved these out of core.links into core.link_services and
left no re-export, silently breaking `from ...core.links import <name>`."""

import pytest

from megabasterd_cli.core import link_services, links

MOVED = [
    "decode_elc_payload",
    "resolve_elc_links",
    "decrypt_dlc_container",
    "get_megacrypter_info",
    "get_megacrypter_download_url",
    "resolve_megacrypter_link",
]


@pytest.mark.parametrize("name", MOVED)
def test_moved_name_is_reexported_and_identical(name):
    assert hasattr(links, name), f"core.links lost {name}"
    assert getattr(links, name) is getattr(link_services, name)
    assert name in links.__all__
    assert name in dir(links)


def test_unknown_attribute_still_raises_attribute_error():
    missing = "definitely_not_a_real_name"  # via a variable: ruff B009/B018
    with pytest.raises(AttributeError):
        getattr(links, missing)
