"""Regression tests: a failed os.replace must not orphan the temp file.

Antivirus holding config.json open on Windows makes os.replace raise
PermissionError; without cleanup every `mb config set` left a
`config.json.<random>.tmp` behind in the data dir.
"""

from __future__ import annotations

import os

import pytest

from megabasterd_cli.accounts.storage import AccountStorage, AccountStore
from megabasterd_cli.config import ConfigStore


def _tmp_leftovers(directory):
    return [p.name for p in directory.iterdir() if p.name.endswith(".tmp")]


@pytest.fixture
def boom_replace(monkeypatch):
    """Make os.replace always fail with the given error class."""

    def _install(exc):
        def _fail(src, dst):
            raise exc

        monkeypatch.setattr(os, "replace", _fail)

    return _install


@pytest.mark.parametrize(
    "exc",
    [PermissionError("locked by antivirus"), OSError("disk full"), KeyboardInterrupt()],
)
def test_config_save_cleans_temp_on_replace_failure(tmp_path, boom_replace, exc):
    store = ConfigStore(path=tmp_path / "config.json")
    store.save()  # baseline: a real file exists
    assert _tmp_leftovers(tmp_path) == []

    boom_replace(exc)
    with pytest.raises(type(exc)):
        store.save()

    assert _tmp_leftovers(tmp_path) == []


@pytest.mark.parametrize(
    "exc",
    [PermissionError("locked by antivirus"), OSError("disk full"), KeyboardInterrupt()],
)
def test_account_save_cleans_temp_on_replace_failure(tmp_path, boom_replace, exc):
    storage = AccountStorage(path=tmp_path / "accounts.json")
    storage.save(AccountStore())
    assert _tmp_leftovers(tmp_path) == []

    boom_replace(exc)
    with pytest.raises(type(exc)):
        storage.save(AccountStore())

    assert _tmp_leftovers(tmp_path) == []


def test_config_save_propagates_original_error(tmp_path, boom_replace):
    store = ConfigStore(path=tmp_path / "config.json")
    store.save()
    boom_replace(OSError("disk full"))
    with pytest.raises(OSError, match="disk full"):
        store.save()
