"""AccountStorage.save must retry a transient PermissionError, like ConfigStore.

The vault is credentials: a save that fails outright because antivirus or the
Windows indexer briefly held accounts.json open is worse here than for config.
Retrying must still leave no *.tmp orphan when every attempt fails.
"""

from __future__ import annotations

import json
import os

import pytest

from megabasterd_cli.accounts.storage import AccountStorage, AccountStore


def _tmp_leftovers(directory):
    return [p.name for p in directory.iterdir() if p.name.endswith(".tmp")]


@pytest.fixture()
def no_sleep(monkeypatch):
    """Keep the retry backoff out of the test runtime."""
    import time

    monkeypatch.setattr(time, "sleep", lambda _s: None)


def test_save_retries_transient_permission_error(tmp_path, monkeypatch, no_sleep):
    storage = AccountStorage(path=tmp_path / "accounts.json")
    storage.save(AccountStore())

    real_replace = os.replace
    calls = {"n": 0}

    def flaky(src, dst):
        calls["n"] += 1
        if calls["n"] <= 3:
            raise PermissionError("locked by antivirus")
        real_replace(src, dst)

    monkeypatch.setattr(os, "replace", flaky)
    storage.save(AccountStore())

    assert calls["n"] == 4  # 3 transient failures, then success
    assert _tmp_leftovers(tmp_path) == []
    assert json.loads((tmp_path / "accounts.json").read_text(encoding="utf-8"))["version"] == 1


def test_save_gives_up_after_bounded_retries(tmp_path, monkeypatch, no_sleep):
    storage = AccountStorage(path=tmp_path / "accounts.json")
    storage.save(AccountStore())

    calls = {"n": 0}

    def always_fail(src, dst):
        calls["n"] += 1
        raise PermissionError("locked forever")

    monkeypatch.setattr(os, "replace", always_fail)
    with pytest.raises(PermissionError, match="locked forever"):
        storage.save(AccountStore())

    assert calls["n"] == 5
    assert _tmp_leftovers(tmp_path) == []


def test_save_does_not_retry_other_oserrors(tmp_path, monkeypatch, no_sleep):
    """Disk full is not transient: fail on the first attempt, clean the temp."""
    storage = AccountStorage(path=tmp_path / "accounts.json")
    storage.save(AccountStore())

    calls = {"n": 0}

    def disk_full(src, dst):
        calls["n"] += 1
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", disk_full)
    with pytest.raises(OSError, match="disk full"):
        storage.save(AccountStore())

    assert calls["n"] == 1
    assert _tmp_leftovers(tmp_path) == []
