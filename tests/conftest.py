"""Shared test setup.

The only thing here is a containment guard, and it earns its place: without it
any test that reaches a real `AccountManager`, `ConfigStore` or queue writes
into the OPERATOR'S `User/` directory, because `user_dir()` falls back to the
install location when the environment says nothing.

That is not a tidiness problem. A test credential is encrypted under the test's
own passphrase, so it lands in the real vault as a perfectly valid row that the
operator's passphrase cannot open - and `account add` then refuses every real
account, correctly, on the evidence of a row the operator never created. It
happened twice, months apart, from one test that passed `tmp_path` as
`download_path` and nothing else.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolate_user_dir(tmp_path_factory, monkeypatch):
    """Point every path resolver at a per-test directory.

    Autouse and unconditional on purpose: an opt-in guard is one a new test can
    forget, which is exactly how this escaped. A test that wants its own
    location still just calls `monkeypatch.setenv` itself - it runs after this
    fixture and wins.
    """
    root = tmp_path_factory.mktemp("mb-user")
    monkeypatch.setenv("MEGABASTERD_USER_DIR", str(root))
    monkeypatch.setenv("MEGABASTERD_LOG_DIR", str(root / "Logs"))
    return root
