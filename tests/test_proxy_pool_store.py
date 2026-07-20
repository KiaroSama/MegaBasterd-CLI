"""Regression tests for the persisted proxy pool store (P1-15).

Covers the four defects: a corrupt pool file crashing every command that calls
`effective_pool`, the non-atomic unlocked write, credentials printed by
`mb proxy list`, and the unbounded read in `mb proxy fetch`.
"""

from __future__ import annotations

import faulthandler
import json
import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from megabasterd_cli.commands import proxy_cmd
from megabasterd_cli.config import Config
from megabasterd_cli.proxy import runtime
from megabasterd_cli.proxy.runtime import _load_persisted_pool
from megabasterd_cli.ui.theme import make_console
from megabasterd_cli.utils.filelock import FileLock, FileLockError

HARD_TIMEOUT = 90.0


@pytest.fixture(autouse=True)
def _watchdog():
    """A lock that never resolves must fail the run, not stall it."""
    faulthandler.dump_traceback_later(HARD_TIMEOUT, exit=True)
    yield
    faulthandler.cancel_dump_traceback_later()


@pytest.fixture
def data_dir(tmp_path: Path, monkeypatch) -> Path:
    d = tmp_path / "data"
    d.mkdir()
    monkeypatch.setattr(runtime, "data_dir", lambda: d)
    return d


# --- corrupt pool file -----------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        '["http://a:1"]',  # root is a list
        '"proxies"',  # root is a string
        "123",  # root is a number
        "null",  # root is null
        "{oops",  # not JSON at all
        '{"proxies": "http://a:1"}',  # a string where a list belongs
        '{"proxies": [1, 2]}',  # non-string entries
    ],
)
def test_corrupt_pool_raises_typed_error(data_dir: Path, payload: str) -> None:
    """Every command routes through effective_pool; corruption must not crash it
    with an AttributeError from deep inside the loader."""
    (data_dir / "proxies.json").write_text(payload, encoding="utf-8")
    cfg = Config(smart_proxy_enabled=True)
    with pytest.raises(runtime.ProxyPoolCorruptionError):
        runtime.effective_pool(cfg)


def test_corrupt_pool_is_preserved_untouched(data_dir: Path) -> None:
    path = data_dir / "proxies.json"
    raw = '["http://a:1"]'
    path.write_text(raw, encoding="utf-8")

    with pytest.raises(runtime.ProxyPoolCorruptionError):
        _load_persisted_pool()

    assert path.read_text(encoding="utf-8") == raw, "the corrupt file was modified"
    backups = list(data_dir.glob("proxies.json.corrupt.*"))
    assert len(backups) == 1
    assert backups[0].read_text(encoding="utf-8") == raw


def test_corrupt_pool_blocks_mutating_commands(data_dir: Path) -> None:
    """`proxy add` loads before it saves, so a corrupt pool can never be
    replaced by a fresh, mostly-empty one."""
    path = data_dir / "proxies.json"
    raw = '["http://a:1"]'
    path.write_text(raw, encoding="utf-8")

    result = CliRunner().invoke(
        proxy_cmd.proxy_cmd, ["add", "http://b:2"], obj={"config": Config()}
    )

    assert result.exit_code != 0
    # The typed error is what makes this a clean failure rather than an
    # AttributeError leaking out of the loader.
    assert isinstance(result.exception, runtime.ProxyPoolCorruptionError)
    assert path.read_text(encoding="utf-8") == raw


# --- atomic, locked write --------------------------------------------------


# These drive `pool_transaction()` rather than the thin `_save_pool` wrapper
# they used to. The wrapper had no production caller at all, so the properties
# below were only ever proven about code nothing ran; `pool_transaction` is the
# path every proxy command actually takes.


def test_a_failed_replace_leaves_the_pool_and_no_temp_file(data_dir: Path, monkeypatch) -> None:
    path = data_dir / "proxies.json"
    path.write_text(json.dumps({"proxies": ["http://old:1"]}), encoding="utf-8")

    def _boom(src, dst):
        raise OSError("simulated replace failure")

    monkeypatch.setattr(os, "replace", _boom)
    with (
        pytest.raises(OSError, match="simulated replace failure"),
        proxy_cmd.pool_transaction() as pool,
    ):
        pool.add("http://new:2")

    assert json.loads(path.read_text(encoding="utf-8"))["proxies"] == ["http://old:1"]
    assert not list(data_dir.glob("*.tmp")), "a temp file was left behind"


def test_a_transaction_refuses_while_another_holder_has_the_lock(
    data_dir: Path, monkeypatch
) -> None:
    monkeypatch.setattr(proxy_cmd, "_POOL_LOCK_TIMEOUT_SECONDS", 0.3)
    path = data_dir / "proxies.json"
    blocker = FileLock(data_dir / "proxies.json.lock")
    blocker.acquire(timeout=5)
    try:
        with pytest.raises(FileLockError), proxy_cmd.pool_transaction() as pool:
            pool.add("http://new:2")
        assert not path.exists(), "a half-written pool file was produced under contention"
    finally:
        blocker.release()


def test_a_transaction_round_trips(data_dir: Path) -> None:
    with proxy_cmd.pool_transaction() as pool:
        pool.add("http://a:1")
        pool.add("socks5://b:2")
    assert [e.url for e in _load_persisted_pool().list()] == ["http://a:1", "socks5://b:2"]
    assert not list(data_dir.glob("*.tmp"))


# --- credential redaction --------------------------------------------------


def test_proxy_list_redacts_credentials(data_dir: Path, monkeypatch) -> None:
    (data_dir / "proxies.json").write_text(
        json.dumps({"proxies": ["http://user:hunter2@host.example:8080"]}), encoding="utf-8"
    )
    # Wide console: a wrapped column could split the password across lines and
    # make the assertion pass for the wrong reason.
    monkeypatch.setattr(proxy_cmd, "_console", make_console(width=200))

    result = CliRunner().invoke(
        proxy_cmd.proxy_cmd,
        ["list", "--no-config-urls"],
        obj={"config": Config()},
        catch_exceptions=False,
    )

    assert result.exit_code == 0
    assert "hunter2" not in result.output
    assert "host.example:8080" in result.output


# --- bounded fetch ---------------------------------------------------------


class _FakeResponse:
    """Mimics the parts of `requests.Response` the fetch command uses."""

    def __init__(self, body: bytes):
        self._body = body
        self.consumed = 0

    def raise_for_status(self) -> None:
        return None

    def iter_content(self, chunk_size=1, decode_unicode=False):
        for start in range(0, len(self._body), chunk_size):
            chunk = self._body[start : start + chunk_size]
            self.consumed += len(chunk)
            yield chunk

    @property
    def text(self) -> str:
        self.consumed = len(self._body)  # the unbounded read this test forbids
        return self._body.decode("utf-8")

    def close(self) -> None:
        return None

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def test_fetch_caps_the_response_body(data_dir: Path, monkeypatch) -> None:
    """A hostile proxy-list URL must not stream gigabytes into memory."""
    import requests

    body = b"1.2.3.4:8080\n" * 800_000  # ~10 MB
    fake = _FakeResponse(body)
    monkeypatch.setattr(requests, "get", lambda *a, **kw: fake)

    result = CliRunner().invoke(
        proxy_cmd.proxy_cmd,
        ["fetch", "--source", "https://example.invalid/list.txt", "--limit", "5"],
        obj={"config": Config()},
        catch_exceptions=False,
    )

    assert result.exit_code == 0
    assert fake.consumed <= proxy_cmd.MAX_FETCH_BYTES + 65536, (
        f"read {fake.consumed} bytes from the proxy list; the cap is "
        f"{proxy_cmd.MAX_FETCH_BYTES}"
    )
    assert os.path.exists(data_dir / "proxies.json")
