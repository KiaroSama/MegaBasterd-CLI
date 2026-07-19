"""`proxy fetch` must never echo a source URL or an exception verbatim.

The failure loop collected `f"{url}: {exc}"` and the empty-result branch printed
`f"No proxies fetched. Errors: {errors}"` - a Python repr of that list. Both
halves are attacker-or-user-supplied: `--source` is a URL that can carry
`user:pass@` credentials, a signed query value or an API token, and `requests`
faithfully repeats the URL it was given inside the exception message, so the
same secret leaks twice per failure.

Redaction here is a DISPLAY concern only: the raw URL still has to reach
`requests.get`, and the fetch semantics (streaming read, byte cap, --limit,
selector, pool_transaction merge) must be untouched.
"""

from __future__ import annotations

import contextlib
import logging

import pytest
import requests

import megabasterd_cli.commands.proxy_cmd as pc

# `_run` supplies the real `Config()` that `proxy fetch` needs in ctx.obj;
# `_urls` reads the persisted store back.
from tests.test_proxy_pool_transaction import _run, _urls


@pytest.fixture
def pool_dir(tmp_path, monkeypatch):
    """Point the proxy store at an isolated directory (same as item 6's)."""
    monkeypatch.setattr("megabasterd_cli.proxy.runtime.data_dir", lambda: tmp_path)
    return tmp_path


PASSWORD = "SENTINEL_PASSWORD"
TOKEN = "SENTINEL_TOKEN"
CRED_SOURCE = f"https://user:{PASSWORD}@example.invalid/list"
TOKEN_SOURCE = f"https://example.invalid/list?token={TOKEN}"

# How a real failure echoes the secret back. The first two occurrences sit in
# canonical URL shapes; the last two are the same values stripped of their URL,
# which is exactly how `requests`/`urllib3` wrap a parse or proxy error.
EXC_TEXT = (
    f"Max retries exceeded with url: {CRED_SOURCE} "
    f"(fell back to {TOKEN_SOURCE}) "
    f"- rejected credentials user:{PASSWORD} and bare token {TOKEN}"
)


class _Resp:
    """Minimal stand-in for a streamed `requests` response."""

    def __init__(self, body: bytes):
        self._body = body
        self.closed = False

    def raise_for_status(self):
        return None

    def iter_content(self, chunk_size=65536):
        for i in range(0, len(self._body), chunk_size):
            yield self._body[i : i + chunk_size]

    def close(self):
        self.closed = True


def _blob(result, caplog) -> str:
    """Everything a human or a machine could read after the command ran."""
    parts = [result.output, repr(result.exception), caplog.text]
    # click<8.2 mixes stderr into output and raises on .stderr
    with contextlib.suppress(ValueError):
        parts.append(result.stderr)
    return "\n".join(p for p in parts if p)


def _assert_no_sentinels(result, caplog, *, where: str) -> None:
    blob = _blob(result, caplog)
    assert PASSWORD not in blob, f"password leaked in {where}: {blob[:600]}"
    assert TOKEN not in blob, f"token leaked in {where}: {blob[:600]}"


@pytest.fixture
def two_sources(monkeypatch):
    """`--source` takes one value, so the multi-source cases patch the table."""
    monkeypatch.setattr(pc, "_DEFAULT_FETCH_SOURCES", {"http": [CRED_SOURCE, TOKEN_SOURCE]})


@pytest.fixture(autouse=True)
def _capture_logs(caplog):
    caplog.set_level(logging.DEBUG)


# ---------------------------------------------------------------------------
# (a) every source failed - the branch that printed the repr of the list
# ---------------------------------------------------------------------------


def test_fetch_with_all_sources_failing_leaks_neither_sentinel(pool_dir, two_sources, caplog):
    def boom(url, **kwargs):
        raise requests.exceptions.ConnectionError(EXC_TEXT)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(requests, "get", boom)
        result = _run(["fetch", "--protocol", "http"], catch=True)

    _assert_no_sentinels(result, caplog, where="fetch/all-failed")


def test_fetch_failure_output_is_not_a_repr_of_an_exception_list(pool_dir, two_sources, caplog):
    def boom(url, **kwargs):
        raise requests.exceptions.ConnectionError(EXC_TEXT)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(requests, "get", boom)
        result = _run(["fetch", "--protocol", "http"], catch=True)

    assert "Errors: [" not in result.output, "raw list repr is still printed"
    # A structured message: the exception class, not a stringified traceback.
    assert "ConnectionError" in result.output, result.output


def test_fetch_failure_redacts_the_source_url_it_reports(pool_dir, caplog):
    def boom(url, **kwargs):
        raise requests.exceptions.ConnectionError("connection refused")

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(requests, "get", boom)
        result = _run(["fetch", "--source", CRED_SOURCE], catch=True)

    _assert_no_sentinels(result, caplog, where="fetch/single-source")
    assert "example.invalid" in result.output, "the redacted URL lost its host"


# ---------------------------------------------------------------------------
# (b) one source succeeded, another failed - the trailing error loop
# ---------------------------------------------------------------------------


def test_fetch_with_one_source_succeeding_leaks_neither_sentinel(pool_dir, two_sources, caplog):
    def half(url, **kwargs):
        if url == CRED_SOURCE:
            raise requests.exceptions.ConnectionError(EXC_TEXT)
        return _Resp(b"1.2.3.4:8080\n")

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(requests, "get", half)
        result = _run(["fetch", "--protocol", "http"], catch=True)

    assert result.exit_code == 0, result.output
    assert "http://1.2.3.4:8080" in _urls(pool_dir), "the successful source was dropped"
    _assert_no_sentinels(result, caplog, where="fetch/partial-success")


# ---------------------------------------------------------------------------
# semantics: redaction is display-only
# ---------------------------------------------------------------------------


def test_the_raw_source_url_is_still_requested(pool_dir, caplog):
    seen: list[str] = []

    def spy(url, **kwargs):
        seen.append(url)
        return _Resp(b"5.6.7.8:1080\n")

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(requests, "get", spy)
        result = _run(["fetch", "--source", CRED_SOURCE, "--limit", "1"], catch=True)

    assert result.exit_code == 0, result.output
    assert seen == [CRED_SOURCE], f"redaction reached the network call: {seen}"
    assert "http://5.6.7.8:1080" in _urls(pool_dir)
