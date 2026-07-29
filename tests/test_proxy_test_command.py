"""`mb proxy test` must probe the pool without leaking what it stores.

The pool was write-only in practice: `proxy list` shows the entries and their
success/failure counters, but a freshly imported list has all-zero counters, so
the only way to learn that an entry was dead was to start a transfer and watch
it fail.

Three properties are load-bearing and each has a test here:

* the verdict - a listening socket is reachable, a closed port is not, and the
  exit code is non-zero only when NOTHING answered (that is what a
  `mb proxy test && mb download ...` script keys on);
* redaction - a pooled URL routinely carries `user:pass@`, and `proxy add` /
  `proxy import` store it exactly as typed, so the schemeless form that
  bypassed `redact_text` must go through `_safe_source`;
* rendering - the URLs come from a remote list or an arbitrary file, so the
  table must treat a cell as literal text and survive an unbalanced tag.

Bounds are tested too: the probes run concurrently, and the per-proxy timeout
comes from the existing `timeout_seconds` config rather than a new knob.

No probe here leaves the loopback interface: the "live" proxy is a real
listening socket bound on 127.0.0.1 and the "dead" one is a port that was just
released.
"""

from __future__ import annotations

import contextlib
import logging
import socket
import time

import pytest
from click.testing import CliRunner

from megabasterd_cli.commands import proxy_cmd as proxy_module
from megabasterd_cli.commands.proxy_cmd import proxy_cmd
from megabasterd_cli.ui.theme import make_console

PASSWORD = "SENTINEL_PASSWORD"
TOKEN = "SENTINEL_TOKEN"


@pytest.fixture
def pool_dir(tmp_path, monkeypatch):
    """Point the proxy store at an isolated directory (same as the other suites)."""
    monkeypatch.setattr("megabasterd_cli.proxy.runtime.data_dir", lambda: tmp_path)
    return tmp_path


@pytest.fixture(autouse=True)
def _wide_console(monkeypatch):
    """The auto-detected width (80) would wrap a cell and hide the evidence."""
    monkeypatch.setattr(proxy_module, "_console", make_console(width=400))


@pytest.fixture(autouse=True)
def _capture_logs(caplog):
    caplog.set_level(logging.DEBUG)


@pytest.fixture
def live_port():
    """A real listening socket on loopback - the only "reachable" proxy used."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(8)
    try:
        yield sock.getsockname()[1]
    finally:
        sock.close()


@pytest.fixture
def dead_port():
    """A port that was bound and released, so a connect is refused, not hung."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _run(args, **cfg_kwargs):
    from megabasterd_cli.config import Config

    return CliRunner().invoke(proxy_cmd, args, obj={"config": Config(**cfg_kwargs)})


def _blob(result, caplog) -> str:
    """Everything a human or a machine could read after the command ran."""
    parts = [result.output, repr(result.exception), caplog.text]
    # click<8.2 mixes stderr into output and raises on .stderr
    with contextlib.suppress(ValueError):
        parts.append(result.stderr)
    return "\n".join(p for p in parts if p)


# ---------------------------------------------------------------------------
# the verdict
# ---------------------------------------------------------------------------


def test_a_listening_socket_is_reported_reachable(pool_dir, live_port):
    assert _run(["add", f"http://127.0.0.1:{live_port}"]).exit_code == 0

    result = _run(["test"])

    assert result.exit_code == 0, result.output
    assert "yes" in result.output, result.output
    assert "ms" in result.output, f"no latency reported: {result.output}"


def test_a_closed_port_is_unreachable_and_exits_non_zero(pool_dir, dead_port):
    assert _run(["add", f"http://127.0.0.1:{dead_port}"]).exit_code == 0

    result = _run(["test"])

    assert result.exit_code == 1, result.output
    assert "no" in result.output, result.output
    # The reason has to survive: "unreachable" alone is not diagnosable.
    assert "Error" in result.output, f"no failure reason reported: {result.output}"


def test_one_reachable_proxy_is_enough_for_a_zero_exit(pool_dir, live_port, dead_port):
    assert _run(["add", f"http://127.0.0.1:{live_port}"]).exit_code == 0
    assert _run(["add", f"http://127.0.0.1:{dead_port}"]).exit_code == 0

    result = _run(["test"])

    assert result.exit_code == 0, result.output
    assert "yes" in result.output and "no" in result.output, result.output


def test_an_empty_pool_exits_non_zero(pool_dir):
    result = _run(["test"])

    assert result.exit_code == 1, result.output


def test_an_unparseable_entry_is_reported_not_raised(pool_dir):
    assert _run(["add", "not-a-proxy"]).exit_code == 0

    result = _run(["test"])

    assert result.exception is None or isinstance(result.exception, SystemExit), result.exception
    assert result.exit_code == 1, result.output


# ---------------------------------------------------------------------------
# redaction
# ---------------------------------------------------------------------------


def test_a_schemeless_entrys_password_never_reaches_the_output(pool_dir, dead_port, caplog):
    """The known trap: `redact_text` only matches AFTER a `scheme://`."""
    assert _run(["add", f"alice:{PASSWORD}@127.0.0.1:{dead_port}"]).exit_code == 0

    result = _run(["test"])

    assert PASSWORD not in _blob(result, caplog), _blob(result, caplog)[:600]
    assert "127.0.0.1" in result.output, "the redacted proxy lost its host"


def test_a_scheme_qualified_entrys_password_never_reaches_the_output(pool_dir, dead_port, caplog):
    assert _run(["add", f"http://bob:{PASSWORD}@127.0.0.1:{dead_port}"]).exit_code == 0

    result = _run(["test"])

    # Assert the verdict too: without it this passes while `test` does not exist.
    assert result.exit_code == 1, result.output
    assert PASSWORD not in _blob(result, caplog), _blob(result, caplog)[:600]


def test_a_credential_bearing_query_value_never_reaches_the_output(pool_dir, dead_port, caplog):
    assert _run(["add", f"http://127.0.0.1:{dead_port}/?token={TOKEN}"]).exit_code == 0

    result = _run(["test"])

    assert result.exit_code == 1, result.output
    assert TOKEN not in _blob(result, caplog), _blob(result, caplog)[:600]


def test_the_raw_url_is_still_probed(pool_dir, live_port, monkeypatch):
    """Redaction is a DISPLAY concern; the socket must see the real host."""
    raw = f"http://alice:{PASSWORD}@127.0.0.1:{live_port}"
    assert _run(["add", raw]).exit_code == 0
    seen: list[str] = []
    real_probe = proxy_module._probe
    monkeypatch.setattr(
        proxy_module, "_probe", lambda url, timeout: (seen.append(url), real_probe(url, timeout))[1]
    )

    result = _run(["test"])

    assert result.exit_code == 0, result.output
    assert seen == [raw], f"redaction reached the probe: {seen}"


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------


def test_unbalanced_markup_in_a_stored_url_does_not_brick_the_command(pool_dir):
    """`proxy fetch`/`import` accept any line; a raw Table dies on this forever."""
    assert _run(["add", "http://127.0.0.1[/bold]x:1"]).exit_code == 0

    result = _run(["test"])

    assert result.exception is None or isinstance(result.exception, SystemExit), result.exception
    assert "[/bold]" in result.output, f"the stored URL was parsed as markup: {result.output}"


# ---------------------------------------------------------------------------
# bounds
# ---------------------------------------------------------------------------


def test_the_per_proxy_timeout_comes_from_the_config(pool_dir, dead_port, monkeypatch):
    seen: list[float] = []
    monkeypatch.setattr(
        proxy_module, "_probe", lambda url, timeout: (seen.append(timeout), (False, "x"))[1]
    )
    assert _run(["add", f"http://127.0.0.1:{dead_port}"]).exit_code == 0

    _run(["test"], timeout_seconds=7)

    assert seen == [7], f"the probe did not use timeout_seconds: {seen}"


def test_the_probes_run_concurrently(pool_dir, monkeypatch):
    """Serially, eight 0.3s probes take 2.4s; concurrently they take ~0.3s."""
    monkeypatch.setattr(
        proxy_module, "_probe", lambda url, timeout: (time.sleep(0.3), (False, "slow"))[1]
    )
    for port in range(9001, 9009):
        assert _run(["add", f"http://127.0.0.1:{port}"]).exit_code == 0

    start = time.monotonic()
    _run(["test"])
    elapsed = time.monotonic() - start

    assert elapsed < 1.5, f"probes ran serially: {elapsed:.2f}s for 8 x 0.3s"


def test_a_probe_that_outlives_the_run_budget_does_not_hang_the_command(pool_dir, monkeypatch):
    """The whole run is capped, not just each socket: a stuck DNS lookup ignores
    the connect timeout, so the command must give up on its own."""
    monkeypatch.setattr(
        proxy_module, "_probe", lambda url, timeout: (time.sleep(3), (True, "never"))[1]
    )
    assert _run(["add", "http://127.0.0.1:9100"]).exit_code == 0

    start = time.monotonic()
    result = _run(["test"], timeout_seconds=1)
    elapsed = time.monotonic() - start

    assert elapsed < 2.5, f"the run was not capped: {elapsed:.2f}s"
    assert result.exit_code == 1, result.output


def test_a_pool_larger_than_the_thread_cap_still_reports(pool_dir, monkeypatch, caplog):
    """A queued probe is CANCELLED at shutdown, and a cancelled future is `done()`.

    So the `future.result() if future.done()` branch called `.result()` on it and
    got `CancelledError` instead of a verdict, destroying the whole report - the
    64 probes that DID answer included. A fetched list is routinely hundreds of
    entries against a 64-thread cap, so every entry past the cap is queued and
    this is the normal path for the command's main use, not a corner.
    """
    monkeypatch.setattr(proxy_module, "MAX_PROBE_THREADS", 1)
    monkeypatch.setattr(
        proxy_module, "_probe", lambda url, timeout: (time.sleep(3), (True, "never"))[1]
    )
    for port in (9201, 9202):
        assert _run(["add", f"http://127.0.0.1:{port}"]).exit_code == 0

    start = time.monotonic()
    result = _run(["test"], timeout_seconds=1)
    elapsed = time.monotonic() - start

    assert "CancelledError" not in _blob(result, caplog)
    assert result.exit_code == 1, result.output
    assert "0/2 reachable" in result.output, result.output
    # The run budget is one connect timeout per WAVE, so two entries against a
    # one-thread cap get 2s - still bounded, and still far under the 6s the
    # probes themselves want.
    assert elapsed < 4, f"the run was not capped: {elapsed:.2f}s"
    # Distinct reasons on purpose: one probe was tried and did not answer, the
    # other never got a socket. Calling the second "no" would be a wrong
    # verdict about a proxy that may be perfectly healthy.
    assert "no answer within" in result.output, result.output
    assert "not probed within the run budget" in result.output, result.output
