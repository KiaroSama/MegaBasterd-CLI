"""A MEGA quota block belongs to one exit IP, not to the clock.

`_get_with_quota_wait` used to answer every EOVERQUOTA the same way: sleep
`quota_wait_seconds`, then retry the route that was already refused. Upstream
MegaBasterd changes route instead. Two signals now cut that bounded backoff
short, and neither may extend it:

* a configured, non-cooled-down proxy pool is worth ONE immediate retry - the
  next request re-selects from the pool, so it can leave the blocked route;
* a local route change during the wait (VPN reconnect, redial, interface swap)
  invalidates the block, so the rest of the sleep is spent on a limit that no
  longer applies.

Nothing here sleeps real time or opens a socket to anyone: `time.sleep` is
recorded instead of performed, and the route probe is faked. The one test that
exercises the real probe asserts it is a UDP route lookup at a reserved
address - no packet, no DNS, no third party.
"""

from __future__ import annotations

import ipaddress
import socket

import pytest

from megabasterd_cli.core import downloader as dl_mod
from megabasterd_cli.core.downloader import MegaDownloader
from megabasterd_cli.core.errors import QuotaError
from megabasterd_cli.proxy.smart_proxy import SmartProxyPool

PROXY = "http://proxy.invalid:8080"


@pytest.fixture()
def slept(monkeypatch):
    """Record every sleep instead of performing it."""
    calls: list[float] = []
    monkeypatch.setattr("megabasterd_cli.core.downloader.time.sleep", calls.append)
    return calls


@pytest.fixture()
def steady_route(monkeypatch):
    """A local route that never changes - the boring default."""
    monkeypatch.setattr(dl_mod, "_local_route_fingerprint", lambda: "10.0.0.5", raising=False)


def _downloader(pool=None, *, force=False, wait=3600, loops=24) -> MegaDownloader:
    # `api` is never touched: every test drives `_get_with_quota_wait` directly
    # with its own callable, which is exactly what the real call sites pass.
    return MegaDownloader(
        api=object(),
        proxy_pool=pool,
        force_proxy=force,
        quota_wait_seconds=wait,
        quota_max_wait_loops=loops,
    )


def _fails_then_ok(times: int, calls: list[int]):
    """A callable that raises EOVERQUOTA `times` times, then succeeds."""

    def fn():
        calls.append(1)
        if len(calls) <= times:
            raise QuotaError(message="EOVERQUOTA")
        return "ok"

    return fn


# ---------------------------------------------------------------------------
# 1. Escalate to the proxy pool
# ---------------------------------------------------------------------------


def test_pool_route_is_tried_immediately_instead_of_being_waited_out(slept):
    """The whole point: a route the pool can change is not worth an hour."""
    dl = _downloader(SmartProxyPool([PROXY, "http://other.invalid:8080"]))
    calls: list[int] = []

    assert dl._get_with_quota_wait(_fails_then_ok(1, calls)) == "ok"
    assert len(calls) == 2
    assert slept == [], "a blocked route the pool can replace must not be slept off"


def test_escalation_is_one_shot_and_the_backoff_then_resumes(slept, steady_route):
    """One immediate retry, not a busy loop that burns the budget in a blink."""
    dl = _downloader(SmartProxyPool([PROXY]), wait=4)
    calls: list[int] = []

    assert dl._get_with_quota_wait(_fails_then_ok(2, calls)) == "ok"
    assert len(calls) == 3
    assert sum(slept) == pytest.approx(4), "only the first block skips the wait"


def test_escalation_does_not_extend_the_bounded_wait(slept, steady_route):
    """Escalation only ever REMOVES waiting from the same attempt budget."""
    dl = _downloader(SmartProxyPool([PROXY]), wait=2, loops=3)
    calls: list[int] = []

    with pytest.raises(QuotaError):
        dl._get_with_quota_wait(_fails_then_ok(99, calls))
    assert len(calls) == 3, "the attempt budget is unchanged"
    assert sum(slept) == pytest.approx(2), "3 attempts = 1 escalation + 1 wait + the refusal"


def test_no_pool_means_the_backoff_is_unchanged(slept, steady_route):
    dl = _downloader(None, wait=6)
    calls: list[int] = []

    assert dl._get_with_quota_wait(_fails_then_ok(1, calls)) == "ok"
    assert sum(slept) == pytest.approx(6)


def test_an_exhausted_pool_offers_no_route_so_the_wait_stands(slept, steady_route):
    """Force mode must not turn "should I wait?" into a hard failure.

    Asking the pool for availability must stay read-only: `select()` here would
    raise ProxyRequiredError under force_smart_proxy, and `pick()` would hand
    out an entry for a request nobody is making.
    """
    pool = SmartProxyPool([PROXY])
    for _ in range(SmartProxyPool.MAX_FAILURES):
        pool.report_failure(PROXY)
    assert pool.pick() is None, "precondition: the only proxy is on cooldown"

    dl = _downloader(pool, force=True, wait=4)
    calls: list[int] = []

    assert dl._get_with_quota_wait(_fails_then_ok(1, calls)) == "ok"
    assert sum(slept) == pytest.approx(4), "no available route means the backoff still applies"


def test_cancel_beats_pool_escalation(slept):
    """Ctrl+C during the first attempt stops it; it does not escalate."""
    dl = _downloader(SmartProxyPool([PROXY]))
    calls: list[int] = []

    def fn():
        calls.append(1)
        dl.stop()
        raise QuotaError(message="EOVERQUOTA")

    with pytest.raises(QuotaError):
        dl._get_with_quota_wait(fn)
    assert len(calls) == 1
    assert slept == []


# ---------------------------------------------------------------------------
# 2. Wake on a route change
# ---------------------------------------------------------------------------


def _routes(monkeypatch, values):
    seq = iter(values)
    last = values[-1]
    monkeypatch.setattr(dl_mod, "_local_route_fingerprint", lambda: next(seq, last), raising=False)


def test_a_route_change_ends_the_wait_early(slept, monkeypatch):
    # baseline, one unchanged tick, then the VPN comes back on a new address.
    _routes(monkeypatch, ["10.0.0.5", "10.0.0.5", "10.9.9.9"])
    dl = _downloader(None, wait=3600)
    calls: list[int] = []

    assert dl._get_with_quota_wait(_fails_then_ok(1, calls)) == "ok"
    assert len(calls) == 2
    assert sum(slept) == pytest.approx(4), "two 2s ticks, not the full hour"


def test_an_unreadable_route_is_not_a_route_change(slept, monkeypatch):
    """A probe that fails mid-wait must not be mistaken for a new IP."""
    _routes(monkeypatch, ["10.0.0.5", None, None])
    dl = _downloader(None, wait=4)
    calls: list[int] = []

    assert dl._get_with_quota_wait(_fails_then_ok(1, calls)) == "ok"
    assert sum(slept) == pytest.approx(4), "the full wait still applies"


def test_an_unreadable_baseline_disables_detection(slept, monkeypatch):
    """No baseline (no default route) degrades to the old behaviour, silently."""
    _routes(monkeypatch, [None, "10.9.9.9", "10.9.9.9"])
    dl = _downloader(None, wait=4)
    calls: list[int] = []

    assert dl._get_with_quota_wait(_fails_then_ok(1, calls)) == "ok"
    assert sum(slept) == pytest.approx(4)


def test_cancel_still_wins_over_the_wait(slept, steady_route):
    dl = _downloader(None, wait=6)
    calls: list[int] = []

    def fn():
        calls.append(1)
        dl.stop()
        raise QuotaError(message="EOVERQUOTA")

    with pytest.raises(QuotaError):
        dl._get_with_quota_wait(fn)
    assert len(calls) == 1
    assert slept == []


def test_route_probe_asks_the_kernel_not_a_third_party(monkeypatch):
    """The probe must be a UDP route lookup at a reserved address.

    A TCP connect (or a "what is my IP" service) would tell a host the user
    never chose that they are downloading right now. `connect()` on a datagram
    socket transmits nothing - it only makes the kernel pick a route and bind a
    source address - and 192.0.2.0/24 is the documentation range, which is
    never routed anywhere.
    """
    used: dict = {}

    class FakeSocket:
        def __init__(self, family, kind):
            used["family"], used["kind"] = family, kind

        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

        def connect(self, address):
            used["address"] = address

        def getsockname(self):
            return ("10.1.2.3", 51234)

        def send(self, *_a, **_k):
            raise AssertionError("the route probe must not transmit anything")

        sendto = send

    monkeypatch.setattr(dl_mod.socket, "socket", lambda family, kind: FakeSocket(family, kind))

    assert dl_mod._local_route_fingerprint() == "10.1.2.3"
    assert used["kind"] is socket.SOCK_DGRAM
    assert ipaddress.ip_address(used["address"][0]) in ipaddress.ip_network("192.0.2.0/24")


def test_route_probe_never_raises():
    """Whatever the host's networking looks like, the answer is str or None."""
    value = dl_mod._local_route_fingerprint()
    assert value is None or isinstance(value, str)
