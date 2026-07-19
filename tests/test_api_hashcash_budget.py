"""The hashcash phase of one API request has a TOTAL time budget.

`_send` retries a 402 up to three times, each with a fresh hashcash challenge.
With a per-solve timeout only, the budget multiplied by the attempt count: a
hostile (or merely unlucky) challenge could hold a single API request for
3 x the per-solve timeout of full-CPU work. The deadline is now computed once
per request and the REMAINING time is handed to each solve.
"""

from __future__ import annotations

import base64
import time

import pytest

from megabasterd_cli.core import api as api_module
from megabasterd_cli.core import hashcash as hashcash_module
from megabasterd_cli.core.api import MegaAPIClient

TOKEN_B64 = base64.urlsafe_b64encode(b"t" * 48).decode().rstrip("=")
CHALLENGE = f"1:200:{TOKEN_B64}"

BUDGET = 0.4


class _Challenge402:
    status_code = 402
    headers = {"X-Hashcash": CHALLENGE}

    def raise_for_status(self):
        return None

    def close(self):
        return None


class _AlwaysChallenges:
    """A server that answers every attempt with a fresh hashcash challenge."""

    def __init__(self):
        self.headers: dict = {}
        self.proxies: dict = {}
        self.sent: list = []

    def post(self, url, json=None, timeout=None, headers=None, proxies=None, stream=False):
        self.sent.append(dict(headers or {}))
        return _Challenge402()

    def close(self):
        return None


@pytest.fixture
def _slow_solver(monkeypatch):
    """A solver that burns exactly the time it is given before answering.

    It succeeds, so the server keeps handing out fresh challenges and the retry
    loop runs to its limit - the case where a per-attempt timeout multiplies.
    """
    handed_out: list[float] = []

    def _solve(challenge, timeout=hashcash_module.DEFAULT_TIMEOUT_S, workers=8):
        handed_out.append(timeout)
        time.sleep(max(0.0, timeout))
        return b"\x00\x00\x00\x00"

    monkeypatch.setattr(hashcash_module, "solve", _solve)
    monkeypatch.setattr(api_module, "HASHCASH_TOTAL_BUDGET_S", BUDGET)
    return handed_out


def _client(session) -> MegaAPIClient:
    client = MegaAPIClient(timeout=1)
    client._session = session
    client.set_session("fake-sid")
    return client


def test_total_hashcash_time_is_bounded_by_the_budget_not_budget_times_attempts(_slow_solver):
    client = _client(_AlwaysChallenges())
    started = time.monotonic()
    with pytest.raises(api_module.HashcashBudgetExceededError):
        client.request({"a": "ug"})
    elapsed = time.monotonic() - started
    assert elapsed < BUDGET * 2, (
        f"hashcash consumed {elapsed:.2f}s of a {BUDGET:.2f}s budget; "
        "the timeout is being restarted per retry attempt"
    )


def test_each_attempt_only_gets_the_time_that_is_left(_slow_solver):
    client = _client(_AlwaysChallenges())
    with pytest.raises(api_module.HashcashBudgetExceededError):
        client.request({"a": "ug"})
    assert sum(_slow_solver) <= BUDGET + 0.05, "the per-attempt slices must add up to one budget"
    assert all(t > 0 for t in _slow_solver), "a solve must never be started with no time left"


def test_direct_callers_keep_the_per_solve_timeout(monkeypatch):
    """The budget lives in api.py; build_solution_header's parameter still works."""
    seen: list[float] = []

    def _solve(challenge, timeout=hashcash_module.DEFAULT_TIMEOUT_S, workers=8):
        seen.append(timeout)
        return b"\x00\x00\x00\x00"

    monkeypatch.setattr(hashcash_module, "solve", _solve)
    header = hashcash_module.build_solution_header(CHALLENGE, timeout=2.5)
    assert seen == [2.5]
    assert header.startswith("1:200:")
