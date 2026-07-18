"""Regression tests: an attacker-supplied X-Hashcash header must not be able to
exhaust memory, CPU, or wall-clock time.

P1-10: `version` was parsed but never validated, `easiness` fed a shift count
directly (10**10 -> ~136 MB integer, 10**15 -> MemoryError, -1 -> ValueError
"negative shift count"), the base64 token was fully decoded before its length
was checked, and the default solve timeout was 300 s inside a 3-attempt caller
loop (up to 15 minutes of full-CPU stall).
"""

from __future__ import annotations

import base64
import threading
import time

import pytest

import megabasterd_cli.core.hashcash as hashcash
from megabasterd_cli.core.hashcash import (
    MAX_EASINESS,
    TOKEN_BYTES,
    HashcashChallenge,
    HashcashError,
    parse_challenge,
)


def _b64url(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii").rstrip("=").replace("+", "-").replace("/", "_")


TOKEN_B64 = _b64url(b"A" * TOKEN_BYTES)


@pytest.mark.parametrize("easiness", [10**10, 10**15, -1, MAX_EASINESS + 1])
def test_out_of_range_easiness_rejected(easiness: int) -> None:
    """Huge / negative easiness must raise a typed error, not allocate or crash."""
    with pytest.raises(HashcashError, match="easiness"):
        parse_challenge(f"1:{easiness}:{TOKEN_B64}")


@pytest.mark.parametrize("easiness", [10**10, -1])
def test_out_of_range_easiness_rejected_on_direct_construction(easiness: int) -> None:
    """Bypassing parse_challenge must not bypass the bound either."""
    with pytest.raises(HashcashError, match="easiness"):
        HashcashChallenge(version=1, easiness=easiness, token=b"A" * TOKEN_BYTES)


@pytest.mark.parametrize("version", [0, 2, 999, -1])
def test_unsupported_version_rejected(version: int) -> None:
    with pytest.raises(HashcashError, match="version"):
        parse_challenge(f"{version}:192:{TOKEN_B64}")


def test_oversized_token_rejected_before_decode(monkeypatch) -> None:
    """The base64 blob is length-bounded before b64decode runs."""
    decoded = {"called": False}
    real_b64decode = hashcash.base64.b64decode

    def spy(*args, **kwargs):
        decoded["called"] = True
        return real_b64decode(*args, **kwargs)

    monkeypatch.setattr(hashcash.base64, "b64decode", spy)

    with pytest.raises(HashcashError, match="token"):
        parse_challenge("1:192:" + "A" * 10_000_000)

    assert not decoded["called"], "b64decode ran on an unbounded attacker blob"


def test_default_timeout_is_bounded() -> None:
    """The default must stay sane: api.py retries up to 3x on this default."""
    assert hashcash.DEFAULT_TIMEOUT_S <= 60.0
    assert hashcash.DEFAULT_TIMEOUT_S * 3 <= 120.0


def test_valid_challenge_still_parses() -> None:
    ch = parse_challenge(f"1:255:{TOKEN_B64}")
    assert ch.version == 1
    assert ch.easiness == 255
    assert ch.threshold > 0


def test_keyboard_interrupt_stops_workers(monkeypatch) -> None:
    """Ctrl-C in the poll loop must signal the workers, not leave them spinning."""
    monkeypatch.setenv("MEGABASTERD_HASHCASH_NATIVE", "0")

    running = threading.Event()

    def never_matches(nonce_bytes, token_repeated, threshold):
        running.set()
        time.sleep(0.01)
        return False

    monkeypatch.setattr(hashcash, "_check_nonce", never_matches)

    def boom(*args, **kwargs):
        running.wait(timeout=5.0)
        raise KeyboardInterrupt

    monkeypatch.setattr(hashcash, "wait", boom)

    challenge = HashcashChallenge(version=1, easiness=0, token=b"\x01" * TOKEN_BYTES)
    started = time.monotonic()
    with pytest.raises(KeyboardInterrupt):
        hashcash.solve(challenge, timeout=60.0, workers=2)
    elapsed = time.monotonic() - started

    # Without stop.set() in a finally the workers run to the 60 s deadline and
    # the ThreadPoolExecutor shutdown blocks on them.
    assert elapsed < 10.0, f"workers were not cancelled (took {elapsed:.1f}s)"
