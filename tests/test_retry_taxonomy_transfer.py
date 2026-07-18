"""A deterministic refusal must be raised once, not replayed eight times.

The chunk retry decorators matched on the BASE class `TransferError`, so
`ProxyRequiredError` (a policy refusal), `TransferCancelled` (a decision) and
a range violation the server will repeat identically were all retried with
exponential backoff - up to eight attempts per chunk for an answer that was
settled the moment it was raised. Worst case for a force-proxy run with an
exhausted pool: roughly two minutes of sleeping per chunk before the same
error surfaces anyway.
"""

from __future__ import annotations

import pytest
import requests

from megabasterd_cli.core.downloader import CdnUrlExpired, _is_transient_chunk_failure
from megabasterd_cli.core.errors import (
    IntegrityError,
    NonRetryableTransferError,
    TransferCancelled,
    TransferError,
)
from megabasterd_cli.proxy.selector import ProxyRequiredError


@pytest.mark.parametrize(
    "exc",
    [
        pytest.param(ProxyRequiredError(message="no proxy"), id="proxy-policy-refusal"),
        pytest.param(TransferCancelled(message="cancelled"), id="cancellation"),
        pytest.param(NonRetryableTransferError(message="range"), id="protocol-violation"),
        pytest.param(IntegrityError(message="mac"), id="integrity"),
    ],
)
def test_deterministic_failures_are_not_retried(exc):
    assert _is_transient_chunk_failure(exc) is False


@pytest.mark.parametrize(
    "exc",
    [
        pytest.param(requests.ConnectionError("reset"), id="connection-reset"),
        pytest.param(requests.Timeout("slow"), id="timeout"),
        pytest.param(CdnUrlExpired(message="expired"), id="cdn-url-expiry"),
        pytest.param(TransferError(message="upstream 503"), id="generic-transfer"),
    ],
)
def test_transient_failures_are_still_retried(exc):
    assert _is_transient_chunk_failure(exc) is True


def test_the_non_retryable_marker_is_a_transfer_error():
    """Existing command handlers must keep reporting these as transfer failures."""
    assert issubclass(NonRetryableTransferError, TransferError)
    assert issubclass(ProxyRequiredError, NonRetryableTransferError)
    assert issubclass(TransferCancelled, NonRetryableTransferError)


def test_a_policy_refusal_reaches_the_caller_after_one_attempt(monkeypatch):
    """End to end through the real decorator: one call, not eight."""
    from megabasterd_cli.core.chunks import Chunk
    from megabasterd_cli.core.downloader import MegaDownloader
    from megabasterd_cli.core.state import TransferState

    downloader = MegaDownloader(api=None, verify_integrity=False, max_workers=1)
    downloader._cdn_url = "https://cdn.invalid/f"
    attempts = []

    def _refuse(*args, **kwargs):
        attempts.append(1)
        raise ProxyRequiredError(message="pool exhausted")

    monkeypatch.setattr(downloader, "_proxies_for_request", _refuse)
    state = TransferState(
        transfer_type="download", source="x", destination="unused", total_size=4096
    )
    with pytest.raises(ProxyRequiredError):
        downloader._download_chunk(
            Chunk(index=0, offset=0, size=1024), b"\x00" * 16, b"\x00" * 8, "unused", state
        )

    assert len(attempts) == 1, f"policy refusal was retried {len(attempts)} times"
