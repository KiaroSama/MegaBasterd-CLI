"""One progress ticker, shared by the downloader and the uploader.

Both transfer loops need the same thing and had a private copy of it: emit
progress on a steady clock while work is in flight, then one final synchronous
emit so the consumer sees 100% of the bytes.

The clock is the point. Reporting once per completed future instead delivers
in late bursts, because `fut.result()` blocks on the FIRST unfinished future in
submission order - so a chunk that landed early is not reported until every
chunk before it has also finished.
"""

from __future__ import annotations

import contextlib
import logging
import threading
from collections.abc import Callable, Iterator

log = logging.getLogger(__name__)

TICK_SECONDS = 0.5
JOIN_TIMEOUT_SECONDS = 2.0


@contextlib.contextmanager
def progress_ticker(emit: Callable[[], None] | None, name: str) -> Iterator[None]:
    """Call `emit` every `TICK_SECONDS` on a daemon thread for this block.

    `emit=None` starts no thread at all, so a transfer with no progress
    consumer pays nothing.

    The final synchronous emit runs on CLEAN exit only: an exception leaving
    the block skips it, so a failed transfer never reports a completion figure
    it never reached. A raising `emit` is logged and never breaks the transfer.
    """
    if emit is None:
        yield
        return

    stop = threading.Event()

    def _loop() -> None:
        while not stop.wait(TICK_SECONDS):
            try:
                emit()
            except Exception:
                log.debug("Progress callback raised (%s)", name, exc_info=True)

    reporter = threading.Thread(target=_loop, name=name, daemon=True)
    reporter.start()
    try:
        yield
    finally:
        stop.set()
        reporter.join(timeout=JOIN_TIMEOUT_SECONDS)

    try:
        emit()
    except Exception:
        log.debug("Final progress callback raised (%s)", name, exc_info=True)
