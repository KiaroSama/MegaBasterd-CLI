"""Shared scaffolding for the queue test modules.

`add` was declared byte-identically in three `test_queue_*` files. It is not a
convenience wrapper over `QueueManager.add` - it also decides what a default
job looks like (a download of a throwaway link with no destination), so three
copies meant three places to change when `QueueItem` grows a required field,
and the first one missed would silently start building a different job than
the tests it feeds believe they asked for.
"""

from __future__ import annotations

from megabasterd_cli.queue.manager import JobType, QueueItem, QueueManager


def add(q: QueueManager, **kwargs) -> QueueItem:
    item = QueueItem(
        id=QueueItem.new_id(),
        type=kwargs.pop("type", JobType.DOWNLOAD.value),
        source=kwargs.pop("source", "https://mega.nz/file/x#y"),
        destination=kwargs.pop("destination", ""),
        **kwargs,
    )
    q.add(item)
    return item
