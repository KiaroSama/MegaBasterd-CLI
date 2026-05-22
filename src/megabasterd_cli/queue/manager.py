"""Persistent transfer queue.

Stores a JSON list of pending/active/failed transfers so the CLI can pick
them up across runs. Each item is one download or upload job.
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path


class JobStatus(str, Enum):
    PENDING = "pending"
    ACTIVE = "active"
    DONE = "done"
    FAILED = "failed"
    CANCELED = "canceled"


class JobType(str, Enum):
    DOWNLOAD = "download"
    UPLOAD = "upload"


@dataclass
class QueueItem:
    id: str
    type: str  # JobType
    source: str  # URL for downloads, file path for uploads
    destination: str
    size: int = 0
    status: str = JobStatus.PENDING.value
    error: str | None = None
    account: str | None = None
    password: str | None = None
    created_iso: str = ""
    finished_iso: str | None = None

    @staticmethod
    def new_id() -> str:
        return uuid.uuid4().hex[:12]


class QueueManager:
    """JSON-file backed transfer queue."""

    def __init__(self, path: Path):
        self.path = path
        self.items: list[QueueItem] = []
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            self.items = []
            return
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
            self.items = [QueueItem(**i) for i in data]
        except (json.JSONDecodeError, OSError, TypeError):
            self.items = []

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump([asdict(i) for i in self.items], f, indent=2)
        os.replace(tmp, self.path)

    def add(self, item: QueueItem) -> str:
        import datetime as dt

        if not item.id:
            item.id = QueueItem.new_id()
        if not item.created_iso:
            item.created_iso = dt.datetime.now(dt.timezone.utc).isoformat()
        self.items.append(item)
        self.save()
        return item.id

    def remove(self, item_id: str) -> bool:
        before = len(self.items)
        self.items = [i for i in self.items if i.id != item_id]
        if len(self.items) != before:
            self.save()
            return True
        return False

    def update_status(self, item_id: str, status: JobStatus, error: str | None = None) -> None:
        import datetime as dt

        for item in self.items:
            if item.id == item_id:
                item.status = status.value
                if error:
                    item.error = error
                if status in (JobStatus.DONE, JobStatus.FAILED, JobStatus.CANCELED):
                    item.finished_iso = dt.datetime.now(dt.timezone.utc).isoformat()
                break
        self.save()

    def pending(self) -> list[QueueItem]:
        return [i for i in self.items if i.status == JobStatus.PENDING.value]

    def clear_done(self) -> int:
        before = len(self.items)
        self.items = [
            i
            for i in self.items
            if i.status not in (JobStatus.DONE.value, JobStatus.CANCELED.value)
        ]
        if len(self.items) != before:
            self.save()
        return before - len(self.items)
