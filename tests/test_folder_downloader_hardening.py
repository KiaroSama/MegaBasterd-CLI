"""Regressions for hostile folder graphs (B6) and option forwarding (C8)."""

from __future__ import annotations

import inspect
import threading
from pathlib import Path

import pytest

from megabasterd_cli.core import downloader as downloader_module
from megabasterd_cli.core.errors import NonRetryableTransferError, TransferError
from megabasterd_cli.core.folder_downloader import FolderNode, MegaFolderDownloader


def _folder(handle: str, parent: str, name: str) -> FolderNode:
    return FolderNode(handle=handle, parent=parent, node_type=1, size=0, name=name, key=b"")


def _file(handle: str, parent: str, name: str) -> FolderNode:
    return FolderNode(
        handle=handle,
        parent=parent,
        node_type=0,
        size=10,
        name=name,
        key=b"",
        raw_key_a32=[0] * 8,
    )


def _cyclic_nodes() -> list[FolderNode]:
    """A.p=B, B.p=A: neither folder ever reaches the root."""
    return [
        _folder("root", "", "Root"),
        _folder("A", "B", "Loop A"),
        _folder("B", "A", "Loop B"),
        _file("victim", "A", "payload.bin"),
    ]


def _run_bounded(fn, timeout: float = 5.0):
    """Run `fn` in a thread; a hang fails the test instead of freezing CI."""
    box: dict[str, BaseException | object] = {}

    def _target() -> None:
        try:
            box["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 - re-raised on the main thread
            box["error"] = exc

    thread = threading.Thread(target=_target, daemon=True)
    thread.start()
    thread.join(timeout)
    assert not thread.is_alive(), f"call did not terminate within {timeout}s (cycle hang)"
    if "error" in box:
        raise box["error"]  # type: ignore[misc]
    return box["value"]


# --- B6: a cyclic parent chain must error, never hang -----------------------


def test_build_file_jobs_rejects_cyclic_parent_chain(tmp_path: Path):
    with pytest.raises(NonRetryableTransferError, match="cyclic"):
        _run_bounded(
            lambda: MegaFolderDownloader._build_file_jobs(_cyclic_nodes(), tmp_path, "root")
        )


def test_sort_by_depth_rejects_cyclic_parent_chain():
    with pytest.raises(NonRetryableTransferError, match="cyclic"):
        _run_bounded(lambda: MegaFolderDownloader._sort_by_depth(_cyclic_nodes(), "root"))


def test_local_path_for_node_rejects_cyclic_parent_chain(tmp_path: Path):
    nodes = _cyclic_nodes()
    victim = next(n for n in nodes if n.handle == "victim")
    with pytest.raises(NonRetryableTransferError, match="cyclic"):
        _run_bounded(
            lambda: MegaFolderDownloader._local_path_for_node(nodes, tmp_path, "root", victim)
        )


def test_a_cycle_is_a_transfer_error_subclass():
    """CLI error handling keys off TransferError; keep the cycle error inside it."""
    assert issubclass(NonRetryableTransferError, TransferError)


def test_healthy_graph_still_builds_normally(tmp_path: Path):
    nodes = [
        _folder("root", "", "Root"),
        _folder("sub", "root", "Sub"),
        _file("f", "sub", "a.bin"),
    ]
    jobs = MegaFolderDownloader._build_file_jobs(nodes, tmp_path, "root")
    assert jobs[0][1] == tmp_path / "Root" / "Sub" / "a.bin"
    assert (
        MegaFolderDownloader._local_path_for_node(nodes, tmp_path, "root", nodes[2])
        == tmp_path / "Root" / "Sub" / "a.bin"
    )


# --- C8: every MegaDownloader option must reach the parallel workers --------

# Options the parallel path deliberately does NOT pass to the constructor.
# `api` is a per-worker clone (one mutable Session per concurrent transfer);
# `speed_limit_kbps` is superseded by the shared limiter so the command-wide
# cap is not multiplied per worker; `limiter` is assigned right after
# construction instead (asserted behaviourally below).
INTENTIONALLY_DIFFERENT = {"api", "speed_limit_kbps", "limiter"}


_REAL_DOWNLOADER = downloader_module.MegaDownloader


class _FakeApi:
    def clone(self):
        return _FakeApi()

    def close(self):
        pass


class _RecordingDownloader:
    calls: list[dict] = []
    instances: list[_RecordingDownloader] = []

    def __init__(self, **kwargs):
        _RecordingDownloader.calls.append(kwargs)
        _RecordingDownloader.instances.append(self)
        self.api = kwargs["api"]


def _run_parallel_worker(monkeypatch, tmp_path: Path):
    """Drive one parallel job against a recording stub; return (parent, stub)."""
    parent = _REAL_DOWNLOADER(
        api=_FakeApi(), auto_resume=False, user_agent="MegaBasterd-CLI/custom-agent"
    )
    folder = MegaFolderDownloader(parent)

    _RecordingDownloader.calls = []
    _RecordingDownloader.instances = []
    monkeypatch.setattr(downloader_module, "MegaDownloader", _RecordingDownloader)

    # The stub has no `_get_with_quota_wait`, so the job fails right after the
    # worker downloader is built - which is all these tests observe.
    with pytest.raises(TransferError):
        folder._download_file_jobs(
            "pubid", [(_file("f", "root", "a.bin"), tmp_path / "a.bin")], parallel_files=2
        )
    assert _RecordingDownloader.calls, "parallel path never constructed a worker downloader"
    return parent, _RecordingDownloader.instances[0]


def _forwarded_kwargs(monkeypatch, tmp_path: Path) -> dict:
    _run_parallel_worker(monkeypatch, tmp_path)
    return _RecordingDownloader.calls[0]


def test_parallel_workers_forward_every_downloader_option(monkeypatch, tmp_path: Path):
    """Guard: a new MegaDownloader option must be forwarded here or allow-listed."""
    expected = {
        name
        for name in inspect.signature(_REAL_DOWNLOADER.__init__).parameters
        if name not in {"self"} | INTENTIONALLY_DIFFERENT
    }
    missing = expected - set(_forwarded_kwargs(monkeypatch, tmp_path))
    assert not missing, f"parallel folder workers drop MegaDownloader options: {sorted(missing)}"


def test_parallel_workers_forward_auto_resume_and_user_agent(monkeypatch, tmp_path: Path):
    kwargs = _forwarded_kwargs(monkeypatch, tmp_path)
    assert kwargs["auto_resume"] is False
    assert kwargs["user_agent"] == "MegaBasterd-CLI/custom-agent"


def test_parallel_workers_share_the_parent_limiter_object(monkeypatch, tmp_path: Path):
    """`limiter` is allow-listed above, so pin its behaviour here instead."""
    parent, worker = _run_parallel_worker(monkeypatch, tmp_path)
    assert worker.limiter is parent.limiter
