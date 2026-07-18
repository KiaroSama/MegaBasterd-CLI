"""One live owner per source upload, across processes.

Two processes uploading the same local file resolved to the SAME resume state
path and the same MEGA upload slot, with no ownership marker anywhere in the
persisted state. They would trade `upload_url` values and completion tokens,
and the last writer would win.

`upload_file` now holds a whole-transfer lease. The lease is an advisory lock,
so a crashed owner releases it automatically - no stale-lease heuristic.
"""

from __future__ import annotations

import multiprocessing as mp
import types
from pathlib import Path

import pytest

from megabasterd_cli.core.uploader import MegaUploader, UploadInProgressError


def _client():
    return types.SimpleNamespace(
        session=types.SimpleNamespace(sid="sid", master_key=b"\x00" * 16, email="a@example.com"),
        api=None,
    )


@pytest.fixture()
def source(tmp_path) -> Path:
    path = tmp_path / "payload.bin"
    path.write_bytes(b"x" * 4096)
    return path


def test_two_uploaders_resolve_to_the_same_state(source):
    """The precondition that makes a lease necessary."""
    a, b = MegaUploader(client=_client()), MegaUploader(client=_client())
    assert str(a._upload_state_destination(source)) == str(b._upload_state_destination(source))


def test_a_second_live_owner_is_refused(source):
    """While one lease is held, another upload of the same source refuses."""
    holder = MegaUploader(client=_client())
    with holder._upload_lease(source):
        other = MegaUploader(client=_client())
        with pytest.raises(UploadInProgressError), other._upload_lease(source):
            pass


def test_the_lease_is_released_afterwards(source):
    """A finished transfer must not block the next one."""
    first = MegaUploader(client=_client())
    with first._upload_lease(source):
        pass
    second = MegaUploader(client=_client())
    with second._upload_lease(source):  # must not raise
        pass


def test_the_lease_is_released_when_the_upload_raises(source):
    first = MegaUploader(client=_client())
    with pytest.raises(RuntimeError), first._upload_lease(source):
        raise RuntimeError("transfer blew up")
    second = MegaUploader(client=_client())
    with second._upload_lease(source):  # the failed run must not leak its lease
        pass


def test_different_sources_do_not_block_each_other(tmp_path):
    one = tmp_path / "a.bin"
    two = tmp_path / "b.bin"
    one.write_bytes(b"a" * 10)
    two.write_bytes(b"b" * 10)
    holder = MegaUploader(client=_client())
    with holder._upload_lease(one):
        other = MegaUploader(client=_client())
        with other._upload_lease(two):  # unrelated file, must be allowed
            pass


def test_the_lease_sidecar_is_not_unlinked(source):
    """Unlinking it would let a third process take a second, independent lease
    on a fresh inode - the same race fixed for destination claims."""
    uploader = MegaUploader(client=_client())
    state_path = uploader._upload_state_destination(source)
    sidecar = Path(str(state_path) + ".uplock")
    with uploader._upload_lease(source):
        assert sidecar.exists()
    assert sidecar.exists(), "removing the sidecar re-opens the two-owner race"


def _hold_then_report(args):
    """Worker PROCESS: try to take the lease, report whether it succeeded."""
    directory, name = args
    import types as _types
    from pathlib import Path as FsPath

    from megabasterd_cli.core.uploader import MegaUploader as WorkerUploader
    from megabasterd_cli.core.uploader import UploadInProgressError as InProgress

    client = _types.SimpleNamespace(
        session=_types.SimpleNamespace(sid="sid", master_key=b"\x00" * 16, email="a@example.com"),
        api=None,
    )
    uploader = WorkerUploader(client=client)
    try:
        with uploader._upload_lease(FsPath(directory) / name):
            import time

            time.sleep(1.5)  # hold it while the parent tries
        return "acquired"
    except InProgress:
        return "refused"


def test_a_second_process_cannot_take_the_lease(source, tmp_path):
    """The real cross-process case, with an actual spawned process."""
    ctx = mp.get_context("spawn")  # Windows-compatible
    proc = ctx.Pool(1)
    async_result = proc.map_async(_hold_then_report, [(str(tmp_path), source.name)])

    # Wait until the child actually owns the lease, then try to take it here.
    holder = MegaUploader(client=_client())
    sidecar = Path(str(holder._upload_state_destination(source)) + ".uplock")
    import time

    deadline = time.monotonic() + 30
    took_it = None
    while time.monotonic() < deadline:
        if sidecar.exists():
            try:
                with holder._upload_lease(source):
                    took_it = True
                break
            except UploadInProgressError:
                took_it = False
                break
        time.sleep(0.05)

    results = async_result.get(timeout=60)
    proc.close()
    proc.join()

    assert results == ["acquired"], results
    assert took_it is False, "this process took a lease the child already owned"


def test_the_lease_survives_a_crashed_owner(tmp_path, source):
    """An advisory lock is dropped by the OS, so no stale lease can persist."""
    ctx = mp.get_context("spawn")
    proc = ctx.Process(target=_hold_then_report, args=((str(tmp_path), source.name),))
    proc.start()
    proc.join(timeout=60)

    uploader = MegaUploader(client=_client())
    with uploader._upload_lease(source):  # must be free again
        pass
