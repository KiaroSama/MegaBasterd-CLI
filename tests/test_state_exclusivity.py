"""`save_state` writes the whole file blind - prove that is safe.

`save_state` serializes the in-memory `TransferState` and replaces the
`.mbstate` file wholesale. It never re-reads and merges. That is only correct
because exactly one process may own a destination at a time: the download path
holds a `.mbclaim` advisory lock from `claim_destination` until
`release_destination`, and the upload path holds a `.uplock` lease for the
whole transfer.

If that invariant ever breaks, blind overwrite silently loses committed
chunks - process A saves {1,2,3}, process B saves {1,2,4}, chunk 3 is gone
from the resume record and gets re-downloaded, or worse, is assumed present.

Nothing in the suite asserted the invariant that `save_state`'s design
depends on, so a future refactor of the claim/lease could quietly turn a
correct blind write into a lost-update bug. These tests use REAL subprocesses,
because the locks are advisory OS locks and are re-entrant within one process.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from megabasterd_cli.core.state import (
    TransferState,
    load_state,
    save_state,
    state_path_for,
)
from megabasterd_cli.utils.helpers import claim_destination, release_destination

REPO_SRC = str(Path(__file__).resolve().parents[1] / "src")


def _run_in_subprocess(body: str, timeout: int = 60) -> subprocess.CompletedProcess:
    """Run a snippet in a genuinely separate process."""
    script = textwrap.dedent(
        f"""
        import sys
        sys.path.insert(0, {REPO_SRC!r})
        {textwrap.indent(textwrap.dedent(body), "        ").lstrip()}
        """
    )
    return subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _state_for(destination: Path, chunks: list[int]) -> TransferState:
    state = TransferState(
        transfer_type="download",
        source="https://mega.invalid/file/X",
        destination=str(destination),
        total_size=4096,
    )
    for index in chunks:
        state.mark_chunk_done(index)
    return state


# ---------------------------------------------------------------------------
# The invariant blind overwrite rests on
# ---------------------------------------------------------------------------


def test_a_second_process_cannot_claim_a_held_destination(tmp_path):
    """The download claim is what makes a blind `save_state` safe."""
    target = tmp_path / "movie.mkv"
    claimed = claim_destination(target)
    try:
        result = _run_in_subprocess(
            f"""
            from pathlib import Path
            from megabasterd_cli.utils.helpers import claim_destination
            print(claim_destination(Path({str(target)!r})))
            """
        )
        assert result.returncode == 0, result.stderr
        other = result.stdout.strip()
    finally:
        release_destination(claimed)

    assert other != str(claimed), (
        "a second process claimed the SAME destination while it was held; "
        "save_state's blind overwrite would lose that process's chunks"
    )
    # Pin the actual outcome so the test cannot pass for the wrong reason
    # (a subprocess that merely failed would also produce "not equal").
    assert Path(other).name == "movie (1).mkv"


def test_the_two_processes_therefore_use_different_state_files(tmp_path):
    """Different destinations mean different `.mbstate` paths - no sharing."""
    target = tmp_path / "movie.mkv"
    claimed = claim_destination(target)
    try:
        result = _run_in_subprocess(
            f"""
            from pathlib import Path
            from megabasterd_cli.utils.helpers import claim_destination
            from megabasterd_cli.core.state import state_path_for
            print(state_path_for(claim_destination(Path({str(target)!r}))))
            """
        )
        assert result.returncode == 0, result.stderr
        other_state = result.stdout.strip()
    finally:
        release_destination(claimed)

    assert other_state != str(state_path_for(claimed))


def test_a_second_process_cannot_take_a_held_upload_lease(tmp_path):
    """The upload lease plays the same role for `.mbstate` on the upload path."""
    source = tmp_path / "payload.bin"
    source.write_bytes(b"x" * 128)

    holder = _run_in_subprocess(
        f"""
        from pathlib import Path
        from megabasterd_cli.core.uploader import MegaUploader, UploadInProgressError

        class _Client:
            session = object()
            api = object()

        source = Path({str(source)!r})
        uploader = MegaUploader(client=_Client())
        with uploader._upload_lease(source):
            try:
                with MegaUploader(client=_Client())._upload_lease(source):
                    print("SECOND-OWNER-ADMITTED")
            except UploadInProgressError:
                print("REFUSED")
        """
    )
    assert holder.returncode == 0, holder.stderr
    assert "REFUSED" in holder.stdout, holder.stdout


# ---------------------------------------------------------------------------
# What blind overwrite actually does, so the dependency is explicit
# ---------------------------------------------------------------------------


def test_save_state_replaces_rather_than_merges(tmp_path):
    """Document the behaviour the invariant above is protecting.

    This is not a bug - it is the design. The test exists so that anyone who
    weakens the claim/lease sees, in one place, exactly what that costs.
    """
    target = tmp_path / "movie.mkv"

    save_state(_state_for(target, [1, 2, 3]))
    assert load_state(target).completed_set == {1, 2, 3}

    # A writer holding an older view overwrites, it does not union.
    save_state(_state_for(target, [1, 2, 4]))

    reloaded = load_state(target)
    assert reloaded.completed_set == {1, 2, 4}
    assert 3 not in reloaded.completed_set


def test_repeated_marks_do_not_duplicate_a_chunk(tmp_path):
    """`completed_chunks` is a list; marking twice must not grow it."""
    target = tmp_path / "movie.mkv"
    state = _state_for(target, [1, 2])
    state.mark_chunk_done(2)
    state.mark_chunk_done(2, mac=b"\x01" * 16)

    save_state(state)

    assert load_state(target).completed_chunks.count(2) == 1


@pytest.mark.parametrize("held_by_first", [True, False])
def test_claim_is_released_for_reuse(tmp_path, held_by_first):
    """A released destination must become claimable again, or resume breaks."""
    target = tmp_path / "movie.mkv"
    first = claim_destination(target)
    if not held_by_first:
        release_destination(first)
        second = claim_destination(target)
        assert second == first
        release_destination(second)
    else:
        release_destination(first)
