"""A state file from a newer format version must survive an older client.

The save path already refuses to overwrite a newer-version `.mbstate`
(`_disk_guard` reads the version before the schema). The LOAD path used to
destroy the same file two different ways, defeating that protection:

* `load_state` validated against the CURRENT schema before looking at the
  version, so a newer file with a different shape was quarantined - which
  deletes the original after preserving a copy.
* Even a newer file that happened to satisfy the current schema made
  `load_state` return None, and the transfer's resume-or-fresh branch then
  called `clear_state`, deleting it.

Now `load_state` checks the version first and leaves an unrecognized-version
file intact, and the transfer refuses rather than clearing it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from megabasterd_cli.core.downloader import MegaDownloader
from megabasterd_cli.core.errors import TransferError
from megabasterd_cli.core.state import (
    STATE_FORMAT_VERSION,
    load_state,
    state_path_for,
    unrecognized_state_version,
)

NEWER = STATE_FORMAT_VERSION + 1


def _write_newer_state(destination: Path, *, valid_shape: bool) -> Path:
    sp = state_path_for(destination)
    doc = {"format_version": NEWER, "revision": 999}
    if valid_shape:
        # A document that also satisfies THIS version's schema, to prove the
        # deletion did not depend on the schema mismatch.
        doc.update(
            transfer_type="download",
            source="https://mega.nz/file/ID#<key>",
            destination=str(destination),
            total_size=1024,
            completed_chunks=[],
            chunk_macs={},
            metadata={},
        )
    else:
        doc["something_a_v2_client_added"] = {"nested": True}  # not this schema
    sp.write_text(json.dumps(doc), encoding="utf-8")
    return sp


@pytest.mark.parametrize("valid_shape", [True, False], ids=["passes-schema", "different-schema"])
def test_load_state_leaves_a_newer_version_file_intact(tmp_path, valid_shape):
    destination = tmp_path / "movie.bin"
    sp = _write_newer_state(destination, valid_shape=valid_shape)

    assert load_state(destination) is None  # declines to resume
    assert sp.is_file(), "load_state deleted a state file from a newer version"
    # And it was not quarantined either (no *.corrupt.* copy left behind).
    assert not list(tmp_path.glob("*.corrupt.*"))
    assert unrecognized_state_version(destination) == NEWER


@pytest.mark.parametrize("valid_shape", [True, False], ids=["passes-schema", "different-schema"])
def test_download_refuses_instead_of_deleting_a_newer_state(tmp_path, monkeypatch, valid_shape):
    destination = tmp_path / "movie.bin"
    sp = _write_newer_state(destination, valid_shape=valid_shape)

    downloader = MegaDownloader(api=None, auto_resume=True)

    # Never reached: the refusal happens before any chunk work.
    def fail(*a, **k):
        raise AssertionError("the transfer should have refused before downloading")

    monkeypatch.setattr(downloader, "_download_chunk", fail)

    with pytest.raises(TransferError, match=f"format version {NEWER}"):
        downloader._run_download(
            cdn_url="https://cdn.invalid/x",
            file_size=1024,
            aes_key=b"\x00" * 16,
            nonce=b"\x00" * 8,
            mac_iv_a32=(0, 0, 0, 0),
            destination=destination,
            source="https://mega.nz/file/ID#<key>",
            on_progress=None,
        )

    assert sp.is_file(), "the download deleted a newer-version state file instead of refusing"


def test_a_same_version_corrupt_file_is_still_quarantined(tmp_path):
    """The refusal is specific to a DIFFERENT version; a corrupt current-version
    file is still quarantined and cleared as before."""
    destination = tmp_path / "movie.bin"
    sp = state_path_for(destination)
    sp.write_text(json.dumps({"format_version": STATE_FORMAT_VERSION, "garbage": True}), "utf-8")

    assert load_state(destination) is None
    assert not sp.is_file(), "a corrupt current-version file should be quarantined (removed)"
    assert list(tmp_path.glob("*.corrupt.*")), "quarantine should have preserved a copy"
    assert unrecognized_state_version(destination) is None
