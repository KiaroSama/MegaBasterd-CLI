"""Upload hardening: symlink leaks, fabricated handles, deterministic retries.

Historical bugs:
- Every upload walk used a bare ``rglob("*")``, so a symlinked FILE passed
  ``is_file()`` and was uploaded — ``notes.lnk -> ~/.ssh/id_rsa`` published a
  private key — while a symlinked DIRECTORY became an empty remote folder.
- A completion response without an ``f`` array made ``_register_node`` return
  the completion token hex AS IF it were a node handle; the caller then cleared
  the resume state and reported success for a node that may never have existed.
- The chunk retry predicate matched the BASE ``TransferError``, so deterministic
  failures (``ProxyRequiredError``, ``TransferCancelled``) were retried five
  times with exponential backoff before returning the same answer.
"""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests
from tenacity import wait_none

import megabasterd_cli.config as config_module
import megabasterd_cli.core.uploader as uploader_module
from megabasterd_cli.core.chunks import iter_chunks
from megabasterd_cli.core.errors import (
    RetryableTransferError,
    TransferCancelled,
    TransferError,
)
from megabasterd_cli.core.state import load_state
from megabasterd_cli.core.uploader import (
    MAX_UPLOAD_RESPONSE_BYTES,
    MegaUploader,
    UploadResult,
    walk_upload_entries,
)
from megabasterd_cli.proxy.selector import ProxyRequiredError

UPLOAD_URL = "https://gfs270n123.userstorage.mega.co.nz/ul/fake"


def _symlink(link: Path, target: Path, *, target_is_directory: bool = False) -> None:
    """Create a symlink, or skip the test where the OS/user cannot."""
    try:
        os.symlink(target, link, target_is_directory=target_is_directory)
    except (OSError, NotImplementedError) as exc:  # Windows without privileges
        pytest.skip(f"symlinks unavailable on this platform/user: {exc}")


# ---------------------------------------------------------------------------
# P1-20 - symlinks must never be walked into an upload
# ---------------------------------------------------------------------------


def test_symlinked_file_is_skipped_and_counted(tmp_path: Path):
    secret = tmp_path / "id_rsa"
    secret.write_text("PRIVATE KEY", encoding="utf-8")
    source_dir = tmp_path / "docs"
    source_dir.mkdir()
    (source_dir / "real.txt").write_text("real", encoding="utf-8")
    _symlink(source_dir / "notes.lnk", secret)

    entries, skipped = walk_upload_entries(source_dir)

    assert [p.name for p in entries] == ["real.txt"]
    assert skipped == 1


def test_symlinked_directory_and_its_contents_are_skipped(tmp_path: Path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret", encoding="utf-8")
    source_dir = tmp_path / "docs"
    source_dir.mkdir()
    (source_dir / "real.txt").write_text("real", encoding="utf-8")
    _symlink(source_dir / "linked", outside, target_is_directory=True)

    entries, skipped = walk_upload_entries(source_dir)

    assert [p.name for p in entries] == ["real.txt"]
    # The link itself, plus anything rglob yielded underneath it.
    assert skipped >= 1
    assert not any("linked" in p.parts for p in entries)


def test_upload_directory_never_uploads_a_symlinked_file(tmp_path: Path):
    """The end-to-end regression: the walk inside `upload_directory` itself."""
    secret = tmp_path / "id_rsa"
    secret.write_text("PRIVATE KEY", encoding="utf-8")
    source_dir = tmp_path / "docs"
    source_dir.mkdir()
    (source_dir / "real.txt").write_text("real", encoding="utf-8")
    _symlink(source_dir / "notes.lnk", secret)

    uploaded: list[Path] = []
    created_folders: list[str] = []

    uploader = MegaUploader.__new__(MegaUploader)
    uploader.client = SimpleNamespace(
        find_root=lambda: "root",
        mkdir=lambda name, parent_handle=None: created_folders.append(name) or f"folder-{name}",
    )

    def _upload_file(path, target_handle=None, on_progress=None):
        uploaded.append(path)
        return UploadResult(
            file_handle="H", name=path.name, size=path.stat().st_size, elapsed_seconds=0.0
        )

    uploader.upload_file = _upload_file

    uploader.upload_directory(source_dir)

    assert [p.name for p in uploaded] == ["real.txt"]
    assert not uploader.last_directory_failures


def test_upload_directory_does_not_create_a_folder_for_a_symlinked_directory(tmp_path: Path):
    outside = tmp_path / "outside"
    outside.mkdir()
    source_dir = tmp_path / "docs"
    source_dir.mkdir()
    _symlink(source_dir / "linked", outside, target_is_directory=True)

    created: list[str] = []
    uploader = MegaUploader.__new__(MegaUploader)
    uploader.client = SimpleNamespace(
        find_root=lambda: "root",
        mkdir=lambda name, parent_handle=None: created.append(name) or f"folder-{name}",
    )
    uploader.upload_file = lambda *a, **k: pytest.fail("no files to upload")

    uploader.upload_directory(source_dir)

    # Only the tree root itself; never an empty stand-in for the symlink.
    assert created == ["docs"]


# ---------------------------------------------------------------------------
# P1-04 - a completion response without a node handle must not be faked
# ---------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, body: bytes = b"COMPLETION", status: int = 200):
        self.status_code = status
        # A real `requests.Response` exposes both; keep the double faithful.
        self.content = body

    def iter_content(self, chunk_size: int = 65536):
        for start in range(0, len(self.content), chunk_size):
            yield self.content[start : start + chunk_size]

    def close(self) -> None:
        pass


class _CompletionAPI:
    """API double whose `complete_upload` answer is configurable."""

    def __init__(self, completion: object):
        self.completion = completion

    def request_upload(self, size: int) -> dict:
        return {"p": UPLOAD_URL}

    def complete_upload(self, **kwargs) -> object:
        return self.completion


def _uploader_for(completion: object) -> MegaUploader:
    client = SimpleNamespace(
        session=SimpleNamespace(master_key=b"\x00" * 16),
        api=_CompletionAPI(completion),
        find_root=lambda: "root",
        invalidate_cache=lambda: None,
    )
    return MegaUploader(client=client, max_workers=1)


@pytest.fixture()
def upload_env(tmp_path, monkeypatch):
    monkeypatch.setattr(config_module, "data_dir", lambda: tmp_path / "data")

    def fake_post(url, data=b"", timeout=None, proxies=None, headers=None, stream=False):
        # Faithful to the real endpoint: a completion token comes back for the
        # chunk holding the file's LAST byte and for no other. The double used
        # to answer every chunk with a token, which the uploader now rejects as
        # the protocol violation it always was.
        offset = int(url.rsplit("/", 1)[-1])
        source = tmp_path / "file.bin"
        total = source.stat().st_size if source.exists() else offset + len(data)
        final = offset + len(data) >= total
        return _FakeResponse(b"COMPLETION" if final else b"")

    monkeypatch.setattr(uploader_module.requests, "post", fake_post)
    return tmp_path


@pytest.mark.parametrize(
    "completion",
    [
        {},  # no "f" array at all
        {"f": []},  # empty node list
        {"f": [{}]},  # node without a handle
        {"f": [{"h": ""}]},  # empty handle
        {"f": [{"h": 42}]},  # non-string handle
        {"f": "nope"},  # not a list
        "not-a-dict",
    ],
)
def test_ambiguous_completion_raises_and_preserves_resume_state(upload_env, completion):
    source = upload_env / "file.bin"
    source.write_bytes(b"\x07" * 4096)
    uploader = _uploader_for(completion)
    state_path = MegaUploader._upload_state_destination(source)

    with pytest.raises(TransferError, match="no usable node handle"):
        uploader.upload_file(source)

    assert load_state(state_path) is not None, "resume state must survive an ambiguous completion"


def test_valid_completion_still_returns_the_node_handle(upload_env):
    source = upload_env / "file.bin"
    source.write_bytes(b"\x07" * 4096)
    uploader = _uploader_for({"f": [{"h": "HANDLE"}]})

    result = uploader.upload_file(source)

    assert result.file_handle == "HANDLE"
    assert load_state(MegaUploader._upload_state_destination(source)) is None


def test_oversized_completion_body_is_rejected(upload_env, monkeypatch):
    source = upload_env / "file.bin"
    source.write_bytes(b"\x07" * 4096)
    huge = b"A" * (MAX_UPLOAD_RESPONSE_BYTES + 1)
    monkeypatch.setattr(
        uploader_module.requests,
        "post",
        lambda *a, **k: _FakeResponse(huge),
    )
    uploader = _uploader_for({"f": [{"h": "HANDLE"}]})
    chunk = next(iter(iter_chunks(4096)))
    state = SimpleNamespace(metadata={}, mark_chunk_done=lambda *a: None, total_size=4096)

    with pytest.raises(TransferError, match="more than"):
        MegaUploader._upload_chunk.retry_with(wait=wait_none())(
            uploader, UPLOAD_URL, source, chunk, b"\x00" * 16, b"\x00" * 8, state
        )


# ---------------------------------------------------------------------------
# P1-19 - deterministic failures must not be retried
# ---------------------------------------------------------------------------


def _count_chunk_attempts(tmp_path: Path, exc: BaseException) -> int:
    """Run `_upload_chunk` with a proxy selection that always raises `exc`."""
    source = tmp_path / "file.bin"
    source.write_bytes(b"\x07" * 4096)
    uploader = _uploader_for({"f": [{"h": "HANDLE"}]})
    attempts = 0

    def _raise():
        nonlocal attempts
        attempts += 1
        raise exc

    uploader._proxies_for_request = _raise
    chunk = next(iter(iter_chunks(4096)))
    state = SimpleNamespace(metadata={}, mark_chunk_done=lambda *a: None, total_size=4096)
    with pytest.raises(type(exc)):
        # `wait_none` keeps the assertion about ATTEMPT COUNT, not backoff time.
        MegaUploader._upload_chunk.retry_with(wait=wait_none())(
            uploader, UPLOAD_URL, source, chunk, b"\x00" * 16, b"\x00" * 8, state
        )
    return attempts


def test_proxy_required_error_is_not_retried(tmp_path: Path):
    assert _count_chunk_attempts(tmp_path, ProxyRequiredError(message="no proxy available")) == 1


def test_transfer_cancelled_is_not_retried(tmp_path: Path):
    assert _count_chunk_attempts(tmp_path, TransferCancelled(message="canceled")) == 1


def test_a_genuine_transport_failure_is_still_retried(tmp_path: Path):
    """The narrowing must not disable retries for genuine transport failures."""
    assert _count_chunk_attempts(tmp_path, requests.ConnectionError("reset")) == 5
    assert _count_chunk_attempts(tmp_path, requests.Timeout("slow")) == 5
    assert _count_chunk_attempts(tmp_path, RetryableTransferError(message="HTTP 503")) == 5


def test_an_unclassified_transfer_error_is_not_retried(tmp_path: Path):
    """The retry predicate is an allowlist, so an unclassified error is final.

    This assertion is the inverse of the one it replaces. A bare
    `TransferError` was being used to stand in for "genuine transport
    failure", but it is the BASE of every deterministic failure too - short
    read, oversized body, fixed 4xx - so matching it retried all of them.
    Transport failures now assert themselves by their own types above.
    """
    assert _count_chunk_attempts(tmp_path, TransferError(message="unclassified")) == 1
