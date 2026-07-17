"""Upload resume identity, mutation detection, and zero-byte uploads.

Historical bugs:
- Upload state was matched by path+size only, so a same-size replaced or
  modified file silently reused old completed chunks (corrupt remote content).
- ``iter_chunks(0)`` yields nothing, so zero-byte uploads ended with
  "Upload finished without a completion token".
"""

from __future__ import annotations

import os
import time
from types import SimpleNamespace

import pytest

import megabasterd_cli.config as config_module
import megabasterd_cli.core.uploader as uploader_module
from megabasterd_cli.core.chunks import iter_chunks
from megabasterd_cli.core.errors import TransferError
from megabasterd_cli.core.state import TransferState, load_state, save_state
from megabasterd_cli.core.uploader import MegaUploader

UPLOAD_URL = "http://fake.invalid/upload"


class _FakeResponse:
    def __init__(self, body: bytes = b"", status: int = 200):
        self.status_code = status
        self.content = body

    def close(self) -> None:
        pass


class _DummyAPI:
    def __init__(self) -> None:
        self.completed: list[dict] = []
        self.upload_requests: list[int] = []

    def request_upload(self, size: int) -> dict:
        self.upload_requests.append(size)
        return {"p": UPLOAD_URL}

    def complete_upload(self, **kwargs) -> dict:
        self.completed.append(kwargs)
        return {"f": [{"h": "HANDLE"}]}


def _dummy_client(api: _DummyAPI | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        session=SimpleNamespace(master_key=b"\x00" * 16),
        api=api or _DummyAPI(),
        find_root=lambda: "root",
        invalidate_cache=lambda: None,
    )


def _write_state(source, file_size, done_chunks=(), token=b"TOKEN", identity=None):
    state_path = MegaUploader._upload_state_destination(source)
    metadata = {
        "upload_url": UPLOAD_URL,
        "aes_key": bytes(range(16)).hex(),
        "nonce": bytes(range(8)).hex(),
    }
    if token is not None:
        metadata["completion_token"] = token.hex()
    if identity is not None:
        metadata["source_identity"] = identity
    state = TransferState(
        transfer_type="upload",
        source=str(source),
        destination=str(state_path),
        total_size=file_size,
        metadata=metadata,
    )
    for chunk in done_chunks:
        state.mark_chunk_done(chunk.index, b"\x00" * 16)
    save_state(state)
    return state_path


@pytest.fixture()
def upload_env(tmp_path, monkeypatch):
    monkeypatch.setattr(config_module, "data_dir", lambda: tmp_path / "data")
    posts: list[str] = []

    def fake_post(url, data=b"", timeout=None, proxies=None, headers=None):
        posts.append(url)
        return _FakeResponse(b"COMPLETION")

    monkeypatch.setattr(uploader_module.requests, "post", fake_post)
    return SimpleNamespace(tmp_path=tmp_path, posts=posts)


def _make_source(tmp_path, size: int, name: str = "file.bin", fill: bytes = b"\x07"):
    source = tmp_path / name
    source.write_bytes(fill * size)
    return source


def test_identity_helpers_detect_content_change(tmp_path):
    source = _make_source(tmp_path, 1024)
    ident = MegaUploader._source_identity(source)
    assert MegaUploader._identities_match(ident, MegaUploader._source_identity(source))
    # Same size, different content (also restore mtime to isolate content check).
    st = source.stat()
    source.write_bytes(b"\x08" * 1024)
    os.utime(source, ns=(st.st_atime_ns, st.st_mtime_ns))
    assert not MegaUploader._identities_match(ident, MegaUploader._source_identity(source))


def test_identity_helpers_detect_metadata_change(tmp_path):
    source = _make_source(tmp_path, 1024)
    ident = MegaUploader._source_identity(source)
    os.utime(source, ns=(time.time_ns(), time.time_ns() + 10**9))
    assert not MegaUploader._identities_match(ident, MegaUploader._source_identity(source))


def test_legacy_state_without_identity_is_not_resumed(upload_env):
    """Old state (no source identity) restarts fresh instead of blind reuse."""
    file_size = 256 * 1024
    source = _make_source(upload_env.tmp_path, file_size)
    chunks = list(iter_chunks(file_size))
    state_path = _write_state(source, file_size, done_chunks=chunks)  # legacy: no identity

    uploader = MegaUploader(client=_dummy_client())
    result = uploader.upload_file(source)
    assert result.size == file_size
    # A fresh upload re-posts every chunk; blind resume would post nothing.
    assert len(upload_env.posts) == len(chunks)
    assert load_state(state_path) is None


def test_changed_content_same_size_rejects_resume(upload_env):
    file_size = 256 * 1024
    source = _make_source(upload_env.tmp_path, file_size)
    chunks = list(iter_chunks(file_size))
    identity = MegaUploader._source_identity(source)
    st = source.stat()
    source.write_bytes(b"\x09" * file_size)  # same size, new content
    os.utime(source, ns=(st.st_atime_ns, st.st_mtime_ns))
    _write_state(source, file_size, done_chunks=chunks, identity=identity)

    uploader = MegaUploader(client=_dummy_client())
    uploader.upload_file(source)
    assert len(upload_env.posts) == len(chunks), "stale chunks must not be reused"


def test_replaced_file_rejects_resume(upload_env):
    file_size = 256 * 1024
    source = _make_source(upload_env.tmp_path, file_size)
    chunks = list(iter_chunks(file_size))
    identity = MegaUploader._source_identity(source)
    _write_state(source, file_size, done_chunks=chunks, identity=identity)
    # Replace the file (new inode/mtime, same path/size/content pattern).
    replacement = upload_env.tmp_path / "replacement.bin"
    replacement.write_bytes(b"\x0a" * file_size)
    os.replace(replacement, source)

    uploader = MegaUploader(client=_dummy_client())
    uploader.upload_file(source)
    assert len(upload_env.posts) == len(chunks)


def test_unchanged_file_resumes(upload_env):
    file_size = 256 * 1024
    source = _make_source(upload_env.tmp_path, file_size)
    chunks = list(iter_chunks(file_size))
    identity = MegaUploader._source_identity(source)
    _write_state(source, file_size, done_chunks=chunks[:-1], identity=identity, token=None)

    uploader = MegaUploader(client=_dummy_client())
    result = uploader.upload_file(source)
    assert result.size == file_size
    # Only the single pending chunk is re-posted.
    assert len(upload_env.posts) == 1


def test_auto_resume_false_never_reuses_state(upload_env):
    file_size = 256 * 1024
    source = _make_source(upload_env.tmp_path, file_size)
    chunks = list(iter_chunks(file_size))
    identity = MegaUploader._source_identity(source)
    _write_state(source, file_size, done_chunks=chunks[:-1], identity=identity)

    uploader = MegaUploader(client=_dummy_client(), auto_resume=False)
    uploader.upload_file(source)
    assert len(upload_env.posts) == len(chunks)


def test_mutation_during_upload_detected_before_finalization(upload_env, monkeypatch):
    file_size = 128 * 1024
    source = _make_source(upload_env.tmp_path, file_size)
    api = _DummyAPI()
    uploader = MegaUploader(client=_dummy_client(api))

    original_post = uploader_module.requests.post

    def mutating_post(url, data=b"", timeout=None, proxies=None, headers=None):
        # Modify the source while its chunks are in flight.
        source.write_bytes(b"\x0b" * file_size)
        return original_post(url, data=data, timeout=timeout, proxies=proxies, headers=headers)

    monkeypatch.setattr(uploader_module.requests, "post", mutating_post)
    with pytest.raises(TransferError, match="changed while it was being uploaded"):
        uploader.upload_file(source)
    assert api.completed == [], "a corrupted upload must never be registered"
    assert load_state(MegaUploader._upload_state_destination(source)) is None


def test_zero_byte_upload_single(upload_env):
    source = _make_source(upload_env.tmp_path, 0)
    api = _DummyAPI()
    reports = []
    uploader = MegaUploader(client=_dummy_client(api))
    result = uploader.upload_file(source, on_progress=reports.append)

    assert result.size == 0
    assert result.file_handle == "HANDLE"
    assert api.upload_requests == [0], "zero-byte upload must request a 0-size slot"
    assert upload_env.posts == [f"{UPLOAD_URL}/0"]
    assert api.completed, "finalization request must occur"
    assert reports and reports[-1].total_bytes == 0  # no division errors


def test_zero_byte_file_in_directory_upload(upload_env):
    root = upload_env.tmp_path / "tree"
    (root / "sub").mkdir(parents=True)
    (root / "sub" / "empty.txt").write_bytes(b"")
    (root / "data.bin").write_bytes(b"\x01" * 1024)

    client = _dummy_client()
    client.mkdir = lambda name, parent_handle=None: f"dir-{name}"
    uploader = MegaUploader(client=client)
    manifest: list[list] = []
    results = uploader.upload_directory(root, on_manifest=lambda jobs: manifest.append(jobs))

    assert sorted(r.size for r in results) == [0, 1024]
    assert len(manifest[0]) == 2, "manifest must list every file with its size"
