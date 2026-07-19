"""The upload-slot response must be validated before it is indexed.

Historical bug: every upload path read the slot URL as ``upload_info["p"]``
with no shape or type guard. A malformed or hostile ``a:u`` answer — a JSON
array, a bare string, an object without ``p``, or ``p`` as a number — escaped
as a raw ``KeyError: 'p'`` / ``TypeError`` and surfaced from the CLI catch-all
as ``Error: 'p'``. It is the same defect class already fixed with
``_expect_mapping``/``_expect_field`` and ``core/api.py``'s ``_parse_body``:
the boundary must raise a typed ``MegaError``.

Four call sites shared the defect — the fresh slot, the expiry refresh, the
zero-byte slot, and the zero-byte refresh — so all four route through one
validating helper now.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import megabasterd_cli.config as config_module
import megabasterd_cli.core.uploader as uploader_module
from megabasterd_cli.core.errors import MegaError
from megabasterd_cli.core.uploader import MegaUploader

# A response body that is not a usable upload slot. Each one used to escape as
# a raw KeyError/TypeError instead of a typed MegaError.
BAD_SLOTS = [
    {},  # no "p" at all
    {"q": "https://x"},  # wrong key
    {"p": 42},  # not a string
    {"p": None},  # explicit null
    {"p": ""},  # empty URL: POSTs would go to "/0"
    {"p": ["https://x"]},  # list instead of a URL
    ["https://x"],  # array instead of an object
    "https://x",  # bare string instead of an object
    None,  # no body at all
]


class _FakeResponse:
    def __init__(self, body: bytes = b"COMPLETION", status: int = 200):
        self.status_code = status
        self.content = body

    def iter_content(self, chunk_size: int = 65536):
        for start in range(0, len(self.content), chunk_size):
            yield self.content[start : start + chunk_size]

    def close(self) -> None:
        pass


class _SlotAPI:
    """API double whose `request_upload` answers are scripted in order."""

    def __init__(self, *answers: object):
        self.answers = list(answers)
        self.calls = 0

    def request_upload(self, size: int) -> object:
        self.calls += 1
        return self.answers[min(self.calls - 1, len(self.answers) - 1)]

    def complete_upload(self, **kwargs) -> dict:
        return {"f": [{"h": "HANDLE"}]}


def _uploader(api: _SlotAPI) -> MegaUploader:
    client = SimpleNamespace(
        session=SimpleNamespace(master_key=b"\x00" * 16),
        api=api,
        find_root=lambda: "root",
        invalidate_cache=lambda: None,
    )
    return MegaUploader(client=client, max_workers=1)


@pytest.fixture()
def upload_env(tmp_path, monkeypatch):
    monkeypatch.setattr(config_module, "data_dir", lambda: tmp_path / "data")
    monkeypatch.setattr(
        uploader_module.requests,
        "post",
        lambda *a, **k: _FakeResponse(b"COMPLETION"),
    )
    return tmp_path


@pytest.mark.parametrize("bad", BAD_SLOTS)
def test_malformed_slot_on_a_regular_upload_raises_a_typed_error(upload_env, bad):
    source: Path = upload_env / "file.bin"
    source.write_bytes(b"\x07" * 4096)
    up = _uploader(_SlotAPI(bad))

    with pytest.raises(MegaError):
        up.upload_file(source)


@pytest.mark.parametrize("bad", BAD_SLOTS)
def test_malformed_slot_on_a_zero_byte_upload_raises_a_typed_error(upload_env, bad):
    source: Path = upload_env / "empty.bin"
    source.write_bytes(b"")
    up = _uploader(_SlotAPI(bad))

    with pytest.raises(MegaError):
        up.upload_file(source)


def test_malformed_slot_on_the_expiry_refresh_raises_a_typed_error(upload_env, monkeypatch):
    """The refresh after an expired upload URL is a fourth indexing site."""
    source: Path = upload_env / "file.bin"
    source.write_bytes(b"\x07" * 4096)
    # First slot is valid, the refresh answer is malformed.
    up = _uploader(_SlotAPI({"p": "https://up.example/ul/ok"}, {}))
    # 403 makes the first chunk POST report an expired slot, forcing a refresh.
    monkeypatch.setattr(
        uploader_module.requests,
        "post",
        lambda *a, **k: _FakeResponse(b"", status=403),
    )

    with pytest.raises(MegaError):
        up.upload_file(source)


def test_malformed_slot_on_the_zero_byte_refresh_raises_a_typed_error(upload_env, monkeypatch):
    source: Path = upload_env / "empty.bin"
    source.write_bytes(b"")
    up = _uploader(_SlotAPI({"p": "https://up.example/ul/ok"}, {}))
    monkeypatch.setattr(
        uploader_module.requests,
        "post",
        lambda *a, **k: _FakeResponse(b"", status=403),
    )

    with pytest.raises(MegaError):
        up.upload_file(source)


def test_a_valid_slot_is_still_accepted(upload_env):
    """The guard must not reject the shape MEGA actually sends."""
    source: Path = upload_env / "file.bin"
    source.write_bytes(b"\x07" * 4096)
    up = _uploader(_SlotAPI({"p": "https://up.example/ul/ok"}))

    assert up.upload_file(source).file_handle == "HANDLE"
