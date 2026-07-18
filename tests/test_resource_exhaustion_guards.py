"""Memory must never be sized by something an attacker chose.

Three separate places sized an allocation from untrusted input:

* `decode_elc_payload` gunzipped a blob taken straight from the PASTED LINK,
  before credentials were looked up and before any network call. Deflate
  reaches ~1029:1, so a 544 KB link expanded to 400 MiB and a 5 MB link to
  ~8 GB.
* Service responses were parsed with `response.json()` / `.text`, which buffer
  AND gzip-inflate the whole body first. The DLC cap tried to catch this with
  `len(response.text) > MAX` - a check that runs only after the damage is done.
  The chunk downloader had no ceiling at all on its `iter_content` accumulator.
* The chunk plan was built from a SERVER-DECLARED file size. A hostile
  MegaCrypter host declaring 1 PiB yields ~1.07 billion Chunk objects
  (~172 GiB) in a loop that runs for hours, before the first HTTP request.

Every test here asserts the guard FIRES; none of them allocates the sizes that
made the original reports interesting.
"""

from __future__ import annotations

import gzip

import pytest

from megabasterd_cli.core import link_services as ls
from megabasterd_cli.core.chunks import MAX_CHUNKS, MAX_FILE_SIZE, Chunk, chunk_count, iter_chunks
from megabasterd_cli.core.crypto import b64_url_encode
from megabasterd_cli.core.downloader import (
    DeclaredSizeError,
    InsufficientDiskSpaceError,
    MegaDownloader,
)
from megabasterd_cli.core.errors import NonRetryableTransferError
from megabasterd_cli.core.links import parse_link
from megabasterd_cli.proxy.selector import ProxySelector

# ---------------------------------------------------------------------------
# B7 - decompression bombs in the link payload
# ---------------------------------------------------------------------------


def _elc_link(payload: bytes):
    return parse_link("mega://elc?" + b64_url_encode(payload))


def test_gzipped_elc_link_cannot_inflate_without_bound():
    """A tiny link must not be able to decide how many MiB we allocate."""
    bomb = gzip.compress(b"\x00" * (ls.MAX_ELC_DECOMPRESSED_BYTES + 1))
    assert len(bomb) < 100_000, "the point is that the compressed link stays small"
    with pytest.raises(ls.PayloadTooLargeError, match="expands beyond"):
        ls.decode_elc_payload(_elc_link(bytes([0x70]) + bomb))


def test_oversized_compressed_elc_link_is_refused_up_front():
    with pytest.raises(ls.PayloadTooLargeError, match="Compressed ELC payload"):
        ls.decode_elc_payload(
            _elc_link(bytes([0x70]) + b"\x00" * (ls.MAX_ELC_COMPRESSED_BYTES + 1))
        )


def test_a_normal_gzipped_elc_link_still_decodes():
    service_url = "https://elc.example/api"
    inner = (
        (0).to_bytes(4, "little")
        + len(service_url).to_bytes(2, "little")
        + service_url.encode()
        + (3).to_bytes(2, "little")
        + b"tok"
    )
    payload = ls.decode_elc_payload(_elc_link(bytes([0x70]) + gzip.compress(inner)))
    assert payload.service_url == service_url
    assert payload.data_token == "tok"


def test_corrupt_gzip_is_reported_as_a_bad_payload_not_a_size_problem():
    with pytest.raises(ValueError, match="Corrupt ELC payload"):
        ls.decode_elc_payload(_elc_link(bytes([0x70]) + b"not gzip at all"))


# ---------------------------------------------------------------------------
# B7 - unbounded response bodies
# ---------------------------------------------------------------------------


class _EndlessResponse:
    """A response whose body never ends; records how much was actually pulled."""

    status_code = 200
    headers: dict = {}
    encoding = "utf-8"

    def __init__(self) -> None:
        self.yielded = 0
        self.closed = False

    def iter_content(self, chunk_size=65536):
        while True:
            self.yielded += chunk_size
            yield b"x" * chunk_size

    def raise_for_status(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True


def _endless_post(monkeypatch):
    response = _EndlessResponse()
    monkeypatch.setattr("requests.post", lambda *a, **kw: response)
    return response


def test_elc_response_is_bounded_while_reading(monkeypatch):
    response = _endless_post(monkeypatch)
    service_url = "https://elc.example/api"
    payload = (
        bytes([0xB9])
        + (0).to_bytes(4, "little")
        + len(service_url).to_bytes(2, "little")
        + service_url.encode()
        + (3).to_bytes(2, "little")
        + b"tok"
    )
    with pytest.raises(ls.PayloadTooLargeError):
        ls.resolve_elc_links(
            _elc_link(payload), user="u", api_key="k", selector=ProxySelector(force=False)
        )
    assert response.yielded <= ls.MAX_SERVICE_RESPONSE_BYTES + 65536
    assert response.closed


def test_megacrypter_response_is_bounded_while_reading(monkeypatch):
    response = _endless_post(monkeypatch)
    with pytest.raises(ls.PayloadTooLargeError):
        ls.get_megacrypter_info(
            parse_link("mc://mc.example/token"), selector=ProxySelector(force=False)
        )
    assert response.yielded <= ls.MAX_SERVICE_RESPONSE_BYTES + 65536


def test_dlc_response_is_bounded_while_reading(monkeypatch):
    """The old `len(response.text) > MAX` cap ran only after the full inflate."""
    response = _endless_post(monkeypatch)
    with pytest.raises(ls.PayloadTooLargeError, match="large"):
        ls.decrypt_dlc_container("B" * 100, selector=ProxySelector(force=False))
    assert response.yielded <= ls.MAX_DLC_RESPONSE_BYTES + 65536


def test_service_responses_are_requested_as_streams():
    """`stream=True` is what makes the cap possible; without it the body is
    already buffered and inflated by the time any check could run."""
    import inspect

    for fn in (ls.resolve_elc_links, ls._post_megacrypter, ls._dlc_post):
        assert "stream=True" in inspect.getsource(fn), fn.__name__


# ---------------------------------------------------------------------------
# B7 - unbounded chunk accumulation in the downloader
# ---------------------------------------------------------------------------

TOTAL = 4 * 1024 * 1024


class _OverlongChunkResponse:
    """A valid-looking 206 with no Content-Length and an endless body.

    `range_validation` only checks Content-Length IF PRESENT, so this response
    passes range validation and then streams forever.
    """

    status_code = 206

    def __init__(self, offset: int, size: int) -> None:
        self.headers = {"Content-Range": f"bytes {offset}-{offset + size - 1}/{TOTAL}"}
        self.yielded = 0

    def iter_content(self, chunk_size=65536):
        while True:
            self.yielded += chunk_size
            yield b"y" * chunk_size

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def close(self) -> None:
        return None


def test_chunk_body_cannot_exceed_the_requested_range(monkeypatch):
    from megabasterd_cli.core.state import TransferState

    offset, size = 1024, 1024
    response = _OverlongChunkResponse(offset, size)
    downloader = MegaDownloader(api=None, verify_integrity=False, max_workers=1)
    downloader._cdn_url = "https://cdn.invalid/file"
    monkeypatch.setattr("megabasterd_cli.core.downloader.requests.get", lambda *a, **kw: response)
    state = TransferState(
        transfer_type="download",
        source="https://mega.nz/file/ID#key",
        destination="unused",
        total_size=TOTAL,
    )
    with pytest.raises(NonRetryableTransferError, match="more than the requested range"):
        downloader._download_chunk(
            Chunk(index=1, offset=offset, size=size), b"\x00" * 16, b"\x00" * 8, "unused", state
        )
    assert response.yielded <= size + 65536, "the read must stop at the first over-long block"


# ---------------------------------------------------------------------------
# B8 - the server's declared size is a claim, not a fact
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "declared",
    [
        1 << 50,  # 1 PiB, as a hostile MegaCrypter host would declare
        MAX_FILE_SIZE + 1,
        -1,
        True,
        "12",
        None,
    ],
)
def test_absurd_declared_sizes_are_refused_before_any_allocation(monkeypatch, tmp_path, declared):
    exploded = False

    def _tripwire(size):
        nonlocal exploded
        exploded = True
        return iter(())

    monkeypatch.setattr("megabasterd_cli.core.downloader.iter_chunks", _tripwire)
    downloader = MegaDownloader(api=None, verify_integrity=False, max_workers=1)
    with pytest.raises(DeclaredSizeError):
        downloader._run_download(
            cdn_url="https://cdn.invalid/file",
            file_size=declared,
            aes_key=b"\x00" * 16,
            nonce=b"\x00" * 8,
            mac_iv_a32=[0, 0],
            destination=tmp_path / "out.bin",
            source="mc://mc.example/token",
            on_progress=None,
        )
    assert not exploded, "the chunk plan must never be built for a rejected size"


def test_chunk_count_is_computed_without_building_the_chunks():
    """The guard cannot depend on the loop it exists to prevent."""
    assert chunk_count(1 << 50) == 1_073_741_828  # 1 PiB, never enumerated
    # Agreement with the real generator on sizes small enough to enumerate.
    for size in (0, 1, 128 * 1024, 1024 * 1024, 5 * 1024 * 1024, 12 * 1024 * 1024):
        assert chunk_count(size) == len(list(iter_chunks(size)))
    assert chunk_count(MAX_FILE_SIZE) == MAX_CHUNKS


def test_preallocation_checks_free_disk_space(monkeypatch, tmp_path):
    monkeypatch.setattr("megabasterd_cli.core.downloader.available_disk_space", lambda p: 1024)
    downloader = MegaDownloader(api=None, verify_integrity=False, max_workers=1)
    destination = tmp_path / "big.bin"
    with pytest.raises(InsufficientDiskSpaceError, match="Not enough free space"):
        downloader._run_claimed_download(
            file_size=10 * 1024 * 1024,
            aes_key=b"\x00" * 16,
            nonce=b"\x00" * 8,
            mac_iv_a32=[0, 0],
            destination=destination,
            source="https://mega.nz/file/ID#key",
            on_progress=None,
            all_chunks=list(iter_chunks(10 * 1024 * 1024)),
        )
    assert not destination.exists(), "nothing may be preallocated when it cannot fit"
