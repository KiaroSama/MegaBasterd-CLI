"""One strict HTTP Range-response validator, shared by every consumer.

Both the chunk downloader and the streaming server decrypt an upstream body
with an AES-CTR counter derived from the byte OFFSET they asked for. If the
server (or a proxy) ignores `Range` and answers with the whole file, or with a
different window of the same length, those bytes decrypt to garbage - and the
downloader writes them straight to disk at the requested offset.

Streaming enforced this already; the downloader did not, and accepted HTTP 200
for a partial request with no `Content-Range` check at all. The rule now lives
in one place so the two cannot drift apart again.
"""

from __future__ import annotations

import re


class RangeNotHonoredError(Exception):
    """The upstream response does not match the requested byte range."""


# `bytes <start>-<end>/<total>`; a `*` in either position is not acceptable
# for a range we are about to decrypt at a specific counter.
_CONTENT_RANGE_RE = re.compile(r"^bytes\s+(\d+)\s*-\s*(\d+)\s*/\s*(\d+|\*)$", re.IGNORECASE)


def validate_range_response(status: int, headers, start: int, end: int, size: int) -> None:
    """Raise RangeNotHonored unless the body is exactly bytes `start`..`end`.

    A nonzero range decrypted with a nonzero AES-CTR counter is only correct
    if the server actually honored the range. A proxy or CDN that ignores
    `Range` and replies 200 with the whole body from byte 0 would otherwise
    produce garbage plaintext that looks like a successful stream.

    HTTP 200 is accepted for one case only: the request covers the whole file,
    where the counter starts at zero anyway.
    """
    wants_whole_file = start == 0 and end == size - 1
    if status == 200:
        if wants_whole_file:
            return
        raise RangeNotHonoredError(
            f"HTTP 200 (full body) for a partial request of bytes {start}-{end}"
        )
    if status != 206:
        raise RangeNotHonoredError(f"expected HTTP 206 for bytes {start}-{end}, got {status}")
    raw = headers.get("Content-Range")
    if not raw:
        raise RangeNotHonoredError("206 response without a Content-Range header")
    match = _CONTENT_RANGE_RE.match(str(raw).strip())
    if match is None:
        raise RangeNotHonoredError(f"unparsable Content-Range {raw!r}")
    got_start, got_end, total = int(match.group(1)), int(match.group(2)), match.group(3)
    if got_start != start or got_end != end:
        raise RangeNotHonoredError(
            f"Content-Range covers {got_start}-{got_end}, requested {start}-{end}"
        )
    if total == "*":
        # We KNOW the file size here, so an unknown total is not something to
        # shrug at: it means the server would not confirm which resource this
        # window belongs to, and these bytes are about to be decrypted at a
        # specific counter.
        raise RangeNotHonoredError(
            f"Content-Range total is unknown ('*') but the file size is known ({size})"
        )
    if int(total) != size:
        raise RangeNotHonoredError(f"Content-Range total {total} does not match file size {size}")
    declared = headers.get("Content-Length")
    if declared is not None:
        try:
            declared_len = int(declared)
        except (TypeError, ValueError):
            raise RangeNotHonoredError(f"unparsable Content-Length {declared!r}") from None
        if declared_len != end - start + 1:
            raise RangeNotHonoredError(
                f"Content-Length {declared_len} does not match the {end - start + 1}-byte range"
            )
