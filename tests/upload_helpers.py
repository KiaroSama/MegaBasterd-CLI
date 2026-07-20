"""Shared scaffolding for the multi-file upload test modules.

`files` was declared byte-identically in two upload tests. It is not queue
scaffolding - it builds the real on-disk payload the uploader walks - so it
lives here rather than in `queue_helpers`, and the 64-byte size is part of the
fixture: the tests assert that exact size back out of `UploadResult`.
"""

from __future__ import annotations

from pathlib import Path


def files(tmp_path: Path, n: int) -> list[str]:
    paths = []
    for i in range(n):
        p = tmp_path / f"f{i}.bin"
        p.write_bytes(b"x" * 64)
        paths.append(str(p))
    return paths
