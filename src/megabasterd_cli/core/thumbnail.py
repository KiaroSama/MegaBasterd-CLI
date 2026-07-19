"""Thumbnail generation for uploaded images.

MEGA stores per-file 250x250 JPEG thumbnails alongside file metadata. The
original MegaBasterd uses ffmpeg/Xuggler for video frames; this port uses
Pillow for images only — video thumbnails are skipped gracefully when Pillow
isn't available.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

THUMB_SIZE = 250
SUPPORTED_IMAGE_EXT = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tiff"}


def create_thumbnail(source: Path, dest: Path) -> bool:
    """Write a 250x250-bounded JPEG thumbnail of `source` to `dest`.

    Returns True if a thumbnail was produced, False if the source isn't a
    supported image or Pillow isn't installed.
    """
    if source.suffix.lower() not in SUPPORTED_IMAGE_EXT:
        return False
    try:
        from PIL import Image  # type: ignore
    except ImportError:
        log.debug("Pillow not installed; skipping thumbnail for %s", source.name)
        return False

    try:
        with Image.open(source) as opened:
            # PIL yields ImageFile but convert() returns Image; one name for
            # both is simpler than threading two types through five lines.
            img: Any = opened
            img.thumbnail((THUMB_SIZE, THUMB_SIZE))
            if img.mode in ("RGBA", "P"):
                img = img.convert("RGB")
            dest.parent.mkdir(parents=True, exist_ok=True)
            img.save(dest, "JPEG", quality=85)
        return True
    except Exception as exc:  # noqa: BLE001
        log.warning("Thumbnail generation failed for %s: %s", source, exc)
        return False
