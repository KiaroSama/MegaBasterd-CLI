# SPDX-License-Identifier: GPL-3.0-or-later
"""Archive validation only: tiny RAM fixtures, no download, decoder or compiler run."""

from io import BytesIO
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile

import media_toolchain as media


class MediaArchiveTests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[2] / ".ci-work" / "media-archive-tests"
        root.mkdir(parents=True, exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(dir=root)
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def tar(self, records):
        archive = self.root / "input.tar.xz"
        with tarfile.open(archive, "w:xz") as stream:
            for name, content, kind in records:
                member = tarfile.TarInfo(name)
                member.type = kind
                member.size = len(content)
                member.mode = 0o755 if name.endswith("configure") else 0o644
                if kind == tarfile.SYMTYPE:
                    member.linkname = "../../escape"
                    member.size = 0
                stream.addfile(member, BytesIO(content) if member.isfile() else None)
        return archive

    def test_source_extracts_exact_version_and_preserves_configure_executable_only(self):
        archive = self.tar([(f"ffmpeg-{media.VERSION}/RELEASE", media.VERSION.encode("utf-8"), tarfile.REGTYPE),
                            (f"ffmpeg-{media.VERSION}/configure", b"fixture-not-executed", tarfile.REGTYPE)])
        destination = self.root / "source"
        source = media.extract_source(archive, destination)
        self.assertEqual((source / "configure").read_bytes(), b"fixture-not-executed")
        self.assertEqual((source / "RELEASE").read_text(encoding="utf-8"), media.VERSION)

    def test_source_refuses_path_escape_links_duplicates_and_wrong_version(self):
        prefix = f"ffmpeg-{media.VERSION}/"
        for name, kind in [(prefix + "../escape", tarfile.REGTYPE),
                           (prefix + "linked", tarfile.SYMTYPE),
                           ("/absolute", tarfile.REGTYPE)]:
            with self.subTest(name=name):
                archive = self.tar([(name, b"x", kind)])
                with self.assertRaises(ValueError):
                    media.extract_source(archive, self.root / "rejected")
                archive.unlink()
        archive = self.tar([(prefix + "RELEASE", b"different", tarfile.REGTYPE)])
        with self.assertRaisesRegex(ValueError, "version"):
            media.extract_source(archive, self.root / "wrong")
        archive.unlink()
        archive = self.tar([(prefix + "RELEASE", b"x", tarfile.REGTYPE)] * 2)
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            media.extract_source(archive, self.root / "duplicate")
        self.assertFalse((self.root / "escape").exists())

    def test_windows_extracts_only_two_regular_tools_and_rejects_missing_duplicate_or_links(self):
        for invalid in [None, "missing", "duplicate", "link"]:
            with self.subTest(invalid=invalid):
                archive = self.root / f"{invalid}.zip"
                with zipfile.ZipFile(archive, "w") as stream:
                    stream.writestr("version/bin/ffmpeg.exe", b"fixture-ffmpeg")
                    stream.writestr("version/README.txt", b"not copied")
                    if invalid != "missing":
                        item = zipfile.ZipInfo("version/bin/ffprobe.exe")
                        if invalid == "link":
                            item.external_attr = 0o120777 << 16
                        stream.writestr(item, b"fixture-ffprobe")
                    if invalid == "duplicate":
                        # Different parent gives the same exact extracted executable.
                        stream.writestr("other/bin/ffmpeg.exe", b"duplicate")
                output = self.root / f"out-{invalid}"
                if invalid is not None:
                    with self.assertRaises(ValueError):
                        media.extract_windows(archive, output)
                else:
                    self.assertEqual(media.extract_windows(archive, output), output / "ffmpeg.exe")
                    self.assertEqual({p.name for p in output.iterdir()}, {"ffmpeg.exe", "ffprobe.exe"})

    def test_member_and_copy_bounds_are_fail_closed_without_overwriting_existing_files(self):
        for name in ["../outside", "a/../b", "C:/file", "a\\b", "a//b", "a\x00b"]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                media.member_path(name)
        for body, size in [(b"short", 6), (b"too-long", 3), (b"", media.MAX_MEMBER + 1)]:
            with self.subTest(size=size), self.assertRaises(ValueError):
                media.copy_exact(BytesIO(body), self.root / f"partial-{size}", size)
        output = self.root / "precious"
        output.write_bytes(b"original")
        with self.assertRaises(FileExistsError):
            media.copy_exact(BytesIO(b"changed"), output, 7)
        self.assertEqual(output.read_bytes(), b"original")
