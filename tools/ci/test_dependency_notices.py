# SPDX-License-Identifier: GPL-3.0-or-later
"""Tiny locked-package notice inventories; no compiler, network or fixture executable."""

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parents[1] / "package"
sys.path.insert(0, str(HERE))
import archive
import dependencies
import notices

BUILD = {"version": "2.0.0", "commit": "a" * 40,
         "target": "x86_64-unknown-linux-gnu", "kind": "runtime"}


class DependencyNoticeTests(unittest.TestCase):
    def setUp(self):
        base = Path(__file__).resolve().parents[2] / ".ci-work" / "dependency-notice-tests"
        base.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=base)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.project = self.root / "extracted source"
        self.project.mkdir()
        self.lock = ""
        self.packages = {}
        for name, version, license_fields, documents in [
            ("first", "1.2.3", 'license="MIT OR Apache-2.0"', {
                "LICENSE": b"Copyright first owner; synthetic MIT fixture\n",
                "NOTICE": b"First attribution\n", "nested/NOTICE.txt": b"Nested separate owner\n"}),
            ("second", "2.3.4", 'license-file="terms/legal.txt"', {
                "LICENSE": b"Copyright second owner; distinct synthetic grant\n",
                "terms/legal.txt": "Synthetic explicit UTF-8 grant: café\n".encode("utf-8"),
                "licenses/exception.txt": b"Synthetic exception text\n"}),
        ]:
            package = self.project / "vendor" / f"{name}-{version}"
            files = {"Cargo.toml": f'[package]\nname="{name}"\nversion="{version}"\n{license_fields}\n'.encode("utf-8"),
                     "src/lib.rs": b"pub fn fixture() {}\n", **documents}
            self.packages[name] = (package, files)
            self.write_package(name)
            self.lock += (f'[[package]]\nname="{name}"\nversion="{version}"\n'
                          f'source="{dependencies.REGISTRY}"\nchecksum="' + "1" * 64 + '"\n')
        (self.project / "Cargo.lock").write_text(self.lock, encoding="utf-8", newline="\n")

    def write_package(self, name):
        package, files = self.packages[name]
        for relative, data in files.items():
            path = package / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        checks = {"package": "1" * 64,
                  "files": {path: hashlib.sha256(data).hexdigest() for path, data in files.items()}}
        (package / ".cargo-checksum.json").write_text(json.dumps(checks), encoding="utf-8", newline="\n")

    def test_notices_keep_each_package_and_nested_original_bytes_in_the_real_archive(self):
        entries, hashes = notices.notice_entries(self.project, self.root / "notices", BUILD)
        expected = {}
        for package, files in self.packages.values():
            for name, data in files.items():
                if name not in {"Cargo.toml", "src/lib.rs"}:
                    expected[f"licenses/dependencies/{package.name}/{name}"] = data
        self.assertEqual(set(entries), {*expected, notices.INDEX})
        document = json.loads(entries[notices.INDEX].read_text(encoding="utf-8"))
        self.assertEqual(document["identity"], BUILD)
        self.assertEqual(document["lock_sha256"], hashlib.sha256(self.lock.encode("utf-8")).hexdigest())
        self.assertEqual([(p["name"], p["version"], p["license"], p["license_file"])
                          for p in document["packages"]],
                         [("first", "1.2.3", "MIT OR Apache-2.0", None),
                          ("second", "2.3.4", None, "terms/legal.txt")])
        self.assertIn("legal_review", document)
        for package in document["packages"]:
            for item in package["documents"]:
                data = expected[item["path"]]
                self.assertEqual(item["bytes"], len(data))
                self.assertEqual(item["sha256"], hashlib.sha256(data).hexdigest())
                self.assertEqual(item["source"], "vendor/" + item["path"].removeprefix("licenses/dependencies/"))
        output = self.root / "notice-intermediate.zip"
        archive.prepare(output, entries, BUILD)
        report = archive.verify(output)
        self.assertEqual({row["path"]: row["sha256"] for row in report["files"]}, hashes)
        extracted = self.root / "extracted notices with spaces"
        archive.extract(output, extracted, BUILD)
        for path, data in expected.items():
            self.assertEqual((extracted / path).read_bytes(), data)

    def test_missing_empty_unsafe_nontext_or_changed_notices_fail_closed(self):
        package, files = self.packages["second"]
        original = dict(files)
        for mode in ["missing", "empty", "blank", "nontext", "outside", "changed", "missing-root"]:
            files.clear()
            files.update(original)
            if mode == "missing":
                files["Cargo.toml"] = files["Cargo.toml"].replace(b"terms/legal.txt", b"terms/absent.txt")
            elif mode == "outside":
                files["Cargo.toml"] = files["Cargo.toml"].replace(b"terms/legal.txt", b"../outside.txt")
            elif mode == "missing-root":
                files["Cargo.toml"] = files["Cargo.toml"].replace(b'license-file="terms/legal.txt"', b'license="MIT"')
                del files["LICENSE"]
                (package / "LICENSE").unlink()
            elif mode != "changed":
                files["terms/legal.txt"] = {"empty": b"", "blank": b" \n", "nontext": b"\xff"}[mode]
            self.write_package("second")
            if mode == "changed":
                (package / "terms/legal.txt").write_bytes(b"not the locked notice")
            output = self.root / ("refused-" + mode)
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                notices.notice_entries(self.project, output, BUILD)
            self.assertFalse(output.exists())
