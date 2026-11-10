# SPDX-License-Identifier: GPL-3.0-or-later
"""Small source inventories exercise real hashing, not Cargo or downloaded dependencies."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parents[1] / "package"
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location("dependency_source", HERE / "dependencies.py")
dependencies = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dependencies)


class DependencySourceTests(unittest.TestCase):
    def setUp(self):
        base = Path(__file__).resolve().parents[2] / ".ci-work" / "dependency-source-tests"
        base.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=base)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.vendor = self.root / "vendor"
        self.vendor.mkdir()
        self.package = self.vendor / "tiny-1.2.3"
        self.package.mkdir()
        (self.package / "src").mkdir()
        self.files = {"Cargo.toml": b'[package]\nname = "tiny"\nversion = "1.2.3"\nlicense = "MIT"\n',
                      "src/lib.rs": b"pub fn value() -> u8 { 7 }\n", "LICENSE": b"Synthetic MIT fixture notice\n",
                      "build-helper.sh": b"#!/bin/sh\nexit 0\n"}
        for name, data in self.files.items():
            (self.package / name).write_bytes(data)
        if os.name != "nt":
            (self.package / "build-helper.sh").chmod(0o755)
        self.checksums = {"$comment": "Fixture checksums are not a signature",
                          "package": "1" * 64,
                          "files": {name: hashlib.sha256(data).hexdigest() for name, data in self.files.items()}}
        self.write_checksums()
        self.lock = {"package": [{"name": "megabasterd-cli", "version": "2.0.0"},
            {"name": "tiny", "version": "1.2.3", "source": dependencies.REGISTRY, "checksum": "1" * 64}]}

    def write_checksums(self):
        (self.package / ".cargo-checksum.json").write_text(json.dumps(self.checksums), encoding="utf-8")

    def test_every_actual_file_is_bound_to_the_exact_locked_package_and_rebuild_config(self):
        entries, packages = dependencies.inventory(self.vendor, self.lock)
        self.assertEqual(set(entries), {"vendor/tiny-1.2.3/" + name for name in
                                       [*self.files, ".cargo-checksum.json"]})
        self.assertEqual(len(packages), 1)
        self.assertEqual({key: packages[0][key] for key in ["name", "version", "checksum", "license"]},
                         {"name": "tiny", "version": "1.2.3", "checksum": "1" * 64, "license": "MIT"})
        self.assertEqual(packages[0]["files"], self.checksums["files"])
        self.assertEqual(packages[0]["executables"], [] if os.name == "nt" else ["build-helper.sh"])
        self.assertEqual(packages[0]["checksum_file_sha256"], hashlib.sha256(
            (self.package / ".cargo-checksum.json").read_bytes()).hexdigest())
        self.assertEqual(entries["vendor/tiny-1.2.3/src/lib.rs"].read_bytes(), self.files["src/lib.rs"])
        config = dependencies.vendor_config(b'[source.crates-io]\nreplace-with = "vendored-sources"\n'
            b'[source.vendored-sources]\ndirectory = "/ci/temporary/vendor"\n')
        self.assertEqual(config, '[source.crates-io]\nreplace-with = "vendored-sources"\n\n'
            '[source.vendored-sources]\ndirectory = "vendor"\n')
        self.assertNotIn("temporary", config)

    def test_actual_preparation_archives_exact_dependency_bytes_and_portable_configuration(self):
        import shutil
        import archive
        root = self.root / "project"
        root.mkdir()
        (root / "Cargo.toml").write_bytes(b'[package]\nversion="2.0.0"\n')
        lock = (b'[[package]]\nname="megabasterd-cli"\nversion="2.0.0"\n'
                b'[[package]]\nname="tiny"\nversion="1.2.3"\nsource="' + dependencies.REGISTRY.encode("ascii") +
                b'"\nchecksum="' + b"1" * 64 + b'"\n')
        (root / "Cargo.lock").write_bytes(lock)
        work = self.root / "work"
        work.mkdir()
        calls, events = [], []
        def command(argv, label, environment, log, **bounds):
            calls.append((argv, label, bounds))
            self.assertEqual(argv[:5], ["cargo", "+1.99.1", "vendor", "--locked", "--versioned-dirs"])
            self.assertEqual(label, "distribution-vendor")
            shutil.copytree(self.vendor, argv[-1])
            return 0, (b'[source.crates-io]\nreplace-with="vendored-sources"\n'
                       b'[source.vendored-sources]\ndirectory="vendor"\n'), b""
        class Log:
            def event(self, *args, **fields):
                events.append(fields)
        path, report = dependencies.prepare_dependencies(root, work, {"commit": "a" * 40},
            "x86_64-unknown-linux-gnu", ["cargo", "+1.99.1"], {}, command, Log(), 512)
        self.assertEqual(len(calls), 1)
        manifest = archive.verify(path)
        self.assertEqual({row["path"] for row in manifest["files"]},
            {"Cargo.lock", ".cargo/config.toml", "dependency-manifest.json"} |
            {"vendor/tiny-1.2.3/" + name for name in [*self.files, ".cargo-checksum.json"]})
        self.assertEqual(report["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual((root / "Cargo.lock").read_bytes(), lock)
        self.assertEqual(len(events), 1)
        self.assertIs(events[0]["release_ready"], False)
        self.assertEqual(events[0]["offline_build"], "unverified")
        import zipfile
        with zipfile.ZipFile(path) as stream:
            self.assertEqual(stream.read(".cargo/config.toml"), dependencies.CONFIG.encode("utf-8"))
            self.assertEqual(stream.read("vendor/tiny-1.2.3/src/lib.rs"), self.files["src/lib.rs"])
            self.assertEqual(stream.getinfo("vendor/tiny-1.2.3/build-helper.sh").external_attr >> 16,
                             0o100644 if os.name == "nt" else 0o100755)

    def test_failed_vendor_and_changed_lock_never_publish_a_dependency_archive(self):
        root = self.root / "failed project"
        root.mkdir()
        (root / "Cargo.toml").write_bytes(b'[package]\nversion="2.0.0"\n')
        lock_path = root / "Cargo.lock"
        events = []
        class Log:
            def event(self, *args, **fields):
                events.append(fields)
        for mode in ["command", "config", "lock"]:
            lock_path.write_bytes(b'[[package]]\nname="megabasterd-cli"\nversion="2.0.0"\n')
            work = self.root / mode
            work.mkdir()
            def command(*args, **kwargs):
                if mode == "lock":
                    lock_path.write_bytes(b"changed")
                output = (b'[source.crates-io]\nreplace-with="vendored-sources"\n'
                          b'[source.vendored-sources]\ndirectory="vendor"\n')
                return (101 if mode == "command" else 0), (b"bad" if mode == "config" else output), b""
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                dependencies.prepare_dependencies(root, work, {"commit": "a" * 40},
                    "x86_64-unknown-linux-gnu", ["cargo", "+1.99.1"], {}, command, Log(), 512)
            self.assertFalse(list(work.rglob("*.zip")))
        self.assertEqual(events, [])

    def test_tampering_extra_missing_packages_wrong_lock_and_unsafe_paths_are_refused(self):
        original = self.files["src/lib.rs"]
        manifest_hash = self.checksums["files"]["Cargo.toml"]
        for mode in ["bytes", "extra", "missing", "checksum", "traversal", "source", "duplicate", "name", "version"]:
            with self.subTest(mode=mode):
                self.checksums["files"]["Cargo.toml"] = manifest_hash
                self.write_checksums()
                (self.package / "src/lib.rs").write_bytes(original)
                lock = json.loads(json.dumps(self.lock))
                if mode == "bytes":
                    (self.package / "src/lib.rs").write_bytes(b"tampered")
                elif mode == "extra":
                    (self.package / "unexpected").write_bytes(b"extra")
                elif mode == "missing":
                    (self.package / "src/lib.rs").unlink()
                elif mode == "checksum":
                    lock["package"][1]["checksum"] = "2" * 64
                elif mode == "traversal":
                    self.checksums["files"]["../outside"] = "3" * 64
                    self.write_checksums()
                    del self.checksums["files"]["../outside"]
                elif mode == "source":
                    lock["package"][1]["source"] = "git+https://example.invalid/unapproved"
                elif mode == "duplicate":
                    lock["package"].append(dict(lock["package"][1]))
                elif mode in {"name", "version"}:
                    changed = (b'[package]\nname="wrong"\nversion="1.2.3"\n' if mode == "name" else
                               b'[package]\nname="tiny"\nversion="9.0.0"\n')
                    (self.package / "Cargo.toml").write_bytes(changed)
                    self.checksums["files"]["Cargo.toml"] = hashlib.sha256(changed).hexdigest()
                    self.write_checksums()
                with self.assertRaises(ValueError):
                    dependencies.inventory(self.vendor, lock)
                extra = self.package / "unexpected"
                if extra.exists():
                    extra.unlink()
                (self.package / "Cargo.toml").write_bytes(self.files["Cargo.toml"])
        self.checksums["files"]["Cargo.toml"] = manifest_hash
        self.write_checksums()
        (self.package / "src/lib.rs").write_bytes(original)
        other = self.vendor / "extra-1.0.0"
        other.mkdir()
        with self.assertRaises(ValueError):
            dependencies.inventory(self.vendor, self.lock)

    def test_rebuild_config_rejects_extra_sources_and_nonreplacement_output(self):
        for data in [b"", b'[source.crates-io]\nreplace-with="other"\n',
                     b'[source.other]\ndirectory="vendor"\n',
                     b'[source.crates-io]\nreplace-with="vendored-sources"\n'
                     b'[source.vendored-sources]\ndirectory="vendor"\n[net]\noffline=true\n']:
            with self.subTest(data=data), self.assertRaises(ValueError):
                dependencies.vendor_config(data)
