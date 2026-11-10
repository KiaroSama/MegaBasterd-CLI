# SPDX-License-Identifier: GPL-3.0-or-later
"""Tiny packaging fixtures only; no compiler, signing, application or network execution."""

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "distribution_archive", HERE.parent / "package" / "archive.py")
archive = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(archive)
SOURCE_SPEC = importlib.util.spec_from_file_location(
    "distribution_source", HERE.parent / "package" / "source.py")
source = importlib.util.module_from_spec(SOURCE_SPEC)
# The explicit module is supplied by the same reviewed package directory as the CI caller.
sys.modules["archive"] = archive
SOURCE_SPEC.loader.exec_module(source)

IDENTITY = {"version": "2.0.0", "commit": "a" * 40,
            "target": "x86_64-pc-windows-msvc", "kind": "runtime"}


class DistributionArchiveTests(unittest.TestCase):
    def setUp(self):
        root = HERE.parents[1] / ".ci-work" / "distribution-tests"
        root.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=root)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.inputs = self.root / "inputs with spaces"
        self.inputs.mkdir()
        (self.inputs / "mb.exe").write_bytes(b"not an executable: fixture only")
        (self.inputs / "LICENSE").write_text("fixture license\n", encoding="utf-8")
        (self.inputs / "notice.txt").write_text("Unicode notice: \u00e9\n", encoding="utf-8", newline="\n")
        self.entries = {"mb.exe": self.inputs / "mb.exe", "LICENSE": self.inputs / "LICENSE",
                        "licenses/notice.txt": self.inputs / "notice.txt"}

    def test_archive_has_exact_members_hashes_modes_identity_and_utf8_without_host_paths(self):
        destination = self.root / "runtime.zip"
        report = archive.prepare(destination, self.entries, IDENTITY)
        self.assertEqual(report["sha256"], hashlib.sha256(destination.read_bytes()).hexdigest())
        self.assertEqual(report["bytes"], destination.stat().st_size)
        with zipfile.ZipFile(destination) as stream:
            self.assertEqual(set(stream.namelist()), {*self.entries, "manifest.json"})
            manifest = json.loads(stream.read("manifest.json").decode("utf-8"))
            self.assertEqual(manifest["identity"], IDENTITY)
            self.assertEqual(stream.getinfo("manifest.json").external_attr >> 16, 0o100644)
            self.assertEqual(manifest["stage"], "prepared; signing and runtime verification required")
            self.assertNotIn(str(self.root), json.dumps(manifest))
            self.assertEqual(len(manifest["files"]), 3)
            for row in manifest["files"]:
                content = stream.read(row["path"])
                self.assertEqual(content, self.entries[row["path"]].read_bytes())
                self.assertEqual(row["sha256"], hashlib.sha256(content).hexdigest())
                self.assertEqual(row["bytes"], len(content))
                self.assertEqual(stream.getinfo(row["path"]).external_attr >> 16,
                                 0o100755 if row["path"] == "mb.exe" else 0o100644)
            self.assertEqual(stream.read("licenses/notice.txt").decode("utf-8"),
                             "Unicode notice: \u00e9\n")
        self.assertEqual(archive.verify(destination)["identity"], IDENTITY)
        repeated = self.root / "repeated.zip"
        self.assertEqual(archive.prepare(repeated, self.entries, IDENTITY)["sha256"], report["sha256"])

    def test_unsafe_names_case_collisions_private_components_and_existing_output_are_refused(self):
        names = ["../outside", "/absolute", "a\\b", "C:/file", "a//b", "a/./b", "a\x00b",
                 "secrets.md", "nested/.ignoreme/value", ".ai/data", "User/accounts.json",
                 "Logs/file.txt", "anything.env", "CON", "a.", "a ", "manifest.json"]
        for index, name in enumerate(names):
            with self.subTest(name=name), self.assertRaises(ValueError):
                archive.prepare(self.root / f"bad-{index}.zip", {name: self.inputs / "mb.exe"}, IDENTITY)
        with self.assertRaises(ValueError):
            archive.prepare(self.root / "case.zip", {"MB.exe": self.inputs / "mb.exe",
                                                    "mb.exe": self.inputs / "mb.exe"}, IDENTITY)
        destination = self.root / "existing.zip"
        destination.write_bytes(b"preserve")
        with self.assertRaises(FileExistsError):
            archive.prepare(destination, self.entries, IDENTITY)
        self.assertEqual(destination.read_bytes(), b"preserve")
        self.assertFalse((self.root / "outside").exists())
        for executables in [{"absent"}, ["mb.exe"], {"../outside"}]:
            with self.subTest(executables=executables), self.assertRaises(ValueError):
                archive.prepare(self.root / "bad-executable.zip", self.entries, IDENTITY,
                                executables=executables)
        source_zip = self.root / "source.zip"
        archive.prepare(source_zip, self.entries, {**IDENTITY, "kind": "source"},
                        executables={"licenses/notice.txt"})
        with zipfile.ZipFile(source_zip) as stream:
            self.assertEqual(stream.getinfo("mb.exe").external_attr >> 16, 0o100644)
            self.assertEqual(stream.getinfo("licenses/notice.txt").external_attr >> 16, 0o100755)

    def test_readback_rejects_tampered_payload_extra_members_and_unsupported_identity(self):
        original = self.root / "original.zip"
        archive.prepare(original, self.entries, IDENTITY)
        for variant in ["payload", "extra", "manifest", "schema-bool", "schema-float", "manifest-link"]:
            changed = self.root / f"{variant}.zip"
            with zipfile.ZipFile(original) as source, zipfile.ZipFile(changed, "x") as target:
                for item in source.infolist():
                    data = source.read(item)
                    if variant == "payload" and item.filename == "mb.exe":
                        data = b"changed"
                    if item.filename == "manifest.json":
                        value = json.loads(data)
                        if variant == "manifest":
                            value["identity"]["target"] = "unsupported"
                        elif variant in {"schema-bool", "schema-float"}:
                            value["schema_version"] = True if variant == "schema-bool" else 1.0
                        elif variant == "manifest-link":
                            item.external_attr = 0o120777 << 16
                        data = json.dumps(value).encode("utf-8")
                    target.writestr(item, data)
                if variant == "extra":
                    target.writestr("unlisted.txt", b"not authorized")
            with self.subTest(variant=variant), self.assertRaises(ValueError):
                archive.verify(changed)
        for key, value in [("commit", "main"), ("target", "x86_64-unknown-linux-musl"),
                           ("version", "2.0.0\n"), ("kind", "signed"), ("target", []), ("kind", {})]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                archive.prepare(self.root / f"invalid-{key}.zip", self.entries, {**IDENTITY, key: value})

    def test_late_failure_preserves_destination_absence_and_allows_a_clean_retry(self):
        destination = self.root / "late-failure.zip"
        before = {path.name for path in self.root.iterdir()}
        with self.assertRaises(FileNotFoundError):
            archive.prepare(destination, {**self.entries, "missing.txt": self.inputs / "missing"}, IDENTITY)
        self.assertFalse(destination.exists())
        self.assertEqual({path.name for path in self.root.iterdir()}, before)
        archive.prepare(destination, self.entries, IDENTITY)
        self.assertEqual(archive.verify(destination)["identity"], IDENTITY)
        self.assertEqual({path.name for path in self.root.iterdir()}, before | {destination.name})

    def test_ci_source_preparation_uses_the_actual_inventory_and_never_claims_a_signed_release(self):
        project = self.root / "source project"
        project.mkdir()
        paths = sorted(archive.REQUIRED_SOURCE | {"tools/package/source.py"})
        for name in paths:
            path = project / name
            path.parent.mkdir(parents=True, exist_ok=True)
            content = '[package]\nversion = "2.0.0"\n' if name == "Cargo.toml" else "synthetic source\n"
            path.write_text(content, encoding="utf-8")
        calls, events = [], []

        def command(argv, label, environment, log, **bounds):
            calls.append((argv, label, bounds))
            return 0, ("\0".join([*paths, "User/private.json", "tests/test_legacy.py"]) + "\0").encode("utf-8"), b""

        class Log:
            def event(self, level, message, **fields):
                events.append((level, message, fields))

        output, report = source.prepare_project_source(
            project, {"commit": IDENTITY["commit"]}, IDENTITY["target"], {}, command, Log(), 512)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], ["git", "ls-files", "-z"])
        self.assertEqual(calls[0][2], {"wall": 30, "idle": 10, "memory_mib": 512})
        self.assertTrue(output.is_relative_to(project / ".ci-work" / "distribution"))
        manifest = archive.verify(output)
        self.assertEqual(manifest["identity"], {**IDENTITY, "kind": "source"})
        self.assertEqual({row["path"] for row in manifest["files"]}, set(paths))
        self.assertEqual(report["sha256"], hashlib.sha256(output.read_bytes()).hexdigest())
        self.assertIs(events[-1][2]["release_ready"], False)
        self.assertEqual(events[-1][2]["signing"], "separate gate")
        for code, payload in [(1, b""), (0, b"unterminated"), (0, b"LICENSE\0")]:
            with self.subTest(code=code, payload=payload), self.assertRaises(ValueError):
                source.prepare_project_source(
                    project, {"commit": IDENTITY["commit"]}, IDENTITY["target"], {},
                    lambda *args, **kwargs: (code, payload, b""), Log(), 512)
        self.assertEqual(len(events), 1)

    def test_source_inventory_is_explicit_and_never_absorbs_retained_python_or_local_state(self):
        candidates = [*archive.REQUIRED_SOURCE, "src/cli/args.rs", "tests/cli_contract.rs",
                      "tools/package/archive.py", "tools/ci/test_distribution_archive.py",
                      "tests/fixtures/crypto-vectors.json", "tests/fixtures/proxy_tls/public-test-key.txt",
                      "src/megabasterd_cli/cli.py", "tests/test_uploader.py", "Run.ps1",
                      "User/credentials.json", ".ai/memory.md", ".git/config", "skills-lock.json"]
        selected = archive.source_names(candidates)
        self.assertTrue(archive.REQUIRED_SOURCE <= set(selected))
        self.assertIn("src/cli/args.rs", selected)
        self.assertIn("tests/fixtures/proxy_tls/public-test-key.txt", selected)
        for name in ["src/megabasterd_cli/cli.py", "tests/test_uploader.py", "Run.ps1",
                     "User/credentials.json", ".ai/memory.md", ".git/config", "skills-lock.json"]:
            self.assertNotIn(name, selected)
        with self.assertRaises(ValueError):
            archive.source_names([name for name in candidates if name != "LICENSE"])
