# SPDX-License-Identifier: GPL-3.0-or-later
"""Real tiny source ZIPs and command callbacks; no compiler or fixture binary executes."""

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parents[1] / "package"
sys.path.insert(0, str(HERE))
import archive
import dependencies
import rebuild

IDENTITY = {"version": "2.0.0", "commit": "a" * 40,
            "target": "x86_64-pc-windows-msvc", "kind": "source"}
LOCK = ('[[package]]\nname="megabasterd-cli"\nversion="2.0.0"\n'
        '[[package]]\nname="tiny"\nversion="1.2.3"\nsource="' + dependencies.REGISTRY +
        '"\nchecksum="' + "1" * 64 + '"\n').encode("utf-8")


def fixture(root):
    inputs = root / "source inputs"
    inputs.mkdir()
    project = {}
    for name in sorted(archive.REQUIRED_SOURCE):
        path = inputs / name
        path.parent.mkdir(parents=True, exist_ok=True)
        data = (b'[package]\nname="megabasterd-cli"\nversion="2.0.0"\n' if name == "Cargo.toml"
                else LOCK if name == "Cargo.lock" else b"synthetic source or notice\n")
        path.write_bytes(data)
        project[name] = path
    project_archive = root / "project-source.zip"
    archive.prepare(project_archive, project, IDENTITY)
    package = inputs / "vendor/tiny-1.2.3"
    package.mkdir(parents=True)
    files = {"Cargo.toml": b'[package]\nname="tiny"\nversion="1.2.3"\nlicense="MIT"\n',
             "lib.rs": b"pub fn value() -> u8 { 7 }\n", "LICENSE": b"Synthetic fixture notice\n"}
    hashes = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
    for name, data in files.items():
        (package / name).write_bytes(data)
    checksum = json.dumps({"package": "1" * 64, "files": hashes}).encode("utf-8")
    (package / ".cargo-checksum.json").write_bytes(checksum)
    metadata = {"identity": IDENTITY, "lock_sha256": hashlib.sha256(LOCK).hexdigest(), "packages": [{
        "name": "tiny", "version": "1.2.3", "checksum": "1" * 64, "license": "MIT", "files": hashes,
        "executables": [], "checksum_file_sha256": hashlib.sha256(checksum).hexdigest()}]}
    (inputs / "dependency-manifest.json").write_text(json.dumps(metadata), encoding="utf-8")
    (inputs / "config.toml").write_text(dependencies.CONFIG, encoding="utf-8", newline="\n")
    entries = {"vendor/tiny-1.2.3/" + name: package / name for name in [*files, ".cargo-checksum.json"]}
    entries.update({"Cargo.lock": inputs / "Cargo.lock", ".cargo/config.toml": inputs / "config.toml",
                    "dependency-manifest.json": inputs / "dependency-manifest.json"})
    dependency_archive = root / "dependency-source.zip"
    archive.prepare(dependency_archive, entries, IDENTITY)
    tools = root / "installed toolchain/bin"
    tools.mkdir(parents=True)
    for name in ("cargo", "rustc", "rustdoc"):
        (tools / name).write_bytes(b"tool path fixture, never executed")
    return project_archive, dependency_archive, entries, tools


class SourceRebuildTests(unittest.TestCase):
    def setUp(self):
        base = Path(__file__).resolve().parents[2] / ".ci-work/source-rebuild-tests"
        base.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=base)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.project, self.dependency, self.entries, self.tools = fixture(self.root)

    def test_rebuild_uses_extracted_sources_empty_cache_explicit_tools_and_frozen_native_build(self):
        calls, events = [], []
        class Log:
            def event(self, *args, **fields):
                events.append(fields)
        for mode in ("ok", "build-error", "source-change", "missing-alias"):
            scratch = self.root / mode
            scratch.mkdir()
            def command(argv, label, environment, log, **bounds):
                calls.append(label)
                if label.startswith("rebuild-tool-"):
                    self.assertEqual(argv, ["rustup", "which", "--toolchain", "1.99.1", argv[-1]])
                    return 0, str(self.tools / argv[-1]).encode("utf-8") + b"\n", b""
                self.assertEqual(label, "extracted-source-build")
                self.assertEqual(argv, [self.tools / "cargo", "build", "--frozen", "--release", "--workspace",
                                       "--bins", "-j", "1"])
                project = bounds["cwd"]
                self.assertEqual(project, scratch / "native source with spaces")
                self.assertEqual((project / "Cargo.lock").read_bytes(), LOCK)
                self.assertEqual((project / ".cargo/config.toml").read_bytes(), dependencies.CONFIG.encode("utf-8"))
                self.assertEqual(list(Path(environment["CARGO_HOME"]).iterdir()), [])
                self.assertNotIn("RUSTUP_HOME", environment)
                self.assertNotIn("GITHUB_TOKEN", environment)
                self.assertNotIn("MEGABASTERD_USER_DIR", environment)
                self.assertNotIn("RUSTFLAGS", environment)
                self.assertEqual(environment["CARGO_NET_OFFLINE"], "true")
                self.assertEqual(environment["RUSTC"], str(self.tools / "rustc"))
                self.assertEqual(environment["RUSTDOC"], str(self.tools / "rustdoc"))
                self.assertEqual(bounds["wall"], 900)
                self.assertEqual(bounds["idle"], 180)
                self.assertEqual(environment["HOOKMAKER_MAX_TEST_WORKERS"], "1")
                if mode == "build-error":
                    return 101, b"", b""
                release = Path(environment["CARGO_TARGET_DIR"]) / "release"
                release.mkdir()
                for name in ("mb", "mbcli", "megabasterd-cli"):
                    if mode != "missing-alias" or name != "mbcli":
                        artifact = release / (name + "-hashed.exe")
                        artifact.write_bytes(name.encode("ascii") + b" fixture")
                        os.link(artifact, release / (name + ".exe"))
                if mode == "source-change":
                    (project / "src/main.rs").write_bytes(b"changed by build")
                return 0, b"", b""
            args = (self.project, self.dependency, scratch, IDENTITY, ["cargo", "+1.99.1"],
                    {"PATH": "fixture tools", "CARGO_HOME": "old cache", "GITHUB_TOKEN": "synthetic token",
                     "MEGABASTERD_USER_DIR": "old user", "RUSTFLAGS": "unapproved override"}, command, Log(), 1, 512)
            if mode == "ok":
                project, binaries = rebuild.rebuild(*args)
                self.assertEqual(len(binaries), 3)
                self.assertEqual(binaries["mb.exe"].read_bytes(), b"mb fixture")
                self.assertEqual(binaries["mb.exe"].stat().st_nlink, 1)
                original = scratch / "target/release/mb.exe"
                self.assertEqual(original.stat().st_nlink, 2)
                self.assertEqual(original.read_bytes(), b"mb fixture")
                with self.assertRaises(ValueError):
                    archive.prepare(scratch / "linked-input.zip", {"mb.exe": original},
                                    {**IDENTITY, "kind": "runtime"})
            else:
                with self.subTest(mode=mode), self.assertRaises((ValueError, FileNotFoundError)):
                    rebuild.rebuild(*args)
        self.assertEqual(len(calls), 16)
        self.assertEqual(len(events), 1)
        self.assertIs(events[0]["release_ready"], False)
        self.assertIs(events[0]["os_network_isolation"], False)
        self.assertEqual(events[0]["packages"], 1)

    def test_wrong_commit_lock_config_manifest_and_extra_member_fail_before_any_command(self):
        for index, mode in enumerate(("identity", "lock", "config", "manifest", "extra")):
            entries = dict(self.entries)
            replacement = self.root / (mode + ".txt")
            if mode == "lock":
                replacement.write_bytes(LOCK + b"# changed\n")
                entries["Cargo.lock"] = replacement
            elif mode == "config":
                replacement.write_bytes(b'[net]\noffline=false\n')
                entries[".cargo/config.toml"] = replacement
            elif mode == "manifest":
                data = json.loads(entries["dependency-manifest.json"].read_text(encoding="utf-8"))
                data["packages"][0]["license"] = "wrong"
                replacement.write_text(json.dumps(data), encoding="utf-8")
                entries["dependency-manifest.json"] = replacement
            elif mode == "extra":
                replacement.write_bytes(b"unexpected")
                entries["unexpected.txt"] = replacement
            package = self.root / f"changed-{index}.zip"
            archive.prepare(package, entries, {**IDENTITY, "commit": "b" * 40} if mode == "identity" else IDENTITY)
            scratch = self.root / f"restore-{index}"
            scratch.mkdir()
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                rebuild.rebuild(self.project, package, scratch, IDENTITY, ["cargo", "+1.99.1"], {},
                                lambda *args, **kwargs: self.fail("invalid sources reached a tool"), None, 1, 512)

    def test_tool_resolution_refuses_failures_relative_missing_and_mixed_toolchains(self):
        for mode in ("failure", "relative", "missing", "mixed"):
            def command(argv, *args, **kwargs):
                path = self.tools / argv[-1]
                if mode == "relative":
                    path = Path("relative/cargo")
                elif mode == "missing":
                    path = self.root / "missing"
                elif mode == "mixed" and argv[-1] == "rustc":
                    path = self.root / "different/rustc"
                    path.parent.mkdir()
                    path.write_bytes(b"other tool")
                return (1 if mode == "failure" else 0), str(path).encode("utf-8") + b"\n", b""
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                rebuild.tool_paths(["cargo", "+1.99.1"], {}, command, None, 512)
