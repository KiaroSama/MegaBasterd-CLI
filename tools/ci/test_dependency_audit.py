# SPDX-License-Identifier: GPL-3.0-or-later
"""Tiny archive and command-contract tests; no audit tool, compiler or network runs."""

import hashlib
import importlib.util
import io
import os
from pathlib import Path
import tarfile
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("dependency_audit", Path(__file__).with_name("dependency_audit.py"))
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


class DependencyAuditTests(unittest.TestCase):
    def archive(self, root, changes=None):
        changes = changes or {}
        path = root / "fixture.tar.gz"
        with tarfile.open(path, "w:gz") as stream:
            for name in sorted(audit.MEMBERS):
                entry = tarfile.TarInfo(audit.PREFIX + "/" + name)
                data = b"synthetic tool bytes" if name == "cargo-deny" else b"fixture notice\n"
                entry.size = len(data)
                entry.mode = 0o755 if name == "cargo-deny" else 0o644
                for key, value in changes.get(name, {}).items():
                    setattr(entry, key, value)
                stream.addfile(entry, io.BytesIO(data) if entry.isfile() else None)
        return path

    def test_archive_requires_the_exact_regular_tool_and_notices_before_publication(self):
        base = Path(__file__).resolve().parents[2] / ".ci-work" / "dependency-audit-tests"
        base.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=base) as temporary:
            root = Path(temporary)
            archive = self.archive(root)
            output = root / "tool"
            output.mkdir()
            binary = audit.extract(archive, output)
            self.assertEqual(binary.read_bytes(), b"synthetic tool bytes")
            if os.name != "nt":
                self.assertEqual(binary.stat().st_mode & 0o777, 0o700)
            self.assertEqual({item.name for item in output.iterdir()}, {"cargo-deny"})
            with self.assertRaises(FileExistsError):
                audit.extract(archive, output)
            self.assertEqual(binary.read_bytes(), b"synthetic tool bytes")

    def test_link_traversal_and_missing_notice_leave_no_tool(self):
        base = Path(__file__).resolve().parents[2] / ".ci-work" / "dependency-audit-tests"
        base.mkdir(parents=True, exist_ok=True)
        cases = [
            {"cargo-deny": {"type": tarfile.SYMTYPE, "linkname": "victim"}},
            {"cargo-deny": {"type": tarfile.LNKTYPE, "linkname": "victim"}},
            {"cargo-deny": {"name": audit.PREFIX + "/../cargo-deny"}},
            {"LICENSE-MIT": {"name": audit.PREFIX + "/unexpected"}},
        ]
        with tempfile.TemporaryDirectory(dir=base) as temporary:
            for index, changes in enumerate(cases):
                root = Path(temporary) / str(index)
                root.mkdir()
                archive = self.archive(root, changes)
                output = root / "tool"
                output.mkdir()
                with self.subTest(case=index), self.assertRaises(ValueError):
                    audit.extract(archive, output)
                self.assertEqual(list(output.iterdir()), [])

    def test_audit_checks_version_locked_full_graph_failures_and_lock_drift(self):
        base = Path(__file__).resolve().parents[2] / ".ci-work" / "dependency-audit-tests"
        base.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=base) as temporary:
            root = Path(temporary)
            lock = root / "Cargo.lock"
            lock.write_text("fixture lock\n", encoding="utf-8", newline="\n")
            (root / "Cargo.toml").write_text("[package]\n", encoding="utf-8")
            (root / "deny.toml").write_text("[licenses]\n", encoding="utf-8")
            events = []
            class Log:
                def event(self, *args, **fields):
                    events.append((args, fields))
            for mode in ["ok", "version", "version-failure", "audit-failure", "lock-drift"]:
                calls = []
                lock.write_text("fixture lock\n", encoding="utf-8", newline="\n")
                def command(argv, label, environment, log, **bounds):
                    calls.append((argv, label, bounds))
                    self.assertEqual(environment, {"fixture": "environment"})
                    self.assertGreater(bounds["wall"], 0)
                    self.assertGreater(bounds["idle"], 0)
                    if label == "dependency-audit-version":
                        if mode == "version-failure":
                            return 125, b"", b""
                        return 0, (b"cargo-deny unexpected\n" if mode == "version" else
                                   f"cargo-deny {audit.VERSION}\n".encode("ascii")), b""
                    self.assertEqual(label, "dependency-audit-check")
                    self.assertEqual(argv[1:], ["--locked", "--manifest-path", str(root / "Cargo.toml"),
                        "--config", str(root / "deny.toml"), "--color", "never", "check",
                        "advisories", "licenses", "sources"])
                    if mode == "lock-drift":
                        lock.write_text("changed\n", encoding="utf-8")
                    return (4 if mode == "audit-failure" else 0), b"", b""
                if mode in {"version", "lock-drift"}:
                    with self.subTest(mode=mode), self.assertRaises(ValueError):
                        audit.check(root, root / "cargo-deny", {"fixture": "environment"}, command, Log(), 512)
                else:
                    code = audit.check(root, root / "cargo-deny", {"fixture": "environment"}, command, Log(), 512)
                    self.assertEqual(code, {"audit-failure": 4, "version-failure": 125}.get(mode, 0))
                self.assertEqual(len(calls), 1 if mode in {"version", "version-failure"} else 2)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0][1]["lock_sha256"], hashlib.sha256(b"fixture lock\n").hexdigest())
