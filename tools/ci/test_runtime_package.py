# SPDX-License-Identifier: GPL-3.0-or-later
"""Runtime archive preparation with synthetic bytes; no binary or compiler executes."""

import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

HERE = Path(__file__).resolve().parents[1] / "package"
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location("runtime_package", HERE / "runtime.py")
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)

IDENTITY = {"version": "2.0.0", "commit": "a" * 40,
            "target": "x86_64-pc-windows-msvc", "kind": "runtime"}


class RuntimePackageTests(unittest.TestCase):
    def test_exact_runtime_archive_extracts_aliases_notices_and_retains_bytes_and_modes(self):
        import archive
        base = Path(__file__).resolve().parents[2] / ".ci-work" / "runtime-package-tests"
        base.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=base) as temporary:
            root = Path(temporary)
            entries = {}
            for name in ["mb.exe", "mbcli.exe", "megabasterd-cli.exe", "LICENSE", "licenses/MIT-historical.txt"]:
                path = root / (name.replace("/", "-"))
                path.write_bytes((name + " synthetic fixture").encode("utf-8"))
                entries[name] = path
            package = root / "intermediate.zip"
            archive.prepare(package, entries, IDENTITY)
            destination = root / "extracted native with spaces"
            runtime.extract(package, destination, IDENTITY)
            for name, path in entries.items():
                self.assertEqual((destination / name).read_bytes(), path.read_bytes())
            if os.name != "nt":
                self.assertEqual((destination / "mb.exe").stat().st_mode & 0o777, 0o755)
            with self.assertRaises(FileExistsError):
                runtime.extract(package, destination, IDENTITY)
            self.assertFalse((destination / "src").exists())
            with self.assertRaises(ValueError):
                runtime.extract(package, root / "wrong identity", {**IDENTITY, "commit": "b" * 40})
            with zipfile.ZipFile(package) as source, zipfile.ZipFile(root / "tampered.zip", "x") as output:
                for info in source.infolist():
                    output.writestr(info, b"changed" if info.filename == "mb.exe" else source.read(info))
            with self.assertRaises(ValueError):
                runtime.extract(root / "tampered.zip", root / "bad output", IDENTITY)
            self.assertFalse((root / "bad output").exists())

    def test_optimized_build_prepares_only_the_declared_intermediate_before_relocated_commands(self):
        import archive
        import shutil
        from test_source_rebuild import fixture
        base = Path(__file__).resolve().parents[2] / ".ci-work" / "runtime-package-tests"
        base.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=base) as temporary:
            for mode in ("ok", "build-failure", "smoke-failure", "missing-host", "launcher-failure"):
                root = Path(temporary) / mode
                root.mkdir()
                project_archive, _, _, tools = fixture(root)
                project = root / "source inputs"
                original_lock = (project / "Cargo.lock").read_bytes()
                calls, events = [], []
                class Log:
                    def event(self, *args, **fields):
                        events.append((args, fields))
                def command(argv, label, environment, log, **bounds):
                    calls.append(label)
                    if label == "distribution-vendor":
                        self.assertEqual(argv[:5], ["cargo", "+1.99.1", "vendor", "--locked", "--versioned-dirs"])
                        shutil.copytree(project / "vendor", argv[-1])
                        return 0, b'[source.crates-io]\nreplace-with="vendored-sources"\n[source.vendored-sources]\ndirectory="vendor"\n', b""
                    if label.startswith("rebuild-tool-"):
                        return 0, str(tools / argv[-1]).encode("utf-8") + b"\n", b""
                    if label == "extracted-source-build":
                        self.assertEqual(argv, [tools / "cargo", "build", "--frozen", "--release",
                                                "--workspace", "--bins", "-j", "1"])
                        if mode == "build-failure":
                            return 101, b"", b""
                        release = Path(environment["CARGO_TARGET_DIR"]) / "release"
                        release.mkdir()
                        for name in runtime.ALIASES:
                            (release / (name + ".exe")).write_bytes((name + " fixture").encode("ascii"))
                        return 0, b"", b""
                    if mode == "smoke-failure":
                        return 1, b"", b""
                    if label.startswith("packaged-launcher-"):
                        if mode == "launcher-failure":
                            return 7, b"", b""
                        self.assertEqual(argv[:5], [tools / "pwsh.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-File"])
                        launcher, arguments = Path(argv[5]), argv[6:]
                        self.assertEqual(launcher.name, "Run.ps1")
                        self.assertIn("native with spaces", launcher.parts)
                        self.assertEqual(launcher.read_bytes(), b"synthetic source or notice\n")
                        self.assertEqual(bounds["cwd"].name, "unrelated caller")
                        self.assertEqual((bounds["wall"], bounds["idle"]), (15, 5))
                        self.assertTrue(all(key in runtime.RUNTIME_KEYS for key in environment))
                        self.assertFalse(any(key.startswith("MEGABASTERD_") for key in environment))
                        self.assertEqual(environment["PATH"], str(launcher.parent.parent / "home/empty executable search path"))
                        if label.endswith("-set"):
                            self.assertEqual(arguments, ["--no-log-file", "config", "set", "download_path", "launcher  literal & [safe]"])
                            return 0, b"", b"[INFO] Configuration setting saved.\r\n"
                        if label.endswith("-get"):
                            self.assertEqual(arguments, ["--no-log-file", "config", "get", "download_path"])
                            return 0, b"launcher  literal & [safe]\r\n", b""
                        binary = launcher.parent / "mb.exe"
                    else:
                        binary, arguments = Path(argv[0]), argv[1:]
                    self.assertIn("native with spaces", binary.parts)
                    self.assertEqual(binary.read_bytes(), (binary.stem + " fixture").encode("ascii"))
                    if arguments == ["--version"]:
                        return 0, b"mb 2.0.0\n", b""
                    if arguments == ["--help"]:
                        return 0, b"Usage: download --help\n", b""
                    if arguments == ["--not-a-real-option"]:
                        return 2, b"", b"[ERROR] Invalid option\n"
                    if not arguments:
                        return 2, b"", b"[ERROR] No command provided. Use mb --help in noninteractive mode.\n"
                    if arguments[-2:] == ["get", "max_workers"]:
                        return 0, b"8\n", b""
                    return 0, str(binary.parent / "User/native-v2/Config/config.json").encode("utf-8") + b"\n", b""
                args = (project, {"commit": IDENTITY["commit"]}, IDENTITY["target"],
                        ["cargo", "+1.99.1"], {}, command, Log(), 1, 512)
                if mode == "ok":
                    with mock.patch.object(runtime.shutil, "which", return_value=str(tools / "pwsh.exe")) as lookup:
                        path, report = runtime.prepare_runtime(*args, project_archive=project_archive)
                    lookup.assert_called_once_with("pwsh.exe", path="")
                    manifest = archive.verify(path)
                    self.assertEqual(len(manifest["files"]), 11)
                    self.assertEqual([row["path"] for row in manifest["files"]
                                      if "/" not in row["path"] and row["path"].lower().endswith(".ps1")],
                                     ["Run.ps1"])
                    with zipfile.ZipFile(path) as packed:
                        self.assertEqual(packed.read("Run.ps1"),
                                         (project / "tools/launcher/Run.Native.ps1").read_bytes())
                        self.assertEqual(packed.read("licenses/dependencies/tiny-1.2.3/LICENSE"),
                                         b"Synthetic fixture notice\n")
                        import json
                        index = json.loads(packed.read("licenses/dependencies/index.json"))
                        self.assertEqual(index["identity"], IDENTITY)
                        self.assertEqual(index["packages"][0]["name"], "tiny")
                        self.assertEqual(index["packages"][0]["version"], "1.2.3")
                    self.assertIn("UNSIGNED-INTERMEDIATE", path.name)
                    self.assertEqual(len(calls), 28)
                    self.assertEqual(calls[-5:], ["packaged-launcher-" + case
                                                 for case in ("version", "invalid", "path", "set", "get")])
                    self.assertEqual(report["bytes"], path.stat().st_size)
                    self.assertEqual(len(events), 3)
                    self.assertIn("not for publication", events[-1][1]["signing"])
                else:
                    selected = None if mode == "missing-host" else str(tools / "pwsh.exe")
                    with (self.subTest(mode=mode),
                          mock.patch.object(runtime.shutil, "which", return_value=selected),
                          self.assertRaises(ValueError)):
                        runtime.prepare_runtime(*args, project_archive=project_archive)
                    self.assertEqual(len(events), 1 if mode == "build-failure" else 2)
                    self.assertTrue(all("relocated smoke passed" not in event[0][1] for event in events))
                self.assertTrue(all(event[1]["release_ready"] is False for event in events))
                output = project / ".ci-work/runtime-intermediate" / IDENTITY["target"]
                self.assertEqual({child.name for child in output.iterdir() if child.is_dir()}, {"dependency-source"})
                self.assertEqual((project / "Cargo.lock").read_bytes(), original_lock)

    def test_packaged_launcher_requires_a_host_preserves_literal_arguments_and_rejects_bad_results(self):
        base = Path(__file__).resolve().parents[2] / ".ci-work/runtime-package-tests"
        base.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=base) as temporary:
            root = Path(temporary)
            release, cwd, home = [root / name for name in ("release with spaces", "caller", "home")]
            for path in (release, cwd, home):
                path.mkdir()
            (release / "Run.ps1").write_bytes(b"fixture never executed")
            host = root / "installed PowerShell/powershell.exe"
            host.parent.mkdir()
            host.write_bytes(b"fixture never executed")
            class Log:
                def event(self, *args, **kwargs):
                    pass
            for fault in (None, "version", "invalid", "path", "set", "get"):
                calls = []
                def command(argv, label, environment, log, **bounds):
                    case = label.removeprefix("packaged-launcher-")
                    calls.append(case)
                    self.assertEqual(argv[:6], [host, "-NoLogo", "-NoProfile", "-NonInteractive",
                                               "-File", release / "Run.ps1"])
                    if case == "set":
                        self.assertEqual(argv[6:], ["--no-log-file", "config", "set", "download_path",
                                                   "launcher  literal & [safe]"])
                    results = {"version": (0, b"mb 2.0.0\n", b""),
                               "invalid": (2, b"", b"[ERROR] Invalid option\n"),
                               "path": (0, str(release / "User/native-v2/Config/config.json").encode("utf-8") + b"\n", b""),
                               "set": (0, b"", b"[INFO] Configuration setting saved.\n"),
                               "get": (0, b"launcher  literal & [safe]\n", b"")}
                    return (0, b"wrong\n", b"") if case == fault else results[case]
                with mock.patch.object(runtime.shutil, "which", side_effect=[None, str(host)]) as lookup:
                    args = (release, IDENTITY, cwd, home, {"PATH": "approved host path"}, command, Log(), 512)
                    if fault is None:
                        runtime.smoke_launcher(*args)
                        self.assertEqual(calls, ["version", "invalid", "path", "set", "get"])
                    else:
                        with self.subTest(fault=fault), self.assertRaises(ValueError):
                            runtime.smoke_launcher(*args)
                        self.assertEqual(calls[-1], fault)
                    self.assertEqual(lookup.call_args_list,
                                     [mock.call("pwsh.exe", path="approved host path"),
                                      mock.call("powershell.exe", path="approved host path")])
            with mock.patch.object(runtime.shutil, "which", return_value=None):
                with self.assertRaises(ValueError):
                    runtime.smoke_launcher(*args)
            runtime.smoke_launcher(release, {**IDENTITY, "target": "x86_64-unknown-linux-gnu"},
                                   cwd, home, {}, lambda *a, **k: self.fail("non-Windows host lookup"), Log(), 512)
            self.assertEqual(list(cwd.iterdir()), [])

    def test_relocated_alias_commands_use_only_runtime_environment_and_exact_failure_status(self):
        base = Path(__file__).resolve().parents[2] / ".ci-work" / "runtime-package-tests"
        base.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=base) as temporary:
            root = Path(temporary)
            release = root / "extracted runtime with spaces"
            release.mkdir()
            cwd = root / "unrelated caller"
            home = root / "isolated home"
            cwd.mkdir()
            home.mkdir()
            paths = {name: release / (name + ".exe") for name in runtime.ALIASES}
            for path in paths.values():
                path.write_bytes(b"fixture only")
            calls = []
            class Log:
                def event(self, *args, **kwargs):
                    pass
            def command(argv, label, environment, log, **bounds):
                calls.append((argv, environment, bounds))
                self.assertEqual(bounds["cwd"], cwd)
                self.assertEqual(bounds["wall"], 15)
                self.assertEqual(bounds["idle"], 5)
                self.assertTrue(all(key in runtime.RUNTIME_KEYS for key in environment))
                self.assertEqual(environment["PATH"], str(home / "empty executable search path"))
                self.assertFalse(any(key.startswith("MEGABASTERD_") for key in environment))
                arguments = argv[1:]
                if arguments == ["--version"]:
                    return 0, b"mb 2.0.0\n", b""
                if arguments == ["--help"]:
                    return 0, b"Usage: mb [OPTIONS] [COMMAND]\n download\n --help\n", b""
                if arguments == ["--not-a-real-option"]:
                    return 2, b"", b"[ERROR] Invalid option\n"
                if not arguments:
                    return 2, b"", b"[ERROR] No command provided. Use mb --help in noninteractive mode.\n"
                if arguments[-2:] == ["get", "max_workers"]:
                    return 0, b"8\n", b""
                return 0, str(release / "User/native-v2/Config/config.json").encode("utf-8") + b"\n", b""
            runtime.smoke(paths, IDENTITY, cwd, home, {}, command, Log(), 512)
            self.assertEqual(len(calls), 18)
            with self.assertRaises(ValueError):
                runtime.smoke(paths, IDENTITY, cwd, home, {},
                              lambda *args, **kwargs: (0, b"wrong", b""), Log(), 512)
