# SPDX-License-Identifier: GPL-3.0-or-later
"""Bounded extraction/measurement contracts; native workload execution belongs to CI."""

import ast
import hashlib
import importlib.util
import io
import json
import logging
import os
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("resource_workload", HERE.parent / "oracle/resource_workload.py")
workload = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = workload
SPEC.loader.exec_module(workload)


class ResourceWorkloadTests(unittest.TestCase):
    def test_extraction_retains_complete_original_bodies_and_rejects_missing_or_ambiguous_names(self):
        text = ("import unavailable_dependency\n"
                "raise RuntimeError('module must never execute')\n"
                "LIMIT = 4\n"
                "def selected(value):\n    return value + LIMIT\n"
                "def unrelated():\n    raise AssertionError('must not run')\n")
        tree = workload.selected_definitions(text, {"LIMIT", "selected"})
        original = ast.parse(text)
        self.assertEqual([ast.dump(node) for node in tree.body],
                         [ast.dump(node) for node in original.body[2:4]])
        namespace = {}
        exec(compile(tree, "bounded-extraction-fixture", "exec"), namespace)
        self.assertEqual(namespace["selected"](3), 7)
        self.assertNotIn("unrelated", namespace)
        for invalid in ("LIMIT = OTHER = 4\n", "LIMIT = 4\nLIMIT = 5\n", "OTHER = 4\n"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                workload.selected_definitions(invalid, {"LIMIT"})

    def test_source_hash_is_checked_before_executing_any_selected_definition(self):
        base = HERE.parents[1] / ".ci-work/resource-tooling"
        base.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=base) as temporary:
            root = Path(temporary)
            source = root / "src/megabasterd_cli/core/fixture.py"
            source.parent.mkdir(parents=True)
            text = "def value():\n    return 7\n"
            source.write_text(text, encoding="utf-8", newline="\n")
            digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
            with patch.object(workload, "SOURCES", {"fixture": (digest, {"value"})}):
                self.assertEqual(workload.load_source(root)["value"](), 7)
                source.write_text(text + "# changed\n", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "digest differs"):
                    workload.load_source(root)
                source.unlink()
                with self.assertRaises(OSError):
                    workload.load_source(root)
            with self.assertRaises(ValueError):
                workload.confined(root.parent / "outside", root)
            with self.assertRaises(ValueError):
                workload.confined(root / "src/../src", root)

    def test_checked_runner_transports_only_verified_resource_inputs(self):
        spec = importlib.util.spec_from_file_location("resource_native_runner", HERE / "run-native.py")
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        base = HERE.parents[1] / ".ci-work/resource-tooling"
        base.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=base) as temporary:
            baseline = Path(temporary)
            (baseline / ".git").mkdir()
            commit = "1" * 40
            environment = {"sentinel": "preserved"}
            outputs = [(0, (workload.BASELINE + "\n").encode("ascii"), b""),
                       (0, (commit + "\n").encode("ascii"), b""), (0, b"", b"")]
            snapshot = {"fixture": "no application imported"}
            with patch.object(runner, "command", side_effect=outputs) as command, \
                    patch.object(runner.evidence, "identity", return_value={"commit": commit}) as identity, \
                    patch.object(runner, "load_inputs", return_value=snapshot) as inputs:
                found, current = runner.checked_inputs(baseline, environment, None, 512)
            self.assertIs(found, snapshot)
            self.assertEqual(current, {"commit": commit})
            self.assertEqual(environment, {"sentinel": "preserved",
                             "MEGABASTERD_CI_BASELINE_ROOT": str(baseline),
                             "MEGABASTERD_CI_PYTHON": sys.executable,
                             "MEGABASTERD_CI_COMMIT": commit})
            self.assertEqual(identity.call_args.args[1], commit)
            inputs.assert_called_once_with(runner.ROOT, baseline_root=baseline)
            self.assertEqual([call.args[1] for call in command.call_args_list],
                             ["source-baseline-identity", "candidate-identity", "candidate-clean-tree"])
            environment = {"sentinel": "preserved"}
            with patch.object(runner, "command", return_value=(0, b"0" * 40 + b"\n", b"")), \
                    patch.object(runner, "load_inputs") as inputs:
                with self.assertRaisesRegex(ValueError, "baseline commit differs"):
                    runner.checked_inputs(baseline, environment, None, 512)
                inputs.assert_not_called()
            self.assertEqual(environment, {"sentinel": "preserved"})

    def test_main_closes_exclusive_logs_and_sanitizes_baseline_and_logging_failures(self):
        project = HERE.parents[1]
        base = project / ".ci-work/resource-contract"
        base.mkdir(parents=True, exist_ok=True)
        baseline = Path(os.environ.get("MEGABASTERD_CI_BASELINE_ROOT", str(project)))
        functions = workload.load_source(baseline)
        logger = logging.getLogger("source-resource")
        original_handlers, original_level = list(logger.handlers), logger.level
        self.addCleanup(logger.setLevel, original_level)
        with tempfile.TemporaryDirectory(dir=base) as temporary:
            root = Path(temporary)
            selected_baseline = root / "baseline"
            selected_baseline.mkdir()
            source = root / "input.bin"
            source.write_bytes(b"bounded CLI input\x00\xff")
            original = source.read_bytes()
            log_snapshots = {}
            for mode in ("success", "baseline-error", "logging-error"):
                output = root / mode
                output.mkdir()
                selected = functions.copy()
                if mode == "baseline-error":
                    def fail(*args, **kwargs):
                        raise functions["SplitterError"]("SENTINEL_PRIVATE_PATH password=DO_NOT_EMIT")
                    selected["merge_parts"] = fail
                stdout, stderr = io.StringIO(), io.StringIO()
                arguments = ["resource_workload.py", "--baseline", str(selected_baseline),
                             "--source", str(source), "--directory", str(output)]
                with patch.object(sys, "argv", arguments), \
                        patch.object(workload, "SIZES", (len(original),)), \
                        patch.object(workload, "load_source", return_value=selected), \
                        redirect_stdout(stdout), redirect_stderr(stderr):
                    if mode == "logging-error":
                        with patch.object(workload.logging, "FileHandler", side_effect=OSError("DO_NOT_EMIT")):
                            code = workload.main()
                    else:
                        code = workload.main()
                self.assertEqual(code, 0 if mode == "success" else 1)
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual(stderr.getvalue(), "" if code == 0 else
                                 "Source resource workload failed; inspect private CI diagnostics.\n")
                self.assertEqual(logger.handlers, original_handlers)
                self.assertEqual(source.read_bytes(), original)
                if code == 0:
                    result = json.loads((output / "sample.json").read_text(encoding="utf-8"))
                    self.assertEqual(result["sha256"], hashlib.sha256(original).hexdigest())
                    self.assertEqual((output / "merged.bin").read_bytes(), original)
                else:
                    self.assertFalse((output / "sample.json").exists())
                    self.assertFalse((output / "merged.bin").exists())
                logs = {path.name: path for path in root.glob("resource_workload_*.log")}
                self.assertEqual(len(logs), 1 if mode == "success" else 2)
                for name, previous in log_snapshots.items():
                    self.assertEqual(logs[name].read_bytes(), previous)
                for name, path in logs.items():
                    text = path.read_text(encoding="utf-8", errors="strict")
                    self.assertRegex(name, r"^resource_workload_\d{4}-\d\d-\d\d_\d\d-\d\d-\d\d_UTC_[0-9a-f]{32}\.log$")
                    self.assertIn(" UTC] [INFO] [RESOURCE] Started", text)
                    self.assertNotIn("DO_NOT_EMIT", text)
                    self.assertNotIn("SENTINEL_PRIVATE_PATH", text)
                    if name not in log_snapshots:
                        self.assertIn("Finished exit_code=0" if code == 0 else
                                      "Failed exit_code=1 category=RuntimeError", text)
                    renamed = path.with_suffix(".closed")
                    path.rename(renamed)
                    renamed.rename(path)
                log_snapshots = {name: path.read_bytes() for name, path in logs.items()}

    def test_workload_uses_real_selected_functions_and_keeps_byte_counts_and_timings_explicit(self):
        baseline = Path(os.environ.get("MEGABASTERD_CI_BASELINE_ROOT", str(HERE.parents[1])))
        functions = workload.load_source(baseline)
        base = HERE.parents[1] / ".ci-work/resource-tooling"
        base.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=base) as temporary:
            root = Path(temporary)
            source, output = root / "input.bin", root / "outputs"
            source.write_bytes(b"bounded synthetic input\x00\xff")
            output.mkdir()
            original = source.read_bytes()
            with patch.object(workload, "SIZES", (len(original),)):
                result = workload.workload(source, output, functions)
            self.assertEqual(result["engine"], "python-source")
            self.assertEqual(result["bytes"], len(original))
            self.assertEqual(result["sha256"], hashlib.sha256(original).hexdigest())
            self.assertEqual(result["sha1"], hashlib.sha1(original).hexdigest())
            self.assertEqual((output / "merged.bin").read_bytes(), original)
            self.assertEqual(source.read_bytes(), original)
            self.assertEqual({path.name for path in output.iterdir()},
                             {"input.bin.part1-1", "input.bin.sha1", "merged.bin"})
            for field in ("hash_ns", "split_ns", "merge_ns", "peak_rss_bytes"):
                self.assertIs(type(result[field]), int)
                self.assertGreater(result[field], 0)
            with self.assertRaises(ValueError):
                workload.workload(source, output, functions)
