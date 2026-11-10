# SPDX-License-Identifier: GPL-3.0-or-later
"""Pure receipt/harness checks; tiny files and RAM literals, no target execution."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import native_evidence as evidence

SHA = "1" * 40
ENVIRONMENT = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": evidence.REPOSITORY,
               "GITHUB_SHA": SHA, "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2"}
DIGEST = hashlib.sha256(b"reviewed fixture source\n").hexdigest()
REFERENCE = "src/cli/controlled.rs::case"
WANTED = {REFERENCE: {"suite": "src/lib.rs", "harness_test": "cli::controlled::case",
                      "source_sha256": DIGEST, "required_platforms": ["linux", "macos", "windows"]}}


def output(names):
    return "".join(f"ok {name}\n" for name in names).encode("utf-8")


class NativeEvidenceTests(unittest.TestCase):
    def setUp(self):
        base = Path(__file__).resolve().parents[2] / ".ci-work" / "evidence-tooling-tests"
        base.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=base)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def test_workflow_identity_rejects_wrong_commit_repo_run_or_attempt(self):
        self.assertEqual(evidence.identity(ENVIRONMENT, SHA), {
            "repository": evidence.REPOSITORY, "commit": SHA, "run_id": "123", "run_attempt": "2"})
        for key, value in [("GITHUB_ACTIONS", "false"), ("GITHUB_REPOSITORY", "other/repo"),
                           ("GITHUB_SHA", "2" * 40), ("GITHUB_RUN_ID", "0"),
                           ("GITHUB_RUN_ATTEMPT", "-1")]:
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    evidence.identity({**ENVIRONMENT, key: value}, SHA)

    def test_pretty_discovery_is_exact_bounded_and_never_accepts_benchmarks(self):
        data = b"cli::controlled::case: test\r\nother: test\r\n\r\n2 tests, 0 benchmarks\r\n"
        self.assertEqual(evidence.discovery(data), {"cli::controlled::case", "other"})
        self.assertEqual(evidence.discovery(b"0 tests, 0 benchmarks\n"), set())
        for invalid in [b"case: test\ncase: test\n2 tests, 0 benchmarks\n",
                        b"case: test\n0 tests, 0 benchmarks\n",
                        b"case: benchmark\n0 tests, 1 benchmark\n",
                        b"case: test\n", b"1 test, 0 benchmarks\ncase: test\n"]:
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    evidence.discovery(invalid)

    def test_results_require_each_discovered_name_once_and_zero_filtered_ignored_or_failed(self):
        names = {"cli::controlled::case", "other"}
        valid = output(sorted(names))
        self.assertEqual(evidence.results(valid, names), names)
        self.assertEqual(evidence.results(valid.replace(b"\n", b"\r\n"), names), names)
        for invalid in [output(["other"]), valid + b"ok other\n",
                        valid.replace(b"ok other", b"ok unknown"),
                        valid.replace(b"ok other", b"ignored other"),
                        valid.replace(b"ok other", b"ignored: reason other"),
                        valid.replace(b"ok other", b"failed other"),
                        valid.replace(b"ok other", b"failed: detail other"),
                        b"", valid + valid, valid + b"unexpected text\n"]:
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    evidence.results(invalid, names)
        path = self.root / "results.txt"
        path.write_bytes(valid)
        self.assertEqual(evidence.result_file(path, names), names)
        with self.assertRaises(ValueError):
            evidence.result_file(self.root / "missing", names)

    def test_cargo_artifacts_require_complete_current_package_and_contained_executables(self):
        target = {"name": "controlled", "kind": ["test"], "src_path": str(self.root / "tests/controlled.rs"),
                  "test": True}
        package = {"id": "path+controlled#2.0.0", "manifest_path": str(self.root / "Cargo.toml"),
                   "targets": [target]}
        metadata = {"packages": [package]}
        output_root = self.root / "build"
        output_root.mkdir()
        executable = output_root / "controlled.exe"
        executable.write_bytes(b"fixture, never executed")
        message = {"reason": "compiler-artifact", "package_id": package["id"],
                   "profile": {"test": True}, "target": target, "executable": str(executable)}
        finish = {"reason": "build-finished", "success": True}
        def encoded(messages):
            return ("\n".join(json.dumps(item) for item in messages) + "\n").encode("utf-8")
        found = evidence.artifacts(encoded([message, finish]), metadata, self.root, output_root)
        self.assertEqual(found[0]["source"], "tests/controlled.rs")
        self.assertEqual(found[0]["executable"], executable)
        outside = self.root / "outside.exe"
        outside.write_bytes(b"not executed")
        for invalid in [[finish], [message], [message, message, finish],
                        [message, {**finish, "success": False}],
                        [{**message, "package_id": "other"}, finish],
                        [{**message, "executable": None}, finish],
                        [{**message, "executable": str(outside)}, finish],
                        [{**message, "executable": str(output_root / "missing")}, finish],
                        [message, finish, finish]]:
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    evidence.artifacts(encoded(invalid), metadata, self.root, output_root)

    def test_assertion_identity_is_full_name_not_an_ambiguous_leaf(self):
        target = {"path": "src/cli/controlled.rs", "test": "case", "harness_test": "cli::controlled::case",
                  "source_sha256": DIGEST, "required_platforms": ["windows", "linux", "macos"]}
        ledger = {"modules": [{"tests": [{"targets": [target]}]}]}
        self.assertEqual(evidence.references(ledger), WANTED)
        self.assertEqual(evidence.passed_references(WANTED, {"src/lib.rs": {"cli::controlled::case"}},
                                                    target="x86_64-pc-windows-msvc"),
                         {REFERENCE: {"source_sha256": DIGEST}})
        for suites in [{}, {"src/lib.rs": {"other::case"}}, {"tests/controlled.rs": {"cli::controlled::case"}}]:
            with self.assertRaises(ValueError):
                evidence.passed_references(WANTED, suites, target="x86_64-pc-windows-msvc")
        for full in [None, "cli::other::different", "cli::../case"]:
            target["harness_test"] = full
            with self.assertRaises(ValueError):
                evidence.references(ledger)

    def test_shared_assertion_requires_the_union_of_every_source_platform_scope(self):
        target = {"path": "src/cli/controlled.rs", "test": "case", "harness_test": "cli::controlled::case",
                  "source_sha256": DIGEST, "required_platforms": ["windows"]}
        unix = {**target, "required_platforms": ["linux", "macos"]}
        ledger = {"modules": [{"tests": [{"targets": [target]}, {"targets": [unix]}]}]}
        self.assertEqual(evidence.references(ledger), WANTED)
        unix["source_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "conflicting"):
            evidence.references(ledger)
        for value in [None, [], ["unknown"], ["linux", "linux"]]:
            target["required_platforms"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                evidence.references({"modules": [{"tests": [{"targets": [target]}]}]})

    def receipt_set(self):
        directory = self.root / "receipts"
        context = evidence.identity(ENVIRONMENT, SHA)
        suites = {"src/lib.rs": {"cli::controlled::case"}}
        for target in evidence.TARGETS:
            report = evidence.receipt(context, target, WANTED, suites)
            evidence.write_receipt(directory / f"native-evidence-{target}/receipt.json", report)
        return directory, context

    def test_aggregation_requires_both_macos_architectures_and_exact_run_and_digest(self):
        directory, context = self.receipt_set()
        with patch.object(evidence, "references", return_value=WANTED), \
                patch.object(evidence, "reconcile_coverage", return_value={"execution_complete": True}) as reconcile, \
                patch.object(evidence, "require_report", wraps=evidence.require_report) as gate:
            reconcile.return_value = {"structure_complete": True, "accounting_ready": True,
                                      "execution_complete": True}
            retirements = {"tests/test_fixture.py::test_import": "fixture-only-approval"}
            result = evidence.aggregate({"ledger": {}}, directory, context,
                                        retirement_approvals=retirements)
            self.assertTrue(result["execution_complete"])
            self.assertIs(reconcile.call_args.kwargs["retirement_approvals"], retirements)
            merged = reconcile.call_args.kwargs["execution_evidence"]
            self.assertEqual(set(merged["targets"][REFERENCE]["passed_platforms"]), {"windows", "linux", "macos"})
            self.assertEqual(reconcile.call_args.kwargs["expected_commit"], SHA)
            gate.assert_called_once_with(result, stage="execution")
            reconcile.return_value = {**result, "accounting_ready": False, "execution_complete": False}
            with self.assertRaises(ValueError):
                evidence.aggregate({"ledger": {}}, directory, context)
            reconcile.return_value = result
            extra = directory / "unexpected"
            extra.mkdir()
            with self.assertRaises(ValueError):
                evidence.aggregate({"ledger": {}}, directory, context)
            extra.rmdir()
            extra = directory / "native-evidence-aarch64-apple-darwin" / "extra.json"
            extra.write_text("{}", encoding="utf-8")
            with self.assertRaises(ValueError):
                evidence.aggregate({"ledger": {}}, directory, context)
            extra.unlink()
            path = directory / "native-evidence-aarch64-apple-darwin/receipt.json"
            original = path.read_text(encoding="utf-8")
            for key, value in [("commit", "2" * 40), ("run_id", "124"), ("run_attempt", "1"),
                               ("target", "x86_64-apple-darwin"), ("repository", "other/repo"),
                               ("schema_version", True), ("test_count", 0), ("targets", {})]:
                invalid = json.loads(original)
                invalid[key] = value
                path.write_text(json.dumps(invalid), encoding="utf-8")
                with self.subTest(key=key), self.assertRaises(ValueError):
                    evidence.aggregate({"ledger": {}}, directory, context)
            invalid = json.loads(original)
            invalid["targets"][REFERENCE]["source_sha256"] = "0" * 64
            path.write_text(json.dumps(invalid), encoding="utf-8")
            with self.assertRaises(ValueError):
                evidence.aggregate({"ledger": {}}, directory, context)
            path.unlink()
            with self.assertRaises(ValueError):
                evidence.aggregate({"ledger": {}}, directory, context)

    def test_receipt_outputs_are_exclusive_utf8_and_duplicate_keys_are_refused(self):
        directory, _ = self.receipt_set()
        path = next(directory.rglob("receipt.json"))
        before = path.read_bytes()
        with self.assertRaises(FileExistsError):
            evidence.write_receipt(path, {})
        self.assertEqual(path.read_bytes(), before)
        with self.assertRaises(ValueError):
            json.loads('{"commit":"one","commit":"two"}', object_pairs_hook=evidence.pairs)
        with self.assertRaises(UnicodeError):
            evidence.decode(b"\xff")
