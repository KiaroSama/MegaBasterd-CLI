# SPDX-License-Identifier: GPL-3.0-or-later
"""Run via the owned CI runner: unittest discovery in tools/ci, no target imports.

One actual full-ledger/source snapshot is loaded for the class. Mutations stay in RAM;
no mapping/status/hash is written back and no retained Python/Rust test is executed.
"""

import ast
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import unittest

try:
    from . import coverage_contract as coverage
except ImportError:
    import coverage_contract as coverage

ROOT = Path(__file__).resolve().parents[2]
SHA = "1" * 40
OTHER_SHA = "2" * 40
TARGET_TEXT = "#[test]\nfn controlled_parity_case() { assert_eq!(2 + 2, 4); }\n"
TARGET_PATH = "tests/controlled_contract.rs"


class CoverageContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        baseline = os.environ.get("MEGABASTERD_CI_BASELINE_ROOT")
        cls.inputs = coverage.load_inputs(ROOT, baseline_root=baseline)
        cls.report = coverage.reconcile_coverage(cls.inputs)
        cls.written_index = next(
            (mi, ri) for mi, module in enumerate(cls.inputs["ledger"]["modules"])
            for ri, row in enumerate(module["tests"])
            if row["status"] == "written_unexecuted"
        )

    def snapshot(self):
        return {"ledger": deepcopy(self.inputs["ledger"]),
                "sources": dict(self.inputs["sources"]),
                "targets": dict(self.inputs["targets"]),
                "platform_helper": self.inputs["platform_helper"]}

    def selected(self, snapshot):
        mi, ri = self.written_index
        return snapshot["ledger"]["modules"][mi]["tests"][ri]

    def verified_fixture(self):
        snapshot = self.snapshot()
        row = self.selected(snapshot)
        row["status"] = "verified"
        original = deepcopy(row["targets"][0])
        original.update(path=TARGET_PATH, test="controlled_parity_case",
                        harness_test="controlled_parity_case",
                        source_sha256=hashlib.sha256(TARGET_TEXT.encode("utf-8")).hexdigest())
        row["targets"] = [original]
        snapshot["targets"][TARGET_PATH] = TARGET_TEXT
        evidence = {"commit": SHA, "targets": {TARGET_PATH + "::controlled_parity_case": {
            "source_sha256": original["source_sha256"],
            "passed_platforms": ["windows", "linux", "macos"]}}}
        return snapshot, evidence

    def test_actual_ledger_denominator_and_pending_are_honest_not_runtime_counts(self):
        report = self.report
        self.assertEqual(report["definitions"], 1416)
        self.assertEqual(report["modules"], 164)
        self.assertEqual(report["parameterized_definitions"], 117)
        self.assertEqual(report["parameter_decorators"], 118)
        self.assertIsNone(report["runtime_cases"])
        self.assertEqual(sum(report["statuses"].values()), 1416)
        unresolved = report["statuses"].get("pending", 0) + report["statuses"].get("blocked", 0)
        if unresolved:
            self.assertFalse(report["accounting_ready"])
        self.assertFalse(report["execution_complete"])
        self.assertLessEqual(len(report["examples"]), 12)
        with self.assertRaises(coverage.CoverageError):
            coverage.require_report(report, stage="execution")

    def test_structural_fingerprint_ignores_only_absent_empty_type_parameters(self):
        source = '@pytest.mark.parametrize("value", [1, 2])\ndef test_value(value):\n    assert value > 0\n'
        absent = ast.parse(source).body[0]
        absent._fields = tuple(name for name in absent._fields if name != "type_params")
        empty = deepcopy(absent)
        empty._fields = (*empty._fields, "type_params")
        empty.type_params = []
        self.assertEqual(coverage._ast_sha(absent), coverage._ast_sha(empty))
        reordered = deepcopy(empty)
        reordered._fields = tuple(reversed(reordered._fields))
        self.assertEqual(coverage._ast_sha(empty), coverage._ast_sha(reordered))
        nonempty = deepcopy(empty)
        nonempty.type_params = [ast.Name(id="T", ctx=ast.Load())]
        self.assertNotEqual(coverage._ast_sha(empty), coverage._ast_sha(nonempty))
        for replacement in [source.replace("value > 0", "value > 1"),
                            source.replace("[1, 2]", "[1, 3]")]:
            with self.subTest(replacement=replacement):
                self.assertNotEqual(coverage._ast_sha(empty), coverage._ast_sha(ast.parse(replacement).body[0]))

    def test_gate_stages_do_not_require_execution_before_tests_can_start(self):
        # Stage transitions are independent of the still-incomplete actual migration ledger.
        report = {"structure_complete": True, "accounting_ready": True,
                  "execution_complete": False, "problems": {"execution": 1}}
        self.assertIs(coverage.require_report(report, stage="structure"), report)
        self.assertIs(coverage.require_report(report, stage="accounting"), report)
        with self.assertRaises(coverage.CoverageError):
            coverage.require_report(report, stage="execution")
        report["accounting_ready"] = False
        with self.assertRaises(coverage.CoverageError):
            coverage.require_report(report, stage="accounting")
        with self.assertRaisesRegex(coverage.CoverageError, "Unknown coverage gate"):
            coverage.require_report(report, stage="invented")
        report["execution_complete"] = True
        with self.assertRaises(coverage.CoverageError):
            coverage.require_report(report, stage="execution")
        with self.assertRaises(coverage.CoverageError):
            coverage.require_report(None, stage="structure")

    def test_omitted_definition_and_module_cannot_pass_structure_gate(self):
        for module_missing in [False, True]:
            with self.subTest(module_missing=module_missing):
                snapshot = self.snapshot()
                if module_missing:
                    snapshot["ledger"]["modules"].pop()
                else:
                    snapshot["ledger"]["modules"][0]["tests"].pop()
                with self.assertRaisesRegex(coverage.CoverageError, "accounting is incomplete|total differs"):
                    coverage.reconcile_coverage(snapshot)

    def test_duplicate_identity_or_module_is_rejected_not_double_counted(self):
        for duplicate_module in [False, True]:
            with self.subTest(duplicate_module=duplicate_module):
                snapshot = self.snapshot()
                modules = snapshot["ledger"]["modules"]
                if duplicate_module:
                    modules[-1] = deepcopy(modules[0])
                else:
                    modules[0]["tests"][1] = deepcopy(modules[0]["tests"][0])
                with self.assertRaisesRegex(coverage.CoverageError, "Duplicate"):
                    coverage.reconcile_coverage(snapshot)

    def test_duplicate_json_key_cannot_override_a_disposition(self):
        with self.assertRaisesRegex(coverage.CoverageError, "Duplicate JSON"):
            json.loads('{"status":"pending","status":"verified"}', object_pairs_hook=coverage._pairs)

    def test_changed_source_and_parameters_are_not_accepted_by_surviving_names(self):
        snapshot = self.snapshot()
        module = snapshot["ledger"]["modules"][0]
        snapshot["sources"][module["source"]] += "\n# changed baseline\n"
        self.selected(snapshot)["source_ast_sha256"] = "0" * 64
        parameterized = next(row for m in snapshot["ledger"]["modules"] for row in m["tests"] if row["parameters"])
        parameterized["parameters"][0]["decorator_sha256"] = "0" * 64
        report = coverage.reconcile_coverage(snapshot)
        self.assertGreaterEqual(report["problems"]["structure"], self.report["problems"]["structure"] + 3)
        self.assertFalse(report["structure_complete"])

    def test_stale_target_digest_and_undefined_function_are_detected(self):
        snapshot = self.snapshot()
        row = self.selected(snapshot)
        row["targets"][0]["source_sha256"] = "0" * 64
        row["targets"][0]["test"] = "missing_parity_assertion"
        row["targets"][0]["harness_test"] = "missing_parity_assertion"
        report = coverage.reconcile_coverage(snapshot)
        snapshot2 = self.snapshot()
        self.selected(snapshot2)["targets"][0]["path"] = TARGET_PATH
        self.selected(snapshot2)["targets"][0]["test"] = "controlled_parity_case"
        self.selected(snapshot2)["targets"][0]["harness_test"] = "controlled_parity_case"
        self.selected(snapshot2)["targets"][0]["source_sha256"] = hashlib.sha256(TARGET_TEXT.encode("utf-8")).hexdigest()
        snapshot2["targets"][TARGET_PATH] = TARGET_TEXT
        clean_reference = coverage.reconcile_coverage(snapshot2)
        self.selected(snapshot2)["targets"][0]["source_sha256"] = "0" * 64
        self.selected(snapshot2)["targets"][0]["test"] = "missing_parity_assertion"
        self.selected(snapshot2)["targets"][0]["harness_test"] = "missing_parity_assertion"
        broken_reference = coverage.reconcile_coverage(snapshot2)
        self.assertEqual(broken_reference["problems"]["structure"], clean_reference["problems"]["structure"] + 2)
        with self.assertRaises(coverage.CoverageError):
            coverage.require_report(report, stage="structure")

    def test_missing_target_file_is_not_a_valid_test_reference(self):
        snapshot, _ = self.verified_fixture()
        before = coverage.reconcile_coverage(snapshot)
        snapshot["targets"].pop(TARGET_PATH)
        report = coverage.reconcile_coverage(snapshot)
        self.assertFalse(report["structure_complete"])
        self.assertEqual(report["problems"]["structure"], before["problems"]["structure"] + 2)

    def test_narrowed_or_duplicate_native_scope_is_always_rejected(self):
        for platforms in [["linux"], [], ["windows", "linux"], ["linux", "linux", "macos"], ["unknown"]]:
            with self.subTest(platforms=platforms):
                snapshot = self.snapshot()
                self.selected(snapshot)["targets"][0]["required_platforms"] = platforms
                with self.assertRaisesRegex(coverage.CoverageError, "platform"):
                    coverage.reconcile_coverage(snapshot)

    def test_evidence_must_match_explicit_expected_commit_not_merely_a_valid_sha(self):
        snapshot, evidence = self.verified_fixture()
        good = coverage.reconcile_coverage(snapshot, expected_commit=SHA, execution_evidence=evidence)
        written_rows = sum(len(row["targets"]) for module in snapshot["ledger"]["modules"]
                           for row in module["tests"] if row["status"] in {"written_unexecuted", "verified"})
        for expected in [None, OTHER_SHA]:
            with self.subTest(expected=expected):
                report = coverage.reconcile_coverage(snapshot, expected_commit=expected,
                                                     execution_evidence=evidence)
                self.assertEqual(report["problems"]["execution"], good["problems"]["execution"] + written_rows)
                self.assertFalse(report["execution_complete"])
        with self.assertRaisesRegex(coverage.CoverageError, "expected current commit"):
            coverage.reconcile_coverage(snapshot, expected_commit="main", execution_evidence=evidence)

    def test_forged_verified_row_without_external_results_cannot_complete(self):
        snapshot, evidence = self.verified_fixture()
        good = coverage.reconcile_coverage(snapshot, expected_commit=SHA, execution_evidence=evidence)
        empty = coverage.reconcile_coverage(snapshot, expected_commit=SHA)
        rows = sum(len(row["targets"]) for module in snapshot["ledger"]["modules"]
                   for row in module["tests"] if row["status"] in {"written_unexecuted", "verified"})
        self.assertEqual(empty["problems"]["execution"], good["problems"]["execution"] + rows + 1)
        self.assertFalse(good["execution_complete"], "other pending rows must remain blocking")
        self.assertEqual(good["statuses"].get("verified"), 1)

    def test_missing_platform_results_or_wrong_target_bytes_do_not_verify(self):
        snapshot, evidence = self.verified_fixture()
        good = coverage.reconcile_coverage(snapshot, expected_commit=SHA, execution_evidence=evidence)
        reference = TARGET_PATH + "::controlled_parity_case"
        for missing in [True, False]:
            with self.subTest(missing_platform=missing):
                bad = deepcopy(evidence)
                if missing:
                    bad["targets"][reference]["passed_platforms"] = ["linux"]
                else:
                    bad["targets"][reference]["source_sha256"] = "0" * 64
                report = coverage.reconcile_coverage(snapshot, expected_commit=SHA, execution_evidence=bad)
                self.assertEqual(report["problems"]["execution"], good["problems"]["execution"] + 1)

    def test_written_rows_can_use_external_evidence_without_post_ci_ledger_edits(self):
        snapshot, evidence = self.verified_fixture()
        self.selected(snapshot)["status"] = "written_unexecuted"
        before = deepcopy(snapshot["ledger"])
        report = coverage.reconcile_coverage(snapshot, expected_commit=SHA, execution_evidence=evidence)
        self.assertEqual(snapshot["ledger"], before)
        empty = coverage.reconcile_coverage(snapshot, expected_commit=SHA)
        rows = sum(len(row["targets"]) for module in snapshot["ledger"]["modules"]
                   for row in module["tests"] if row["status"] in {"written_unexecuted", "verified"})
        self.assertEqual(empty["problems"]["execution"], report["problems"]["execution"] + rows + 1)
        self.assertFalse(report["execution_complete"], "the other unresolved rows must still block")

    def test_forged_retirement_requires_separately_supplied_exact_authority(self):
        snapshot = self.snapshot()
        row = snapshot["ledger"]["modules"][0]["tests"][0]
        identity = row["source_id"]
        row["status"] = "approved_retired"
        row["retirement"] = {"authority": "fixture-explicit-approval", "invariant_review": "fixture only; not persisted"}
        missing = coverage.reconcile_coverage(snapshot)
        wrong = coverage.reconcile_coverage(snapshot, retirement_approvals={identity: "different-approval"})
        approved = coverage.reconcile_coverage(snapshot, retirement_approvals={identity: "fixture-explicit-approval"})
        self.assertEqual(missing["problems"]["accounting"], wrong["problems"]["accounting"])
        self.assertEqual(missing["problems"]["accounting"], approved["problems"]["accounting"] + 1)
        if any(row["status"] in {"pending", "blocked"}
               for module in snapshot["ledger"]["modules"] for row in module["tests"]):
            self.assertFalse(approved["accounting_ready"], "all other pending rows still block")

    def test_malformed_ledger_containers_raise_domain_error_not_key_or_type_error(self):
        for field, value in [("modules", None), ("modules", {}), ("source_counts", []),
                             ("schema_version", True), ("ast_fingerprint_format", None),
                             ("ast_fingerprint_format", "ast-dump")]:
            with self.subTest(field=field, value=value):
                snapshot = self.snapshot()
                snapshot["ledger"][field] = value
                with self.assertRaises(coverage.CoverageError):
                    coverage.reconcile_coverage(snapshot)
        for field, value in [("source_id", None), ("status", []), ("targets", {}),
                             ("parameters", None), ("reason", 7), ("source_ast_sha256", True)]:
            with self.subTest(row_field=field):
                snapshot = self.snapshot()
                self.selected(snapshot)[field] = value
                with self.assertRaises(coverage.CoverageError):
                    coverage.reconcile_coverage(snapshot)

    def test_malformed_evidence_shapes_raise_domain_errors(self):
        snapshot, evidence = self.verified_fixture()
        for value in [[], {"commit": SHA, "targets": []}, {"commit": None, "targets": {}},
                      {"commit": SHA, "targets": {"not-a-reference": {}}},
                      {"commit": SHA, "targets": {TARGET_PATH + "::controlled_parity_case": None}}]:
            with self.subTest(value=value):
                with self.assertRaises(coverage.CoverageError):
                    coverage.reconcile_coverage(snapshot, expected_commit=SHA, execution_evidence=value)
        reference = TARGET_PATH + "::controlled_parity_case"
        evidence["targets"][reference]["passed_platforms"] = "linux"
        with self.assertRaisesRegex(coverage.CoverageError, "array"):
            coverage.reconcile_coverage(snapshot, expected_commit=SHA, execution_evidence=evidence)

    def test_path_escape_and_missing_assertion_metadata_are_rejected(self):
        for field, value in [("path", "tests/../outside.rs"), ("invariant", ""), ("variants", None), ("test", ""),
                             ("harness_test", None), ("harness_test", "unrelated_leaf")]:
            with self.subTest(field=field):
                snapshot = self.snapshot()
                self.selected(snapshot)["targets"][0][field] = value
                with self.assertRaises(coverage.CoverageError):
                    coverage.reconcile_coverage(snapshot)

    def test_snapshot_and_original_ledger_are_not_mutated_by_reconciliation(self):
        snapshot = self.snapshot()
        before = deepcopy(snapshot["ledger"])
        coverage.reconcile_coverage(snapshot)
        self.assertEqual(snapshot["ledger"], before)
        self.assertEqual(self.inputs["ledger"], before)
