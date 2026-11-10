# SPDX-License-Identifier: GPL-3.0-or-later
"""Source-only OS floors; no baseline imports, native execution or runtime skips."""

from pathlib import Path
import unittest

import platform_scope as scope


class PlatformScopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import os
        root = Path(os.environ.get("MEGABASTERD_CI_BASELINE_ROOT", Path(__file__).resolve().parents[2]))
        cls.helper = (root / "tests/launcher_helpers.py").read_text(encoding="utf-8", errors="strict")

    def test_only_verified_source_markers_and_literal_os_conditions_narrow_the_floor(self):
        text = ('import os\nimport sys\nimport pytest\n'
                'from tests.launcher_helpers import windows_only, posix_only\n'
                '@windows_only\ndef test_windows():\n    pass\n'
                '@posix_only\ndef test_unix():\n    pass\n'
                '@pytest.mark.skipif(os.name != "nt", reason="ACLs")\n'
                'def test_acl():\n    pass\n'
                '@pytest.mark.skipif(sys.platform == "win32", reason="mode bits")\n'
                'def test_modes():\n    pass\n'
                '@pytest.mark.skipif(unavailable(), reason="prerequisite")\n'
                'def test_unknown():\n    pass\n'
                'def test_general():\n    pass\n')
        self.assertEqual(scope.source_platforms(text, self.helper), {
            "test_windows": frozenset({"windows"}), "test_unix": frozenset({"linux", "macos"}),
            "test_acl": frozenset({"windows"}), "test_modes": frozenset({"linux", "macos"}),
            "test_unknown": scope.PLATFORMS, "test_general": scope.PLATFORMS,
        })
        for helper in [None, self.helper + "\n# changed marker implementation\n"]:
            with self.subTest(helper_missing=helper is None), self.assertRaisesRegex(ValueError, "helper"):
                scope.source_platforms(text, helper)

    def test_module_class_alias_and_shadowing_never_invent_a_smaller_os_scope(self):
        text = ('import os as operating\nimport pytest as testing\n'
                'from tests.launcher_helpers import windows_only as win\n'
                'pytestmark = testing.mark.skipif(operating.name == "posix", reason="Windows")\n'
                '@win\nclass TestNative:\n    def test_case(self):\n        pass\n')
        self.assertEqual(scope.source_platforms(text, self.helper),
                         {"TestNative::test_case": frozenset({"windows"})})
        for prefix in ['windows_only = object()\n', 'def windows_only(value):\n    return value\n']:
            text = ('from tests.launcher_helpers import windows_only\n' + prefix +
                    '@windows_only\ndef test_case():\n    pass\n')
            self.assertEqual(scope.source_platforms(text, self.helper), {"test_case": scope.PLATFORMS})
        text = ('import pytest\nclass Custom:\n    name = "nt"\nos = Custom()\n'
                '@pytest.mark.skipif(os.name != "nt", reason="not stdlib")\n'
                'def test_case():\n    pass\n')
        self.assertEqual(scope.source_platforms(text, None), {"test_case": scope.PLATFORMS})
        for replacement in [
            'from tests.launcher_helpers import posix_only as windows_only\n',
            'from .tests.launcher_helpers import windows_only\n',
            'windows_only = lambda value: value\n',
        ]:
            text = ('from tests.launcher_helpers import windows_only\n' + replacement +
                    '@windows_only\ndef test_case():\n    pass\n')
            with self.subTest(replacement=replacement):
                self.assertEqual(scope.source_platforms(text, self.helper), {"test_case": scope.PLATFORMS})

    def test_source_scopes_flow_through_exact_four_target_receipts_without_forgiving_missing_results(self):
        from copy import deepcopy
        import hashlib
        import json
        import os
        import tempfile
        from unittest.mock import patch
        import coverage_contract as coverage
        import native_evidence as evidence

        root = Path(__file__).resolve().parents[2]
        inputs = coverage.load_inputs(root, baseline_root=os.environ.get("MEGABASTERD_CI_BASELINE_ROOT"))
        inputs = deepcopy(inputs)
        wanted_ids = {
            "tests/test_launcher_native_secure_open.py::test_a_created_file_whose_descriptor_did_not_take_is_refused": ["windows"],
            "tests/test_secure_log_invariant.py::test_a_failed_secure_open_never_falls_back_to_an_ordinary_open": ["linux", "macos"],
        }
        target_path = "tests/platform_fixture.rs"
        text = "#[test]\nfn windows_case() {}\n#[test]\nfn unix_case() {}\n"
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        inputs["targets"][target_path] = text
        for module in inputs["ledger"]["modules"]:
            for row in module["tests"]:
                if row["source_id"] in wanted_ids:
                    oses = wanted_ids[row["source_id"]]
                    name = "windows_case" if oses == ["windows"] else "unix_case"
                    row["status"] = "written_unexecuted"
                    row["targets"] = [{"path": target_path, "test": name, "harness_test": name,
                                       "source_sha256": digest, "required_platforms": oses,
                                       "invariant": "synthetic scope transport", "seam": "synthetic only",
                                       "variants": "source-marked OS scope"}]
        report = coverage.reconcile_coverage(inputs)
        self.assertTrue(report["structure_complete"])
        self.assertFalse(report["accounting_ready"], "other pending obligations stay blocking")
        wanted = evidence.references(inputs["ledger"])
        selected = {key: value for key, value in wanted.items() if key.startswith(target_path + "::")}
        self.assertEqual(len(selected), 2)
        commit = "1" * 40
        context = {"repository": evidence.REPOSITORY, "commit": commit, "run_id": "123", "run_attempt": "1"}
        base = root / ".ci-work/platform-scope"
        base.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=base) as temporary:
            directory = Path(temporary)
            for target in evidence.TARGETS:
                name = "windows_case" if "windows" in target else "unix_case"
                receipt = evidence.receipt(context, target, selected, {target_path: {name}})
                reference = target_path + "::" + name
                self.assertEqual(receipt["targets"], {reference: {"source_sha256": digest}})
                with self.assertRaisesRegex(ValueError, "not executed"):
                    evidence.receipt(context, target, selected, {target_path: set()})
                evidence.write_receipt(directory / f"native-evidence-{target}/receipt.json", receipt)
            with patch.object(evidence, "references", return_value=selected), \
                    patch.object(evidence, "reconcile_coverage", wraps=coverage.reconcile_coverage) as reconcile, \
                    patch.object(evidence, "require_report") as gate:
                result = evidence.aggregate(inputs, directory, context)
                self.assertTrue(result["structure_complete"])
                self.assertFalse(result["execution_complete"])
                merged = reconcile.call_args.kwargs["execution_evidence"]
                self.assertEqual(merged["commit"], commit)
                for name, oses in [("windows_case", {"windows"}), ("unix_case", {"linux", "macos"})]:
                    item = merged["targets"][target_path + "::" + name]
                    self.assertEqual(item["source_sha256"], digest)
                    self.assertEqual(set(item["passed_platforms"]), oses)
                    incomplete = deepcopy(merged)
                    incomplete["targets"][target_path + "::" + name]["passed_platforms"] = []
                    refused = coverage.reconcile_coverage(inputs, expected_commit=commit,
                                                          execution_evidence=incomplete)
                    self.assertEqual(refused["problems"]["execution"], result["problems"]["execution"] + 1)
                gate.assert_called_once_with(result, stage="execution")
                gate.reset_mock()
                path = directory / "native-evidence-x86_64-unknown-linux-gnu/receipt.json"
                original = path.read_text(encoding="utf-8")
                for extra in [False, True]:
                    invalid = json.loads(original)
                    if extra:
                        invalid["targets"][target_path + "::windows_case"] = {"source_sha256": digest}
                    else:
                        invalid["targets"].clear()
                    path.write_text(json.dumps(invalid), encoding="utf-8")
                    with self.subTest(extra=extra), self.assertRaisesRegex(ValueError, "coverage"):
                        evidence.aggregate(inputs, directory, context)
                    gate.assert_not_called()
                path.write_text(original, encoding="utf-8")
                missing = directory / "native-evidence-aarch64-apple-darwin/receipt.json"
                missing.unlink()
                with self.assertRaises(ValueError):
                    evidence.aggregate(inputs, directory, context)

    def test_source_floor_cannot_be_narrowed_by_the_candidate_or_a_changed_helper(self):
        from copy import deepcopy
        import coverage_contract as coverage
        import os

        root = Path(__file__).resolve().parents[2]
        inputs = coverage.load_inputs(root, baseline_root=os.environ.get("MEGABASTERD_CI_BASELINE_ROOT"))
        general = next(row for module in inputs["ledger"]["modules"] for row in module["tests"]
                       if row["source_id"] == "tests/test_account_resolution.py::test_explicit_account_wins")
        self.assertEqual(general["status"], "written_unexecuted")
        before = deepcopy(general)
        for narrowed in [["windows"], ["linux", "macos"]]:
            general["targets"][0]["required_platforms"] = narrowed
            with self.subTest(narrowed=narrowed), self.assertRaisesRegex(coverage.CoverageError, "immutable source scope"):
                coverage.reconcile_coverage(inputs)
        general.clear()
        general.update(before)
        for helper in [None, inputs["platform_helper"] + "\n# changed\n"]:
            with self.subTest(helper_missing=helper is None), self.assertRaisesRegex(
                    coverage.CoverageError, "Malformed coverage snapshot/evidence: ValueError"):
                coverage.reconcile_coverage({**inputs, "platform_helper": helper})
        self.assertEqual(general, before)
        self.assertTrue(coverage.reconcile_coverage(inputs)["structure_complete"])

    def test_empty_or_unknown_platform_declarations_are_not_accepted(self):
        for value in [[], ["linux", "linux"], ["unknown"], "windows", [True]]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                scope.platforms(value)
        self.assertEqual(scope.platforms(["linux", "macos"]), frozenset({"linux", "macos"}))
        text = ('from tests.launcher_helpers import windows_only, posix_only\n'
                '@windows_only\n@posix_only\ndef test_case():\n    pass\n')
        with self.assertRaisesRegex(ValueError, "empty"):
            scope.source_platforms(text, self.helper)
