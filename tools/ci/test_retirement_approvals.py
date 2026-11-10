# SPDX-License-Identifier: GPL-3.0-or-later
"""Manual approval transport checks; tiny JSON files, no application or CI execution."""

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

import retirement_approvals as approvals
from coverage_contract import BASELINE

SHA = "1" * 40
IDENTITY = "tests/test_example.py::test_import_alias"
AUTHORITY = "fixture-owner-decision"
LEDGER = {"baseline_commit": BASELINE, "modules": [{"tests": [{
    "source_id": IDENTITY, "status": "approved_retired",
    "action": "retire_python_import_contract",
    "retirement": {"authority": AUTHORITY, "invariant_review": "fixture only"},
}]}]}


class RetirementApprovalTests(unittest.TestCase):
    def setUp(self):
        base = Path(__file__).resolve().parents[2] / ".ci-work/approval-tooling-tests"
        base.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=base)
        self.addCleanup(temporary.cleanup)
        self.event = Path(temporary.name) / "event.json"
        self.environment = {
            "GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "KiaroSama/MegaBasterd-CLI",
            "GITHUB_SHA": SHA, "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_ACTOR": "KiaroSama", "GITHUB_TRIGGERING_ACTOR": "KiaroSama",
            "GITHUB_EVENT_PATH": str(self.event),
        }
        self.envelope = {
            "schema_version": 1, "baseline_commit": BASELINE, "commit": SHA,
            "ledger_sha256": approvals.ledger_digest(LEDGER),
            "approvals": {IDENTITY: {
                "action": "retire_python_import_contract", "authority": AUTHORITY,
            }},
        }

    def supplied(self, envelope=None):
        raw = json.dumps(self.envelope if envelope is None else envelope, ensure_ascii=True)
        self.environment[approvals.VARIABLE] = raw
        event = {"sender": {"login": "KiaroSama"},
                 "repository": {"full_name": "KiaroSama/MegaBasterd-CLI"},
                 "inputs": {approvals.INPUT: raw}}
        self.event.write_text(json.dumps(event), encoding="utf-8")
        return event

    def test_actual_manual_event_returns_only_exact_scoped_authorities_without_mutation(self):
        self.supplied()
        before = deepcopy(LEDGER)
        self.assertEqual(approvals.load(LEDGER, SHA, self.environment), {IDENTITY: AUTHORITY})
        self.assertEqual(LEDGER, before)
        reordered = dict(reversed(list(self.envelope.items())))
        self.supplied(reordered)
        self.assertEqual(approvals.load(LEDGER, SHA, self.environment), {IDENTITY: AUTHORITY})
        ledger = dict(reversed(list(LEDGER.items())))
        self.assertEqual(approvals.ledger_digest(ledger), approvals.ledger_digest(LEDGER))

    def test_absent_input_never_invents_approval_even_when_the_ledger_claims_retirement(self):
        self.assertEqual(approvals.load(LEDGER, SHA, {}), {})
        self.assertFalse(self.event.exists())

    def test_missing_wrong_or_non_owner_event_cannot_authorize_candidate_supplied_text(self):
        for key, value in [("GITHUB_ACTIONS", "false"), ("GITHUB_REPOSITORY", "other/repo"),
                           ("GITHUB_SHA", "2" * 40), ("GITHUB_EVENT_NAME", "push"),
                           ("GITHUB_ACTOR", "other"), ("GITHUB_TRIGGERING_ACTOR", "other")]:
            self.supplied()
            with self.subTest(key=key), self.assertRaises(ValueError):
                approvals.load(LEDGER, SHA, {**self.environment, key: value})
        for field in ["sender", "repository", "inputs"]:
            event = self.supplied()
            event[field] = {"login": "other"} if field == "sender" else {}
            self.event.write_text(json.dumps(event), encoding="utf-8")
            with self.subTest(field=field), self.assertRaises(ValueError):
                approvals.load(LEDGER, SHA, self.environment)
        self.supplied()
        self.event.unlink()
        with self.assertRaises(ValueError):
            approvals.load(LEDGER, SHA, self.environment)

    def test_changed_commit_ledger_action_authority_or_identity_refuses_retirement(self):
        variants = []
        for key, value in [("schema_version", True), ("baseline_commit", "0" * 40),
                           ("commit", "2" * 40), ("ledger_sha256", "0" * 64),
                           ("approvals", {}), ("unexpected", "field")]:
            value = {**deepcopy(self.envelope), key: value}
            variants.append(value)
        for key, value in [("action", "port_behavior"), ("authority", "other"),
                           ("authority", ""), ("extra", True)]:
            envelope = deepcopy(self.envelope)
            envelope["approvals"][IDENTITY][key] = value
            variants.append(envelope)
        unknown = deepcopy(self.envelope)
        unknown["approvals"][IDENTITY + "_other"] = unknown["approvals"].pop(IDENTITY)
        variants.append(unknown)
        for index, envelope in enumerate(variants):
            self.supplied(envelope)
            with self.subTest(index=index), self.assertRaises(ValueError):
                approvals.load(LEDGER, SHA, self.environment)
        self.supplied()
        for field, value in [("status", "pending"), ("action", "port_behavior")]:
            ledger = deepcopy(LEDGER)
            ledger["modules"][0]["tests"][0][field] = value
            self.envelope["ledger_sha256"] = approvals.ledger_digest(ledger)
            self.supplied()
            with self.subTest(field=field), self.assertRaises(ValueError):
                approvals.load(ledger, SHA, self.environment)

    def test_duplicate_malformed_oversized_and_event_mismatched_json_is_not_approval(self):
        for raw in ["{", "[]", "null", '{"schema_version":1,"schema_version":1}',
                    '{"schema_version":NaN}', " " * (approvals.MAX_INPUT + 1), "\ud800"]:
            event = self.supplied()
            self.environment[approvals.VARIABLE] = raw
            event["inputs"][approvals.INPUT] = raw
            self.event.write_text(json.dumps(event, ensure_ascii=True), encoding="utf-8")
            with self.subTest(raw_length=len(raw)), self.assertRaises(ValueError):
                approvals.load(LEDGER, SHA, self.environment)
        self.supplied()
        self.environment[approvals.VARIABLE] += " "
        with self.assertRaises(ValueError):
            approvals.load(LEDGER, SHA, self.environment)
        self.supplied()
        self.event.write_bytes(b"\xff")
        with self.assertRaises(ValueError):
            approvals.load(LEDGER, SHA, self.environment)
        self.event.write_bytes(b" " * (approvals.MAX_EVENT + 1))
        with self.assertRaises(ValueError):
            approvals.load(LEDGER, SHA, self.environment)

    def test_workflow_and_runner_transport_input_only_to_parent_accounting(self):
        root = Path(__file__).resolve().parents[2]
        release = (root / ".github/workflows/release.yml").read_text(encoding="utf-8")
        child = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        runner = (root / "tools/ci/run-native.py").read_text(encoding="utf-8")
        self.assertIn("retirement_approvals:", release)
        self.assertIn("retirement_approvals: ${{ inputs.retirement_approvals }}", release)
        self.assertEqual(child.count("MEGABASTERD_CI_RETIREMENT_APPROVALS: ${{ inputs.retirement_approvals }}"), 2)
        for step in ["Bounded native discovery, lint, tests and binary smoke",
                     "Require exact commit, both macOS architectures and complete assertions"]:
            self.assertIn(f"- name: {step}\n        env:\n          {approvals.VARIABLE}:", child)
        self.assertNotIn(f"\n      {approvals.VARIABLE}:", child)
        self.assertIn("retirement_approvals=retirements", runner)
        self.assertIn("evidence.aggregate(inputs, directory, current, retirement_approvals=retirements)", runner)
        environment = runner.split("def environment(", 1)[1].split("def worker_budget(", 1)[0]
        self.assertNotIn(approvals.VARIABLE, environment)
        self.assertNotIn("GITHUB_EVENT_PATH", environment)
