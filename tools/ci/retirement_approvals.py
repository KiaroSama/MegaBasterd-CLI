# SPDX-License-Identifier: GPL-3.0-or-later
"""Validate separately supplied manual decisions; never create retirement authority.

The owning runner authenticates its GitHub context before calling this module. The
workflow event is a runner-provided trust input, not a candidate checkout file.
"""

import hashlib
import json
from pathlib import Path

from coverage_contract import BASELINE
from native_evidence import REPOSITORY, pairs

INPUT = "retirement_approvals"
VARIABLE = "MEGABASTERD_CI_RETIREMENT_APPROVALS"
MAX_INPUT = 65_535
MAX_EVENT = 1024 * 1024
ACTIONS = frozenset({"retire_python_import_contract", "retire_python_toolchain_mechanism",
                     "retire_old_data_reader_contract"})


def ledger_digest(ledger):
    """Bind decisions to canonical ledger contents, independent of checkout CRLF."""
    return hashlib.sha256(json.dumps(ledger, ensure_ascii=True, sort_keys=True,
                                    separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()


def _invalid_constant(value):
    raise ValueError("Manual approval JSON contains a nonfinite number")


def _decode(text):
    return json.loads(text, object_pairs_hook=pairs, parse_constant=_invalid_constant)


def load(ledger, commit, environment):
    """Return exact per-ID authorities or refuse; an absent input grants nothing.

    This cannot prove consent against an attacker controlling the runner/workflow.
    A manual dispatch is data supplied by its authenticated owner, not a signature.
    """
    raw = environment.get(VARIABLE, "")
    if raw == "":
        return {}
    try:
        if not isinstance(raw, str) or len(raw.encode("utf-8", errors="strict")) > MAX_INPUT:
            raise ValueError("Manual approval input exceeds its bound")
        owner = REPOSITORY.split("/", 1)[0]
        expected = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": REPOSITORY,
                    "GITHUB_SHA": commit, "GITHUB_EVENT_NAME": "workflow_dispatch",
                    "GITHUB_ACTOR": owner, "GITHUB_TRIGGERING_ACTOR": owner}
        if any(environment.get(key) != value for key, value in expected.items()):
            raise ValueError("Manual approval requires the owning repository and owner dispatch")
        path = Path(environment["GITHUB_EVENT_PATH"])
        if not path.is_absolute() or path.is_symlink() or not path.is_file():
            raise ValueError("Manual approval event file is not a regular absolute file")
        with path.open("rb") as stream:
            data = stream.read(MAX_EVENT + 1)
        if len(data) > MAX_EVENT:
            raise ValueError("Manual approval event exceeds its bound")
        event = _decode(data.decode("utf-8", errors="strict"))
        if (not isinstance(event, dict) or event.get("sender", {}).get("login") != owner
                or event.get("repository", {}).get("full_name") != REPOSITORY
                or event.get("inputs", {}).get(INPUT) != raw):
            raise ValueError("Manual approval input differs from the owner event")
        value = _decode(raw)
        fields = {"schema_version", "baseline_commit", "commit", "ledger_sha256", "approvals"}
        if (not isinstance(value, dict) or set(value) != fields
                or type(value["schema_version"]) is not int or value["schema_version"] != 1
                or value["baseline_commit"] != BASELINE or ledger["baseline_commit"] != BASELINE
                or value["commit"] != commit or value["ledger_sha256"] != ledger_digest(ledger)
                or not isinstance(value["approvals"], dict) or not value["approvals"]):
            raise ValueError("Manual approval schema or immutable source identity differs")
        retired = {row["source_id"]: row for module in ledger["modules"] for row in module["tests"]
                   if row["status"] == "approved_retired"}
        if set(value["approvals"]) != set(retired):
            raise ValueError("Manual approval identities differ from the reviewed retirement set")
        result = {}
        for identity, decision in value["approvals"].items():
            row = retired[identity]
            if (not isinstance(decision, dict) or set(decision) != {"action", "authority"}
                    or row["action"] not in ACTIONS or decision["action"] != row["action"]
                    or not isinstance(decision["authority"], str)
                    or not decision["authority"].strip() or len(decision["authority"]) > 4096
                    or decision["authority"] != row["retirement"]["authority"]):
                raise ValueError("Manual approval action or authority differs from its reviewed row")
            result[identity] = decision["authority"]
        return result
    except (OSError, UnicodeError, KeyError, TypeError, AttributeError, RecursionError):
        raise ValueError("Manual approval input or event is unreadable or malformed") from None
