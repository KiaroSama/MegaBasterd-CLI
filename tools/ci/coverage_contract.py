# SPDX-License-Identifier: GPL-3.0-or-later
"""Fail-closed static parity accounting; never imports source modules or runs tests.

CI order: require_coverage(stage="structure"), native tests/diagnostics, then accounting
acceptance, independently verified evidence aggregation, then stage="execution" with expected_commit.
The owning runner supplies logging, resource bounds, baseline tree and trusted CI evidence.
"""

import ast
from collections import Counter
from functools import lru_cache
import hashlib
import json
import math
from pathlib import Path
import re

from platform_scope import HELPER, source_platforms

BASELINE = "c4559ecef08c1fb47cc57669230d2f6013520416"
PLATFORMS = frozenset({"windows", "linux", "macos"})
MAX_TEXT = 8 * 1024 * 1024
MAX_DEFINITIONS = 1416
STATUSES = {"pending", "written_unexecuted", "blocked", "approved_retired", "verified"}
ACTIONS = {"port_behavior", "rewrite_mechanism_keep_invariant", "retire_python_import_contract",
           "retire_python_toolchain_mechanism", "retire_old_data_reader_contract"}
SOURCE = re.compile(r"tests/test_[A-Za-z0-9_]+\.py")
TARGET = re.compile(r"(?:src|tests)/[A-Za-z0-9_./-]+\.rs")
TEST = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class CoverageError(ValueError):
    """Malformed input, incomplete accounting or absent execution evidence."""


def _object(value, label):
    if not isinstance(value, dict):
        raise CoverageError(label + " must be an object")
    return value


def _list(value, label, bound=MAX_DEFINITIONS):
    if not isinstance(value, list) or len(value) > bound:
        raise CoverageError(label + " must be a bounded array")
    return value


def _text(value, label):
    if not isinstance(value, str) or not value.strip() or len(value) > 4096:
        raise CoverageError(label + " must be nonempty bounded text")
    return value


def _integer(value, label, minimum=0):
    if type(value) is not int or value < minimum:
        raise CoverageError(label + " must be an integer")
    return value


def _digest(value, label):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise CoverageError(label + " must be a SHA256 digest")
    return value


def _commit(value, label):
    if not isinstance(value, str) or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value):
        raise CoverageError(label + " must be an exact commit SHA")
    return value


def _relative(value, pattern, label):
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise CoverageError(label + " is not a canonical project path")
    if any(part in {"", ".", ".."} for part in value.split("/")):
        raise CoverageError(label + " contains unsafe components")
    return value


def _platforms(value, label, *, required=False):
    values = _list(value, label, 3)
    if any(not isinstance(item, str) for item in values):
        raise CoverageError(label + " must contain platform names")
    result = set(values)
    if len(result) != len(values) or not result <= PLATFORMS:
        raise CoverageError(label + " has duplicate/unknown platforms")
    if required and not result:
        raise CoverageError(label + " must include native platforms")
    return result


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CoverageError("Duplicate JSON ledger key")
        result[key] = value
    return result


def _read(path):
    if path.is_symlink() or path.stat().st_size > MAX_TEXT:
        raise CoverageError("Coverage input is linked or exceeds its size bound")
    return path.read_text(encoding="utf-8", errors="strict")


def _path(root, relative):
    path = root / relative
    if not path.resolve().is_relative_to(root):
        raise CoverageError("Coverage input resolves outside its root")
    return path


def _sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _ast_sha(node):
    # ast.dump is a debugging format whose empty-field defaults changed in Python3.13.
    def canonical(value):
        if isinstance(value, ast.AST):
            fields = {name: canonical(item) for name, item in ast.iter_fields(value)
                      if not (name == "type_params" and item == [])}
            return [type(value).__name__, dict(sorted(fields.items()))]
        if isinstance(value, list):
            return [canonical(item) for item in value]
        return [type(value).__name__, repr(value)]
    return _sha(json.dumps(canonical(node), ensure_ascii=True, sort_keys=True, separators=(",", ":")))


def _dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    return _dotted(node.value) + "." + node.attr if isinstance(node, ast.Attribute) else ""


def _parameters(function):
    result = []
    for decorator in function.decorator_list:
        if not isinstance(decorator, ast.Call) or not _dotted(decorator.func).endswith(".parametrize"):
            continue
        keys = {item.arg: item.value for item in decorator.keywords if item.arg}
        names = keys.get("argnames", decorator.args[0] if decorator.args else None)
        values = keys.get("argvalues", decorator.args[1] if len(decorator.args) > 1 else None)
        ids = keys.get("ids")
        literal_ids = None
        if isinstance(ids, (ast.Tuple, ast.List)) and all(isinstance(v, ast.Constant) and
                isinstance(v.value, (str, int, float, type(None))) for v in ids.elts):
            literal_ids = [v.value for v in ids.elts]
        result.append({"decorator_sha256": _ast_sha(decorator), "line": decorator.lineno,
                       "argnames": names.value if isinstance(names, ast.Constant)
                       and isinstance(names.value, str) else None,
                       "static_count": len(values.elts) if isinstance(values, (ast.Tuple, ast.List)) else None,
                       "ids": literal_ids, "runtime_cases": None})
    return result


def _functions(text):
    result = {}

    def visit(body, classes=()):
        for item in body:
            if isinstance(item, ast.ClassDef):
                visit(item.body, (*classes, item.name))
            elif isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name.startswith("test_"):
                name = "::".join((*classes, item.name))
                if name in result:
                    raise CoverageError("Duplicate static Python source test identity")
                result[name] = item
    visit(ast.parse(text, mode="exec").body)
    return result


@lru_cache(maxsize=32)
def _rust_tests(text):
    # Conservative reference check, not Rust parsing or native harness discovery proof.
    return Counter(re.findall(
        r"(?m)^\s*#\[test\]\s*(?:#\[[^\]\n]*\]\s*)*(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", text))


@lru_cache(maxsize=192)
def _source_facts(text):
    return {name: (_ast_sha(function), _parameters(function))
            for name, function in _functions(text).items()}


def _validate_parameters(value):
    for parameter in _list(value, "parameters", 32):
        p = _object(parameter, "parameter")
        _digest(p.get("decorator_sha256"), "parameter decorator")
        _integer(p.get("line"), "parameter line", 1)
        if p.get("argnames") is not None:
            _text(p["argnames"], "parameter names")
        if p.get("static_count") is not None:
            _integer(p["static_count"], "static parameter count")
        if p.get("runtime_cases") is not None or "runtime_cases" not in p:
            raise CoverageError("Parameter runtime cases must remain explicitly unknown")
        if p.get("ids") is not None:
            for item in _list(p["ids"], "parameter IDs"):
                if item is not None and type(item) not in {str, int, float}:
                    raise CoverageError("Parameter ID is not a scalar")
                if isinstance(item, float) and not math.isfinite(item):
                    raise CoverageError("Parameter ID is not finite")


def _validate_ledger(data):
    data = _object(data, "ledger")
    if type(data.get("schema_version")) is not int or data["schema_version"] != 1 or data.get("baseline_commit") != BASELINE:
        raise CoverageError("Coverage ledger schema/baseline differs")
    if data.get("ast_fingerprint_format") != "python-structural-json-v1":
        raise CoverageError("Unsupported cross-version AST fingerprint format")
    counts = _object(data.get("source_counts"), "source counts")
    for key, expected in [("modules", 164), ("definitions", 1416),
                          ("parameterized_definitions", 117), ("parameter_decorators", 118)]:
        if _integer(counts.get(key), "source count " + key) != expected:
            raise CoverageError("Baseline static counts differ")
    if counts.get("runtime_cases") is not None or "runtime_cases" not in counts:
        raise CoverageError("Runtime case count must remain explicitly unknown")
    modules = _list(data.get("modules"), "modules", 164)
    if len(modules) != 164:
        raise CoverageError("Baseline module accounting is incomplete")
    paths, identities = set(), set()
    for module in modules:
        m = _object(module, "module")
        path = _relative(m.get("source"), SOURCE, "source module")
        if path in paths:
            raise CoverageError("Duplicate baseline module")
        paths.add(path)
        _digest(m.get("source_sha256"), "source module digest")
        for row in _list(m.get("tests"), "source tests"):
            row = _object(row, "source row")
            identity = _text(row.get("source_id"), "source identity")
            name = identity.removeprefix(path + "::")
            if name == identity or not all(TEST.fullmatch(part) for part in name.split("::")) or identity in identities:
                raise CoverageError("Duplicate or mismatched source identity")
            identities.add(identity)
            _digest(row.get("source_ast_sha256"), "source AST digest")
            _validate_parameters(row.get("parameters"))
            if (not isinstance(row.get("status"), str) or row["status"] not in STATUSES
                    or not isinstance(row.get("action"), str) or row["action"] not in ACTIONS):
                raise CoverageError("Unknown coverage disposition")
            _text(row.get("reason"), "disposition reason")
            mapping = _list(row.get("targets"), "targets", 64)
            if row["status"] in {"written_unexecuted", "verified"} and not mapping:
                raise CoverageError("Written/verified mapping lacks a specific target")
            refs = set()
            for target in mapping:
                t = _object(target, "target")
                p = _relative(t.get("path"), TARGET, "target path")
                test = _text(t.get("test"), "target test")
                if not TEST.fullmatch(test) or (p, test) in refs:
                    raise CoverageError("Invalid or duplicate target test reference")
                harness = _text(t.get("harness_test"), "target harness identity")
                if (not all(TEST.fullmatch(part) for part in harness.split("::"))
                        or harness.split("::")[-1] != test):
                    raise CoverageError("Target harness identity differs from the mapped test")
                refs.add((p, test))
                for key in ["invariant", "seam", "variants"]:
                    _text(t.get(key), "target " + key)
                _digest(t.get("source_sha256"), "target digest")
                _platforms(t.get("required_platforms"), "required platforms", required=True)
            if row["status"] == "approved_retired":
                approval = _object(row.get("retirement"), "retirement")
                _text(approval.get("authority"), "retirement authority")
                _text(approval.get("invariant_review"), "retirement assertion review")
    if len(identities) != MAX_DEFINITIONS:
        raise CoverageError("Source definition total differs from1416")
    return data


def load_inputs(root, *, baseline_root=None):
    """Read/validate the full ledger and bounded texts once; suitable for a test snapshot.

    Does not import target modules, refresh hashes or mark any row covered. Returned snapshot
    is caller-owned; reconcile_coverage is pure and never mutates it.
    """
    root = Path(root).resolve()
    baseline = root if baseline_root is None else Path(baseline_root).resolve()
    try:
        data = _validate_ledger(json.loads(_read(root / "tests/fixtures/contract_coverage.json"), object_pairs_hook=_pairs))
        sources = {path.relative_to(baseline).as_posix(): _read(path)
                   for path in (baseline / "tests").glob("test_*.py")}
        target_paths = {target["path"] for module in data["modules"] for row in module["tests"] for target in row["targets"]}
        targets = {}
        for relative in target_paths:
            path = _path(root, relative)
            if path.is_file():
                targets[relative] = _read(path)
        return {"ledger": data, "sources": sources, "targets": targets,
                "platform_helper": _read(_path(baseline, HELPER))}
    except CoverageError:
        raise
    except (OSError, UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise CoverageError("Coverage inputs unreadable or malformed: " + type(error).__name__) from None


def _evidence(value, expected_commit):
    if expected_commit is not None:
        _commit(expected_commit, "expected current commit")
    if value is None:
        return {}
    value = _object(value, "execution evidence")
    _commit(value.get("commit"), "evidence commit")
    targets = _object(value.get("targets"), "evidence targets")
    if len(targets) > MAX_DEFINITIONS * 64:
        raise CoverageError("Execution evidence exceeds target bound")
    for reference, result in targets.items():
        if not isinstance(reference, str) or "::" not in reference:
            raise CoverageError("Malformed evidence target reference")
        path, test = reference.rsplit("::", 1)
        _relative(path, TARGET, "evidence path")
        if not TEST.fullmatch(test):
            raise CoverageError("Malformed evidence test name")
        result = _object(result, "evidence target result")
        _digest(result.get("source_sha256"), "evidence target digest")
        _platforms(result.get("passed_platforms"), "passed platforms")
    return value


def reconcile_coverage(inputs, *, expected_commit=None, execution_evidence=None, retirement_approvals=None):
    """Pure static accounting over a load_inputs snapshot; all shape errors are CoverageError.

    Evidence must be independently authenticated by the caller. Its commit MUST equal the
    caller's expected current commit; a syntactically valid SHA or self-written approval is
    never sufficient. Every source-applicable OS is mandatory; all four native receipts
    remain required by the caller, including both macOS architectures.
    Fresh external results can verify written_unexecuted rows without editing the committed ledger
    after CI; this avoids invalidating the exact SHA by rewriting status labels post-execution.
    """
    try:
        snapshot = _object(inputs, "coverage snapshot")
        data = _validate_ledger(snapshot.get("ledger"))
        sources = _object(snapshot.get("sources"), "source snapshot")
        texts = _object(snapshot.get("targets"), "target snapshot")
        for group in [sources, texts]:
            for path, text in group.items():
                if not isinstance(path, str) or not isinstance(text, str) or len(text.encode("utf-8")) > MAX_TEXT:
                    raise CoverageError("Source/target snapshot must contain bounded text")
        native = _evidence(execution_evidence, expected_commit)
        approvals = {} if retirement_approvals is None else _object(retirement_approvals, "retirement approvals")
        for identity, authority in approvals.items():
            _text(identity, "retirement source identity")
            _text(authority, "independent retirement authority")
        structural, accounting, execution = [], [], []
        statuses = Counter()
        named_modules = set()
        parameterized = decorators = 0
        rust = {path: (_sha(text), _rust_tests(text)) for path, text in texts.items()}
        for module in data["modules"]:
            path = module["source"]
            named_modules.add(path)
            text = sources.get(path)
            actual, scopes = {}, {}
            if text is None:
                structural.append((path, "baseline source is missing"))
            else:
                if _sha(text) != module["source_sha256"]:
                    structural.append((path, "baseline module changed; re-review assertions"))
                actual = _source_facts(text)
                scopes = source_platforms(text, snapshot.get("platform_helper"))
            names = set()
            for row in module["tests"]:
                identity, status = row["source_id"], row["status"]
                name = identity[len(path) + 2:]
                names.add(name)
                statuses[status] += 1
                facts = actual.get(name)
                if facts is None:
                    structural.append((identity, "source definition is missing"))
                else:
                    source_digest, params = facts
                    if source_digest != row["source_ast_sha256"]:
                        structural.append((identity, "source assertions changed"))
                    parameterized += bool(params)
                    decorators += len(params)
                    if params != row["parameters"]:
                        structural.append((identity, "source parameter decorators differ"))
                for target in row["targets"]:
                    required = set(target["required_platforms"])
                    if not scopes.get(name, PLATFORMS) <= required:
                        raise CoverageError("Target platforms narrow the immutable source scope")
                    ref = target["path"] + "::" + target["test"]
                    digest, definitions = rust.get(target["path"], (None, Counter()))
                    if definitions[target["test"]] != 1:
                        structural.append((identity, "undefined or ambiguous target " + ref))
                    if digest != target["source_sha256"]:
                        structural.append((identity, "target changed; assertion mapping needs re-review"))
                    if status in {"written_unexecuted", "verified"}:
                        result = native.get("targets", {}).get(ref, {})
                        if expected_commit is None or native.get("commit") != expected_commit:
                            execution.append((identity, "native evidence is not bound to expected current commit"))
                        if result.get("source_sha256") != digest or not required <= set(result.get("passed_platforms", [])):
                            execution.append((identity, "required native platform results/digest are missing"))
                if status in {"pending", "blocked"}:
                    accounting.append((identity, status + ": " + row["reason"]))
                elif status == "approved_retired":
                    if approvals.get(identity) != row["retirement"]["authority"]:
                        accounting.append((identity, "retirement lacks independently supplied scoped approval"))
            if names != set(actual):
                structural.append((path, "omitted or extra source definitions"))
        if named_modules != set(sources):
            structural.append(("ledger", "baseline module paths omitted or added"))
        if parameterized != 117 or decorators != 118:
            structural.append(("ledger", "source parameterized-definition/decorator count differs"))
        all_problems = structural + accounting + execution
        return {"definitions": sum(statuses.values()), "modules": len(named_modules),
                "parameterized_definitions": parameterized, "parameter_decorators": decorators,
                "runtime_cases": None, "statuses": dict(sorted(statuses.items())),
                "structure_complete": not structural,
                "accounting_ready": not structural and not accounting,
                "execution_complete": not all_problems, "complete": not all_problems,
                "problems": {"structure": len(structural), "accounting": len(accounting), "execution": len(execution)},
                "examples": [{"source_id": identity, "reason": reason} for identity, reason in all_problems[:12]]}
    except CoverageError:
        raise
    except (KeyError, TypeError, ValueError, UnicodeError, SyntaxError, RecursionError) as error:
        raise CoverageError("Malformed coverage snapshot/evidence: " + type(error).__name__) from None


def audit_coverage(root, *, baseline_root=None, expected_commit=None, execution_evidence=None, retirement_approvals=None):
    """Fresh-disk audit; expected_commit must come from the runner's independently checked SHA."""
    return reconcile_coverage(load_inputs(root, baseline_root=baseline_root), expected_commit=expected_commit,
                              execution_evidence=execution_evidence, retirement_approvals=retirement_approvals)


def require_report(report, *, stage):
    """Apply one explicit gate to a report without rerunning static inspection."""
    keys = {"structure": "structure_complete", "accounting": "accounting_ready", "execution": "execution_complete"}
    if not isinstance(stage, str) or stage not in keys:
        raise CoverageError("Unknown coverage gate stage")
    if not isinstance(report, dict):
        raise CoverageError("Coverage report must be an object")
    required = ["structure_complete"]
    if stage in {"accounting", "execution"}:
        required.append("accounting_ready")
    if stage == "execution":
        required.append("execution_complete")
    if any(report.get(key) is not True for key in required):
        try:
            message = json.dumps(report, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError, RecursionError):
            raise CoverageError("Malformed coverage report") from None
        raise CoverageError(message)
    return report


def require_coverage(root, *, stage="execution", baseline_root=None, expected_commit=None,
                     execution_evidence=None, retirement_approvals=None):
    """Structure before tests; accounting before parity acceptance; execution before closure."""
    report = audit_coverage(root, baseline_root=baseline_root, expected_commit=expected_commit,
                            execution_evidence=execution_evidence, retirement_approvals=retirement_approvals)
    return require_report(report, stage=stage)
