# SPDX-License-Identifier: GPL-3.0-or-later
"""Exact native harness discovery/results and same-run receipt reconciliation.

The caller owns processes, logging, time/resource bounds and authenticated artifact transport.
This module never executes code, imports application modules or treats JSON as its own authority.
"""

import json
from pathlib import Path
import re

from coverage_contract import reconcile_coverage, require_report
from platform_scope import platforms

TARGETS = frozenset({"x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc",
                     "x86_64-apple-darwin", "aarch64-apple-darwin"})
REPOSITORY = "KiaroSama/MegaBasterd-CLI"
NAME = r"[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*"
MAX_BYTES = 32 * 1024 * 1024
MAX_TESTS = 100_000


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("Duplicate native evidence key")
        result[key] = value
    return result


def decode(data):
    if not isinstance(data, bytes) or len(data) > MAX_BYTES:
        raise ValueError("Native evidence text exceeds its bound")
    return data.decode("utf-8", errors="strict").replace("\r\n", "\n")


def identity(environment, commit):
    if (environment.get("GITHUB_ACTIONS") != "true"
            or environment.get("GITHUB_REPOSITORY") != REPOSITORY
            or not re.fullmatch(r"[0-9a-f]{40}", commit)
            or environment.get("GITHUB_SHA") != commit):
        raise ValueError("Native evidence requires the exact owning GitHub commit")
    value = {"repository": REPOSITORY, "commit": commit}
    for key, variable in [("run_id", "GITHUB_RUN_ID"), ("run_attempt", "GITHUB_RUN_ATTEMPT")]:
        number = environment.get(variable, "")
        if not re.fullmatch(r"[1-9][0-9]{0,19}", number):
            raise ValueError("Native evidence requires a valid workflow run identity")
        value[key] = number
    return value


def artifacts(data, metadata, root, output):
    root, output = Path(root).resolve(), Path(output).resolve()
    package = next(p for p in metadata["packages"]
                   if Path(p["manifest_path"]).resolve() == root / "Cargo.toml")
    expected = {}
    for target in package["targets"]:
        if "custom-build" in target["kind"]:
            continue
        if target["kind"] not in [["lib"], ["bin"], ["test"]] or target["test"] is not True:
            raise ValueError("Native harness kind requires an explicit runner contract")
        key = (target["name"], tuple(target["kind"]), str(Path(target["src_path"]).resolve()))
        if key in expected:
            raise ValueError("Duplicate native harness metadata")
        expected[key] = target
    found, finished = {}, False
    for line in decode(data).splitlines():
        if not line.strip():
            continue
        message = json.loads(line, object_pairs_hook=pairs)
        if not isinstance(message, dict) or finished:
            raise ValueError("Malformed native compilation stream")
        if message.get("reason") == "build-finished":
            if message.get("success") is not True:
                raise ValueError("Native test compilation did not succeed")
            finished = True
        if (message.get("reason") != "compiler-artifact"
                or message.get("package_id") != package["id"]
                or message.get("profile", {}).get("test") is not True):
            continue
        target = message["target"]
        key = (target["name"], tuple(target["kind"]), str(Path(target["src_path"]).resolve()))
        executable = message.get("executable")
        if key not in expected or key in found or not isinstance(executable, str):
            raise ValueError("Missing, duplicate or unexpected native harness artifact")
        path = Path(executable)
        if (not path.is_absolute() or path.is_symlink() or not path.is_file()
                or not path.resolve().is_relative_to(output)):
            raise ValueError("Native harness executable escapes its build root")
        found[key] = {"name": target["name"], "kind": target["kind"],
                      "source": Path(target["src_path"]).resolve().relative_to(root).as_posix(),
                      "executable": path.resolve()}
    if not finished or not expected or set(found) != set(expected):
        raise ValueError("Native harness artifact inventory is incomplete")
    if len({value["executable"] for value in found.values()}) != len(found):
        raise ValueError("Native harness executables are aliased")
    return [found[key] for key in sorted(found)]


def discovery(data):
    names, summary = set(), None
    for line in decode(data).splitlines():
        if not line.strip():
            continue
        test = re.fullmatch(rf"({NAME}): test", line)
        count = re.fullmatch(r"([0-9]+) tests?, ([0-9]+) benchmarks?", line)
        if test and summary is None and test[1] not in names and len(names) < MAX_TESTS:
            names.add(test[1])
        elif count and summary is None:
            summary = tuple(map(int, count.groups()))
        else:
            raise ValueError("Malformed or duplicate native test discovery")
    if summary != (len(names), 0):
        raise ValueError("Native discovery count or benchmark scope differs")
    return names


def results(data, discovered):
    # Pinned stable libtest --logfile is independent of application stdout/stderr.
    observed = {}
    for line in decode(data).splitlines():
        test = re.fullmatch(rf"(ok|failed|ignored) ({NAME})", line)
        if not test or test[2] not in discovered or test[2] in observed:
            raise ValueError("Unexpected, malformed or duplicate native test result")
        observed[test[2]] = test[1]
    if set(observed) != discovered or any(state != "ok" for state in observed.values()):
        raise ValueError("Native results are failed, filtered, ignored or incomplete")
    return discovered


def result_file(path, discovered):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError("Native result file is missing, linked or exceeds its size bound")
    with path.open("rb") as stream:
        return results(stream.read(MAX_BYTES + 1), discovered)


def references(ledger):
    wanted = {}
    for module in ledger["modules"]:
        for row in module["tests"]:
            for target in row["targets"]:
                path, test = target["path"], target["test"]
                full = target.get("harness_test")
                if not isinstance(full, str) or not re.fullmatch(NAME, full) or full.split("::")[-1] != test:
                    raise ValueError("Mapped native assertion lacks an exact harness identity")
                suite = path if path.startswith("tests/") else "src/lib.rs"
                if suite.startswith("tests/") and (suite.count("/") != 1 or full != test):
                    raise ValueError("Integration assertion needs an explicit harness root")
                key = path + "::" + test
                value = {"suite": suite, "harness_test": full, "source_sha256": target["source_sha256"]}
                required = platforms(target.get("required_platforms"))
                if key in wanted:
                    previous = wanted[key]
                    if any(previous[field] != item for field, item in value.items()):
                        raise ValueError("Mapped native assertion has conflicting identities")
                    required |= platforms(previous["required_platforms"])
                wanted[key] = {**value, "required_platforms": sorted(required)}
    return wanted


def applicable_references(wanted, target):
    if target not in TARGETS:
        raise ValueError("Unsupported native receipt target")
    platform = "windows" if "windows" in target else "macos" if "apple" in target else "linux"
    return {reference: value for reference, value in wanted.items()
            if platform in platforms(value.get("required_platforms"))}


def passed_references(wanted, suites, *, target):
    found = {}
    for reference, assertion in applicable_references(wanted, target).items():
        if assertion["harness_test"] not in suites.get(assertion["suite"], set()):
            raise ValueError("Mapped assertion was not executed in its exact native harness")
        found[reference] = {"source_sha256": assertion["source_sha256"]}
    return found


def receipt(context, target, wanted, suites):
    return {"schema_version": 1, **context, "target": target, "suite_count": len(suites),
            "test_count": sum(map(len, suites.values())),
            "targets": passed_references(wanted, suites, target=target)}


def aggregate(inputs, directory, context, *, retirement_approvals=None):
    wanted = references(inputs["ledger"])
    directory = Path(directory).resolve()
    expected = {f"native-evidence-{target}" for target in TARGETS}
    actual = []
    for path in directory.iterdir():
        if len(actual) == len(expected):
            raise ValueError("Native receipt artifact count exceeds its bound")
        actual.append(path)
    if len(actual) != len(expected) or {path.name for path in actual} != expected:
        raise ValueError("Native receipt artifact set differs from the four required targets")
    for artifact in actual:
        if (artifact.is_symlink() or not artifact.is_dir() or artifact.resolve().parent != directory
                or list(artifact.iterdir()) != [artifact / "receipt.json"]):
            raise ValueError("Native receipt artifact contains unexpected paths")
    merged = {"commit": context["commit"], "targets": {}}
    for target in sorted(TARGETS):
        path = directory / f"native-evidence-{target}" / "receipt.json"
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BYTES:
            raise ValueError("Native receipt file is linked or exceeds its size bound")
        with path.open("rb") as stream:
            data = stream.read(MAX_BYTES + 1)
        report = json.loads(decode(data), object_pairs_hook=pairs)
        applicable = applicable_references(wanted, target)
        if (not isinstance(report, dict) or type(report.get("schema_version")) is not int
                or report["schema_version"] != 1
                or report.get("target") != target
                or any(report.get(key) != value for key, value in context.items())
                or type(report.get("suite_count")) is not int or report["suite_count"] < 1
                or type(report.get("test_count")) is not int or report["test_count"] < 1
                or not isinstance(report.get("targets"), dict) or set(report["targets"]) != set(applicable)):
            raise ValueError("Native receipt has the wrong commit, run, target or coverage")
        platform = "windows" if "windows" in target else "macos" if "apple" in target else "linux"
        for reference, item in report["targets"].items():
            if not isinstance(item, dict) or item != {"source_sha256": wanted[reference]["source_sha256"]}:
                raise ValueError("Native receipt source digest differs")
            result = merged["targets"].setdefault(reference, {**item, "passed_platforms": []})
            if platform not in result["passed_platforms"]:
                result["passed_platforms"].append(platform)
    result = reconcile_coverage(inputs, expected_commit=context["commit"], execution_evidence=merged,
                                retirement_approvals=retirement_approvals)
    require_report(result, stage="execution")
    return result


def write_receipt(path, report):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
