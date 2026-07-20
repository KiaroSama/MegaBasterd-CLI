"""Every public name the 1.x surface ever had must still import from its module.

`test_api_compatibility_1x.py` lists restorations by hand. That list has now
been wrong twice: a cleanup pass deleted fourteen public names, they were
restored, and the very next pass deleted six more with the suite still green. A
hand-maintained list only catches what someone remembered to add to it, so it
cannot catch the next one.

This checks the whole surface instead. `tests/data/public_api_1x.json` is a
snapshot of every module-level public name at the initial commit - the earliest
recorded API, since the repository carries no 1.x tag - and the rule is the one
the sibling module already states: a name without a leading underscore was
importable, and 1.x is not a boundary at which importable API may disappear.

The snapshot is committed data rather than something derived from git at run
time. That was the first attempt and it broke every CI job: `actions/checkout`
makes a shallow clone, so the initial commit is not in the object store there.
Committed data is also the more honest shape - the baseline is frozen, so
re-deriving it on every run implies a freedom it does not have, and this way
the check needs no history, no network, and no repository at all.

Regenerate only when you mean to move the baseline, from a full clone:

    python tests/test_public_api_surface.py

Deliberate removals do NOT belong in a regenerated snapshot. They go in
`INTENTIONALLY_REMOVED` with a reason, so dropping public API is a visible line
in a diff rather than a silent side effect of a cleanup pass. Regenerating to
quiet a failure erases the very thing this file exists to notice.

Scope limit worth knowing: this sees module-level functions, classes and
UPPERCASE constants. It does not see class attributes, so a lost dataclass
field like `Menu.subtitle` needs its own test - there is one in the sibling
module.
"""

from __future__ import annotations

import ast
import importlib
import json
from pathlib import Path

import pytest

from tests.launcher_helpers import REPO

SNAPSHOT = Path(__file__).parent / "data" / "public_api_1x.json"

# The baseline is frozen, so its size is a constant, and an exact count is the
# strongest guard against a truncated or half-written snapshot making every
# assertion below vacuously pass. If you deliberately move the baseline or
# change what counts as public, these change with it - deliberately.
BASELINE_MODULES = 31
BASELINE_NAMES = 185

# name -> why it is allowed to be gone. Removing public API is a decision;
# this is where the decision gets written down.
INTENTIONALLY_REMOVED: dict[str, str] = {}


def _public_names(source: str, filename: str) -> set[str]:
    """Module-level functions, classes and UPPERCASE constants."""
    names = set()
    for node in ast.parse(source, filename).body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if not node.name.startswith("_"):
                names.add(node.name)
        elif isinstance(node, ast.Assign):
            # Constants only: a module-level lowercase binding is usually a
            # singleton or an alias, not declared API.
            for target in node.targets:
                if (
                    isinstance(target, ast.Name)
                    and not target.id.startswith("_")
                    and target.id.isupper()
                ):
                    names.add(target.id)
    return names


@pytest.fixture(scope="session")
def baseline() -> dict[str, list[str]]:
    assert SNAPSHOT.is_file(), f"the baseline snapshot is missing: {SNAPSHOT}"
    loaded = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    assert len(loaded) == BASELINE_MODULES, f"snapshot holds {len(loaded)} modules, not a baseline"
    total = sum(len(v) for v in loaded.values())
    assert total == BASELINE_NAMES, f"snapshot holds {total} names, not a baseline"
    return loaded


def test_every_baseline_public_name_still_imports(baseline):
    """Importable from the SAME module - moving a name breaks `from x import y` too.

    A module split may relocate an implementation freely; it just has to leave
    the old name resolvable, by re-export or by PEP 562 `__getattr__`.
    """
    missing = []
    for module, names in sorted(baseline.items()):
        try:
            loaded = importlib.import_module(module)
        except ModuleNotFoundError:
            # The module itself is gone; every name it held is a removal.
            missing += [f"{module}.{n} (module removed)" for n in sorted(names)]
            continue
        for name in sorted(names):
            if f"{module}.{name}" in INTENTIONALLY_REMOVED:
                continue
            if not hasattr(loaded, name):
                missing.append(f"{module}.{name}")

    assert not missing, (
        "public names from the 1.x surface no longer import:\n  "
        + "\n  ".join(missing)
        + "\n\nRestore them, or add each to INTENTIONALLY_REMOVED with a reason."
        + "\nDo NOT regenerate the snapshot to make this pass."
    )


def test_the_allowlist_does_not_name_something_that_still_exists():
    """A stale entry silently un-guards a name that came back."""
    for dotted in INTENTIONALLY_REMOVED:
        module, _, name = dotted.rpartition(".")
        try:
            loaded = importlib.import_module(module)
        except ModuleNotFoundError:
            continue
        assert not hasattr(loaded, name), f"{dotted} exists again; drop it from the allowlist"


if __name__ == "__main__":  # regeneration, see the module docstring
    import subprocess
    import sys

    BASELINE_REV = "5d8f864"  # initial commit
    listing = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", BASELINE_REV],
        cwd=REPO,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    ).stdout.split("\n")

    surface: dict[str, list[str]] = {}
    for path in listing:
        if not (path.startswith("src/megabasterd_cli/") and path.endswith(".py")):
            continue
        blob = subprocess.run(
            ["git", "show", f"{BASELINE_REV}:{path}"],
            cwd=REPO,
            capture_output=True,
            check=True,
        ).stdout.decode("utf-8", "replace")
        module = path[len("src/") : -len(".py")].replace("/", ".").removesuffix(".__init__")
        found = _public_names(blob, path)
        if found:
            surface[module] = sorted(found)

    if len(surface) < BASELINE_MODULES:
        sys.exit(f"only {len(surface)} modules read from {BASELINE_REV}; is this a full clone?")
    SNAPSHOT.parent.mkdir(parents=True, exist_ok=True)
    SNAPSHOT.write_text(
        json.dumps(dict(sorted(surface.items())), indent=2) + "\n", encoding="utf-8"
    )
    print(f"wrote {SNAPSHOT} - {len(surface)} modules, {sum(map(len, surface.values()))} names")
