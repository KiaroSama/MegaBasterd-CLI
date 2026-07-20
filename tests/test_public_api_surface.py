"""Every public name in the accepted 1.x surface must still resolve.

`test_api_compatibility_1x.py` lists restorations by hand. That list has been
wrong twice: a cleanup pass deleted fourteen public names, they were restored,
and the very next pass deleted six more with the suite still green. A
hand-maintained list only catches what someone remembered to add to it.

`tests/data/public_api_1x.json` is the accepted surface: module-level
functions, classes and UPPERCASE constants, plus public methods and attributes
of public classes. The rule is the one the sibling module states - a name
without a leading underscore was importable, and 1.x is not a boundary at which
importable API may disappear.

Two properties make this hold up where the first two attempts did not:

* It is committed DATA, not a query. The first version called `git archive` on
  the initial commit and failed every CI job: `actions/checkout` clones at
  depth 1, so that object does not exist there. Data needs no history, no
  network and no repository, and survives into an sdist.

* Regeneration is MONOTONIC. The second version snapshotted only the initial
  commit, so anything added later - `core.api.is_mutating`,
  `AmbiguousMutationError`, `HashcashBudgetExceededError` - was unguarded, even
  though the file claimed to cover the series. Regeneration now unions the
  existing snapshot with what is on disk and can only ever grow it. Removing a
  name is therefore never a side effect of running a command; it takes an
  `INTENTIONALLY_REMOVED` entry or a hand edit that shows up in the diff.

Regenerate after adding public API - `test_the_snapshot_has_not_gone_stale`
tells you when:

    python -m tests.test_public_api_surface

Never regenerate to make `test_every_public_name_still_resolves` pass. That
test failing means a public name disappeared, which is the one thing this file
exists to notice.
"""

from __future__ import annotations

import ast
import importlib
import json
from pathlib import Path

import pytest

from tests.launcher_helpers import REPO

SRC = REPO / "src" / "megabasterd_cli"
SNAPSHOT = Path(__file__).parent / "data" / "public_api_1x.json"

# A floor, not a total - the snapshot grows as public API is added. It exists
# so a truncated or half-written file fails loudly instead of making every
# assertion below vacuously pass. Raise it deliberately, never lower it.
MINIMUM_NAMES = 780

# "module.name" or "module.Class.member" -> why it is allowed to be gone.
# Removing public API is a decision; this is where the decision gets written.
INTENTIONALLY_REMOVED: dict[str, str] = {}


def _surface(tree: ast.Module) -> set[str]:
    """Public names in one module: bare, or `Class.member` for class contents."""
    found: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not node.name.startswith("_"):
                found.add(node.name)
        elif isinstance(node, ast.ClassDef):
            if node.name.startswith("_"):
                continue
            found.add(node.name)
            found |= {f"{node.name}.{m}" for m in _class_members(node)}
        elif isinstance(node, ast.Assign):
            # Constants only: a module-level lowercase binding is usually a
            # singleton or an alias, not declared API.
            for target in node.targets:
                if (
                    isinstance(target, ast.Name)
                    and not target.id.startswith("_")
                    and target.id.isupper()
                ):
                    found.add(target.id)
    return found


def _class_members(node: ast.ClassDef) -> set[str]:
    """Public methods and attributes, including annotation-only dataclass fields."""
    members: set[str] = set()
    for item in node.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not item.name.startswith("_"):
                members.add(item.name)
        elif isinstance(item, ast.AnnAssign):
            # `title: str` has no class attribute at all when it has no
            # default, so it must be collected from the annotation.
            if isinstance(item.target, ast.Name) and not item.target.id.startswith("_"):
                members.add(item.target.id)
        elif isinstance(item, ast.Assign):
            for target in item.targets:
                if isinstance(target, ast.Name) and not target.id.startswith("_"):
                    members.add(target.id)
    return members


def _current_surface() -> dict[str, set[str]]:
    """What the working tree exposes right now."""
    live: dict[str, set[str]] = {}
    for path in sorted(SRC.rglob("*.py")):
        module = path.relative_to(REPO / "src").with_suffix("").as_posix().replace("/", ".")
        module = module.removesuffix(".__init__")
        found = _surface(ast.parse(path.read_text(encoding="utf-8"), str(path)))
        if found:
            live[module] = found
    return live


def _resolves(module: object, dotted: str) -> bool:
    """`name` or `Class.member`, following the MRO so a moved method still counts."""
    head, _, member = dotted.partition(".")
    if not hasattr(module, head):
        return False
    if not member:
        return True
    owner = getattr(module, head)
    if hasattr(owner, member):
        return True
    # An annotation-only dataclass field with no default is not an attribute.
    return any(
        member in getattr(base, "__annotations__", {}) for base in getattr(owner, "__mro__", [])
    )


@pytest.fixture(scope="session")
def snapshot() -> dict[str, list[str]]:
    assert SNAPSHOT.is_file(), f"the baseline snapshot is missing: {SNAPSHOT}"
    loaded = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    total = sum(len(v) for v in loaded.values())
    assert total >= MINIMUM_NAMES, f"snapshot holds {total} names, under the floor; it is truncated"
    return loaded


def test_every_public_name_still_resolves(snapshot):
    """Resolvable from the SAME module - moving a name breaks `from x import y` too.

    A split may relocate an implementation freely; it just has to leave the old
    name resolvable, by re-export or by PEP 562 `__getattr__`.
    """
    missing = []
    for module, names in sorted(snapshot.items()):
        try:
            loaded = importlib.import_module(module)
        except ModuleNotFoundError:
            missing += [f"{module}.{n} (module removed)" for n in sorted(names)]
            continue
        for name in sorted(names):
            if f"{module}.{name}" in INTENTIONALLY_REMOVED:
                continue
            if not _resolves(loaded, name):
                missing.append(f"{module}.{name}")

    assert not missing, (
        "public names from the accepted 1.x surface no longer resolve:\n  "
        + "\n  ".join(missing)
        + "\n\nRestore them, or add each to INTENTIONALLY_REMOVED with a reason."
        + "\nDo NOT regenerate the snapshot to make this pass."
    )


def test_the_snapshot_has_not_gone_stale(snapshot):
    """New public API must enter the snapshot, or it is never guarded.

    This is the gap that made the previous version's promise false: it held
    only the initial commit, so everything added across the series was
    unprotected while the file claimed to cover it.
    """
    recorded = {f"{m}.{n}" for m, names in snapshot.items() for n in names}
    unguarded = sorted(
        f"{module}.{name}"
        for module, names in _current_surface().items()
        for name in names
        if f"{module}.{name}" not in recorded
    )
    assert not unguarded, (
        f"{len(unguarded)} public name(s) are not in the snapshot, so nothing guards them:\n  "
        + "\n  ".join(unguarded[:40])
        + ("\n  ..." if len(unguarded) > 40 else "")
        + "\n\nRegenerate: python -m tests.test_public_api_surface"
    )


def test_the_allowlist_does_not_name_something_that_still_exists():
    """A stale entry silently un-guards a name that came back."""
    for dotted in INTENTIONALLY_REMOVED:
        module, _, name = dotted.rpartition(".")
        try:
            loaded = importlib.import_module(module)
        except ModuleNotFoundError:
            continue
        assert not _resolves(loaded, name), f"{dotted} exists again; drop it from the allowlist"


if __name__ == "__main__":  # regeneration, see the module docstring
    merged = {m: set(names) for m, names in json.loads(SNAPSHOT.read_text("utf-8")).items()}
    for module, names in _current_surface().items():
        merged.setdefault(module, set()).update(names)  # union only: never drops a name

    SNAPSHOT.parent.mkdir(parents=True, exist_ok=True)
    SNAPSHOT.write_text(
        json.dumps({m: sorted(n) for m, n in sorted(merged.items())}, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"{len(merged)} modules, {sum(len(n) for n in merged.values())} names -> {SNAPSHOT}")
