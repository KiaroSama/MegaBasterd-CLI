"""Every public name the 1.x surface ever had must still import from its module.

`test_api_compatibility_1x.py` lists restorations by hand. That list has now
been wrong twice: a cleanup pass deleted fourteen public names, they were
restored, and the very next pass deleted three more (`format_speed`,
`BUF_SIZE`, and three DLC constants that a module split forgot to re-export).
A hand-maintained list only catches what someone remembered to add to it, so it
cannot catch the next one.

This computes the surface instead. The baseline is the initial commit - the
repository carries no 1.x tag, so that is the earliest recorded public API -
and the rule is the one the sibling module already states: a name without a
leading underscore was importable, and 1.x is not a boundary at which
importable API may disappear.

Deliberate removals are allowed. They go in `INTENTIONALLY_REMOVED` with a
reason, which makes dropping public API a conscious line in a diff rather than
a silent side effect of a cleanup pass.

Scope limit worth knowing: this sees module-level functions, classes and
UPPERCASE constants. It does not see class attributes, so a lost dataclass
field like `Menu.subtitle` needs its own test - there is one in the sibling
module.
"""

from __future__ import annotations

import ast
import importlib
import io
import subprocess
import tarfile

import pytest

from tests.launcher_helpers import REPO

BASELINE = "5d8f864"  # initial commit
PKG = "src/megabasterd_cli/"

# name -> why it is allowed to be gone. Removing public API is a decision;
# this is where the decision gets written down.
INTENTIONALLY_REMOVED: dict[str, str] = {}


def _public_names_at(rev: str) -> dict[str, set[str]]:
    """module dotted path -> public top-level names, read from a git revision."""
    blob = subprocess.run(
        ["git", "archive", rev, "--", PKG],
        cwd=REPO,
        capture_output=True,
        timeout=120,
    )
    assert blob.returncode == 0, blob.stderr.decode("utf-8", "replace")

    surface: dict[str, set[str]] = {}
    with tarfile.open(fileobj=io.BytesIO(blob.stdout)) as archive:
        for member in archive.getmembers():
            if not member.name.endswith(".py"):
                continue
            handle = archive.extractfile(member)
            if handle is None:
                continue
            tree = ast.parse(handle.read().decode("utf-8", "replace"), member.name)
            module = member.name[len("src/") : -len(".py")].replace("/", ".")
            module = module.removesuffix(".__init__")
            names = set()
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    if not node.name.startswith("_"):
                        names.add(node.name)
                elif isinstance(node, ast.Assign):
                    # Constants only: a module-level lowercase binding is
                    # usually a singleton or an alias, not declared API.
                    for target in node.targets:
                        if (
                            isinstance(target, ast.Name)
                            and not target.id.startswith("_")
                            and target.id.isupper()
                        ):
                            names.add(target.id)
            if names:
                surface[module] = names
    return surface


@pytest.fixture(scope="session")
def baseline_surface() -> dict[str, set[str]]:
    surface = _public_names_at(BASELINE)
    assert surface, f"no public names read from {BASELINE}; the scan is broken, not the API"
    return surface


def test_every_baseline_public_name_still_imports(baseline_surface):
    """Importable from the SAME module - moving a name breaks `from x import y` too.

    A module split may relocate an implementation freely; it just has to leave
    the old name resolvable, by re-export or by PEP 562 `__getattr__`.
    """
    missing = []
    for module, names in sorted(baseline_surface.items()):
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
