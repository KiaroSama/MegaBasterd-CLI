# SPDX-License-Identifier: GPL-3.0-or-later
"""Conservative platform floors from pinned source syntax, never imported test code."""

import ast
from functools import lru_cache
import hashlib

PLATFORMS = frozenset({"windows", "linux", "macos"})
HELPER = "tests/launcher_helpers.py"
HELPER_SHA256 = "f5af9ed3e5b6c1e8035e2946f9994584a42ee01ed7e6e635376177ecfd6b0ea1"


def platforms(value):
    if (not isinstance(value, list) or not value or len(value) > 3
            or any(not isinstance(item, str) for item in value)
            or len(set(value)) != len(value) or not set(value) <= PLATFORMS):
        raise ValueError("Platform scope must be a nonempty unique native OS array")
    return frozenset(value)


@lru_cache(maxsize=192)
def source_platforms(text, helper=None):
    """Unknown marks keep every OS; only verified static exclusions reduce the floor."""
    tree = ast.parse(text)
    imports = {}
    duplicates = set()
    for item in tree.body:
        bindings = []
        if isinstance(item, ast.Import):
            bindings = [(name.asname or name.name, name.name) for name in item.names
                        if name.name in {"os", "sys", "pytest"}]
        elif isinstance(item, ast.ImportFrom) and item.level == 0 and item.module == "tests.launcher_helpers":
            bindings = [(name.asname or name.name, name.name) for name in item.names
                        if name.name in {"windows_only", "posix_only"}]
        for name, original in bindings:
            if name in imports:
                duplicates.add(name)
            imports[name] = original
    # A rebound or shadowed name is not trusted as a standard module or imported marker.
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            duplicates.add(node.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            duplicates.add(node.name)
        elif isinstance(node, ast.arg):
            duplicates.add(node.arg)
        elif isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
            base = node.value
            while isinstance(base, ast.Attribute):
                base = base.value
            if isinstance(base, ast.Name):
                duplicates.add(base.id)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                name = alias.asname or alias.name.split(".")[0]
                if (isinstance(node, ast.Import) and imports.get(name) != alias.name
                        or isinstance(node, ast.ImportFrom) and (
                            node.level != 0 or node.module != "tests.launcher_helpers"
                            or imports.get(name) != alias.name)):
                    duplicates.add(name)
    imports = {name: original for name, original in imports.items() if name not in duplicates}
    helper_checked = False

    def dotted(node):
        if isinstance(node, ast.Name):
            return imports.get(node.id, "")
        if isinstance(node, ast.Attribute):
            base = dotted(node.value)
            return base + "." + node.attr if base else ""
        return ""

    def marked_scope(mark):
        nonlocal helper_checked
        name = dotted(mark)
        if name in {"windows_only", "posix_only"}:
            if not helper_checked:
                if (not isinstance(helper, str)
                        or hashlib.sha256(helper.encode("utf-8")).hexdigest() != HELPER_SHA256):
                    raise ValueError("Pinned source platform helper is missing or changed")
                helper_checked = True
            return frozenset({"windows"}) if name == "windows_only" else PLATFORMS - {"windows"}
        if not isinstance(mark, ast.Call) or dotted(mark.func) != "pytest.mark.skipif":
            return PLATFORMS
        if len(mark.args) != 1:
            return PLATFORMS
        condition = mark.args[0]
        if (not isinstance(condition, ast.Compare) or len(condition.ops) != 1
                or len(condition.comparators) != 1 or not isinstance(condition.comparators[0], ast.Constant)
                or not isinstance(condition.ops[0], (ast.Eq, ast.NotEq))):
            return PLATFORMS
        values = {"os.name": {"windows": "nt", "linux": "posix", "macos": "posix"},
                  "sys.platform": {"windows": "win32", "linux": "linux", "macos": "darwin"}}
        actual = values.get(dotted(condition.left))
        expected = condition.comparators[0].value
        if actual is None or not isinstance(expected, str) or expected not in actual.values():
            return PLATFORMS
        return frozenset(os for os, value in actual.items()
                         if (value != expected if isinstance(condition.ops[0], ast.Eq) else value == expected))

    def marks(body):
        assignments = [node.value for node in body if isinstance(node, ast.Assign)
                       and any(isinstance(target, ast.Name) and target.id == "pytestmark" for target in node.targets)]
        if len(assignments) != 1:
            return []
        value = assignments[0]
        return value.elts if isinstance(value, (ast.List, ast.Tuple)) else [value]

    def intersect(inherited, decorators):
        result = inherited
        for decorator in decorators:
            result &= marked_scope(decorator)
        if not result:
            raise ValueError("Source platform scope is empty")
        return result

    result = {}

    def visit(body, inherited, classes=()):
        inherited = intersect(inherited, marks(body))
        for node in body:
            if isinstance(node, ast.ClassDef):
                visit(node.body, intersect(inherited, node.decorator_list), (*classes, node.name))
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
                name = "::".join((*classes, node.name))
                if name in result:
                    raise ValueError("Duplicate source platform test identity")
                result[name] = intersect(inherited, node.decorator_list)
    visit(tree.body, PLATFORMS)
    return result
