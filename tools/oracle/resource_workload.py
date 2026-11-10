# SPDX-License-Identifier: GPL-3.0-or-later
"""CI-only resource workload using verified, unmodified baseline function bodies."""

from __future__ import annotations

import __future__
import argparse
import ast
import contextlib
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import sys
import tempfile
import time
import uuid

BASELINE = "c4559ecef08c1fb47cc57669230d2f6013520416"
SIZES = (1024 * 1024 + 17, 16 * 1024 * 1024 + 17)
SOURCES = {
    "crypter": ("ef0c3755b0191097dc6a2b19ef1ac060234b633c183557de5348c9c0e082f3f6",
                {"_atomic_output"}),
    "upload_identity": ("9f2de240528f3d5a5629c3017feb4a7cf6c637f216bfd99ae43fd49a96a3ed1f",
                        {"_HASH_BLOCK", "_HASH_LOG_THRESHOLD", "file_sha256"}),
    "splitter": ("78d915944c7c8e50d1515a0a42875c34426cb39d2560323f6cd2ad26f602055f",
                 {"_PART_RE", "SplitterError", "SplitterAliasError", "SplitResult",
                  "_is_same_file", "_reject_aliases", "split_file", "merge_parts"}),
}


def selected_definitions(text, expected):
    """Select whole original definitions, never edit their bodies or import the app."""
    nodes, found = [], set()
    for node in ast.parse(text).body:
        names = ({node.name} if isinstance(node, (ast.FunctionDef, ast.ClassDef)) else
                 {target.id for target in node.targets if isinstance(target, ast.Name)}
                 if isinstance(node, ast.Assign) else set())
        selected = names & expected
        if selected:
            if selected != names or found & names:
                raise ValueError("Baseline definition is duplicated or shares an assignment")
            nodes.append(node)
            found.update(names)
    if found != expected:
        raise ValueError("Baseline workload definitions are incomplete")
    return ast.Module(body=nodes, type_ignores=[])


def load_source(root):
    namespace = {"__name__": __name__, "contextlib": contextlib, "dataclass": dataclass,
                 "hashlib": hashlib, "log": logging.getLogger("source-resource"),
                 "os": os, "Path": Path, "re": re, "tempfile": tempfile, "time": time}
    for name, (digest, definitions) in SOURCES.items():
        path = confined(root / "src" / "megabasterd_cli" / "core" / (name + ".py"), root)
        if not path.is_file() or path.stat().st_size > 128 * 1024:
            raise ValueError("Baseline workload source is missing, linked or oversized")
        text = path.read_text(encoding="utf-8", errors="strict")
        if hashlib.sha256(text.encode("utf-8")).hexdigest() != digest:
            raise ValueError("Baseline workload source digest differs")
        tree = selected_definitions(text, definitions)
        exec(compile(tree, str(path), "exec", flags=__future__.annotations.compiler_flag), namespace)
    return namespace


def peak_rss():
    if os.name != "nt":
        import resource
        value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return int(value if sys.platform == "darwin" else value * 1024)
    import ctypes
    from ctypes import wintypes as w
    class Counters(ctypes.Structure):
        _fields_ = [("cb", w.DWORD), ("faults", w.DWORD),
                    ("peak", ctypes.c_size_t), ("working", ctypes.c_size_t),
                    ("remaining", ctypes.c_size_t * 6)]
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.GetCurrentProcess.argtypes, api.GetCurrentProcess.restype = [], w.HANDLE
    api.K32GetProcessMemoryInfo.argtypes = [w.HANDLE, ctypes.c_void_p, w.DWORD]
    api.K32GetProcessMemoryInfo.restype = w.BOOL
    counters = Counters()
    counters.cb = ctypes.sizeof(counters)
    if not api.K32GetProcessMemoryInfo(api.GetCurrentProcess(), ctypes.byref(counters), counters.cb):
        raise OSError("Process peak working set is unavailable")
    return counters.peak


def workload(source, output, functions):
    size = source.stat().st_size
    if size not in SIZES or any(output.iterdir()):
        raise ValueError("Resource workload input size or empty destination differs")
    start = time.perf_counter_ns()
    digest = functions["file_sha256"](source, size)
    hash_ns = time.perf_counter_ns() - start
    start = time.perf_counter_ns()
    split = functions["split_file"](source, 4, output_dir=output)
    split_ns = time.perf_counter_ns() - start
    start = time.perf_counter_ns()
    functions["merge_parts"](split.parts[-1], output=output / "merged.bin", verify_sha1=True)
    merge_ns = time.perf_counter_ns() - start
    return {"schema_version": 1, "engine": "python-source", "bytes": size,
            "sha256": digest, "sha1": split.sha1, "hash_ns": hash_ns,
            "split_ns": split_ns, "merge_ns": merge_ns, "peak_rss_bytes": peak_rss(),
            "runtime": "CPython " + sys.version.split()[0]}


def confined(path, base):
    path, base = path.absolute(), base.resolve(strict=True)
    relative = path.relative_to(base)
    current = base
    for part in relative.parts:
        current /= part
        if part in {".", ".."} or current.is_symlink() or getattr(current.lstat(), "st_file_attributes", 0) & 0x400:
            raise ValueError("Resource workload path is linked or contains traversal")
    if not path.resolve(strict=True).is_relative_to(base):
        raise ValueError("Resource workload escaped its owning scratch")
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    handler = None
    logger = logging.getLogger("source-resource")
    logger.setLevel(logging.INFO)
    try:
        base = root / ".ci-work" / "resource-contract"
        source = confined(args.source, base)
        directory = confined(args.directory, base)
        baseline = confined(args.baseline, root / ".ci-work")
        if not source.is_file() or not directory.is_dir() or any(directory.iterdir()):
            raise ValueError("Resource workload needs an owned input and empty sample directory")
        # Log beside, not inside, the initially empty operation destination.
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S_UTC")
        handler = logging.FileHandler(directory.parent / f"resource_workload_{stamp}_{uuid.uuid4().hex}.log",
                                      mode="x", encoding="utf-8")
        formatter = logging.Formatter("[%(asctime)s UTC] [%(levelname)s] [RESOURCE] %(message)s",
                                      datefmt="%Y-%m-%d %H:%M:%S")
        formatter.converter = time.gmtime
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.info("Started verified baseline workload")
        functions = load_source(baseline)
        try:
            result = workload(source, directory, functions)
        except functions["SplitterError"]:
            raise RuntimeError("Baseline file operation failed") from None
        with (directory / "sample.json").open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(result, stream, sort_keys=True, allow_nan=False)
            stream.write("\n")
        logger.info("Finished exit_code=0 bytes=%d", result["bytes"])
        return 0
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
        if handler is not None:
            logger.error("Failed exit_code=1 category=%s", type(error).__name__)
        print("Source resource workload failed; inspect private CI diagnostics.", file=sys.stderr)
        return 1
    finally:
        if handler is not None:
            logger.removeHandler(handler)
            handler.close()


if __name__ == "__main__":
    raise SystemExit(main())
