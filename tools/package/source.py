# SPDX-License-Identifier: GPL-3.0-or-later
"""Prepare the exact native project's source after the owning CI has verified its tree.

This is project source, not the complete dependency-source or signed release bundle.
The existing native runner owns commands, logging, deadlines and process cleanup.
"""

from pathlib import Path
import tomllib

from archive import identity, prepare, source_names, verify


def prepare_project_source(root, current, target, environment, command, log, memory):
    root = Path(root).resolve()
    version = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))["package"]["version"]
    build = identity({"version": version, "commit": current["commit"], "target": target, "kind": "source"})
    code, output, _ = command(["git", "ls-files", "-z"], "distribution-source-inventory",
                              environment, log, wall=30, idle=10, memory_mib=memory)
    if code:
        raise ValueError("Distribution Git source inventory failed")
    paths = output.decode("utf-8", errors="strict").split("\0")
    if not paths or paths[-1] != "":
        raise ValueError("Distribution Git source inventory is not terminated")
    selected = source_names(paths[:-1])
    destination = root / ".ci-work" / "distribution" / target
    destination.mkdir(parents=True, exist_ok=False)
    archive = destination / f"megabasterd-cli-{version}-{current['commit'][:12]}-project-source.zip"
    report = prepare(archive, {name: root / name for name in selected}, build)
    manifest = verify(archive)
    if manifest["identity"] != build or {row["path"] for row in manifest["files"]} != set(selected):
        raise ValueError("Distribution source archive differs from the verified project inventory")
    log.event("INFO", "Native project source archive prepared", target=target, version=version,
              commit=current["commit"], members=len(selected), bytes=report["bytes"], sha256=report["sha256"],
              release_ready=False, dependency_source="separate gate", signing="separate gate")
    return archive, report
