# SPDX-License-Identifier: GPL-3.0-or-later
"""Rebuild verified source archives with an empty Cargo cache on the native CI host.

Cargo offline mode is not an OS network sandbox or a reproducible-binary/signing claim.
The existing CI command owner supplies deadlines, resource limits and process cleanup.
"""

import hashlib
import json
import os
from pathlib import Path
import stat
import tomllib

from archive import MAX_FILES, MAX_TOTAL, extract, identity, source_names, stage_binary
from dependencies import CONFIG, inventory, pairs, regular

BUILD_KEYS = {"PATH", "SystemRoot", "WINDIR", "COMSPEC", "PATHEXT", "INCLUDE", "LIB", "LIBPATH",
              "VCINSTALLDIR", "VSINSTALLDIR", "VCToolsInstallDir", "WindowsSdkDir", "SDKROOT",
              "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "SYSTEMDRIVE"}


def verify_tree(root, rows):
    expected = {row["path"]: row for row in rows}
    found, directories, total = set(), 0, 0
    def walk_error(error):
        raise error
    for current, children, files in os.walk(root, followlinks=False, onerror=walk_error):
        directories += len(children)
        if directories > MAX_FILES:
            raise ValueError("Extracted source directory count exceeds its bound")
        for name in children:
            regular(Path(current) / name, directory=True)
        for name in files:
            path = Path(current) / name
            relative = path.relative_to(root).as_posix()
            row = expected.get(relative)
            if row is None or relative in found:
                raise ValueError("Extracted source contains an unexpected file")
            info = regular(path)
            total += info.st_size
            if total > MAX_TOTAL or info.st_size != row["bytes"]:
                raise ValueError("Extracted source length differs")
            with path.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            if digest != row["sha256"] or (os.name != "nt" and stat.S_IMODE(info.st_mode) != row["mode"]):
                raise ValueError("Extracted source bytes or executable mode differ")
            found.add(relative)
    if found != set(expected):
        raise ValueError("Extracted source file inventory differs")


def restore(project_archive, dependency_archive, scratch, expected):
    expected = identity(expected)
    if expected["kind"] != "source":
        raise ValueError("Rebuild requires source archives")
    project, dependency = scratch / "native source with spaces", scratch / "dependency source"
    project_manifest = extract(project_archive, project, expected)
    dependency_manifest = extract(dependency_archive, dependency, expected)
    names = {row["path"] for row in project_manifest["files"]}
    if set(source_names(sorted(names))) != names:
        raise ValueError("Rebuild project archive contains undeclared source")
    lock_bytes = (project / "Cargo.lock").read_bytes()
    if lock_bytes != (dependency / "Cargo.lock").read_bytes():
        raise ValueError("Rebuild source archives contain different lockfiles")
    package = tomllib.loads((project / "Cargo.toml").read_text(encoding="utf-8"))["package"]
    if package.get("name") != "megabasterd-cli" or package.get("version") != expected["version"]:
        raise ValueError("Rebuild project manifest identity differs")
    entries, packages = inventory(dependency / "vendor", tomllib.loads(lock_bytes.decode("utf-8")))
    metadata_path = dependency / "dependency-manifest.json"
    if regular(metadata_path).st_size > 16 * 1024 * 1024:
        raise ValueError("Rebuild dependency manifest exceeds its bound")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"), object_pairs_hook=pairs)
    if metadata != {"identity": expected, "lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
                    "packages": packages}:
        raise ValueError("Rebuild dependency manifest differs from the extracted locked sources")
    if (dependency / ".cargo/config.toml").read_bytes() != CONFIG.encode("utf-8"):
        raise ValueError("Rebuild source replacement configuration differs")
    dependency_names = {row["path"] for row in dependency_manifest["files"]}
    if dependency_names != set(entries) | {"Cargo.lock", ".cargo/config.toml", "dependency-manifest.json"}:
        raise ValueError("Rebuild dependency archive contains undeclared material")
    (dependency / "vendor").rename(project / "vendor")
    (dependency / ".cargo").rename(project / ".cargo")
    rows = [*project_manifest["files"], *(row for row in dependency_manifest["files"]
             if row["path"].startswith("vendor/") or row["path"] == ".cargo/config.toml")]
    verify_tree(project, rows)
    return project, rows, len(packages)


def tool_paths(cargo, environment, command, log, memory):
    if len(cargo) != 2 or not cargo[1].startswith("+"):
        raise ValueError("Rebuild requires an explicit installed toolchain")
    tools = {}
    for name in ("cargo", "rustc", "rustdoc"):
        code, stdout, _ = command(["rustup", "which", "--toolchain", cargo[1][1:], name],
                                  "rebuild-tool-" + name, environment, log,
                                  wall=30, idle=10, memory_mib=memory)
        if code:
            raise ValueError("Installed rebuild toolchain could not be resolved")
        text = stdout.decode("utf-8", errors="strict").strip()
        path = Path(text)
        if not text or "\n" in text or "\r" in text or not path.is_absolute() or not path.is_file():
            raise ValueError("Resolved rebuild tool is not an existing absolute executable")
        tools[name] = path.resolve(strict=True)
    if len({path.parent for path in tools.values()}) != 1:
        raise ValueError("Resolved rebuild tools do not belong to one installed toolchain")
    return tools


def rebuild(project_archive, dependency_archive, scratch, expected, cargo, environment,
            command, log, workers, memory):
    project, rows, packages = restore(project_archive, dependency_archive, scratch, expected)
    tools = tool_paths(cargo, environment, command, log, memory)
    home, cache, target, build, temporary = [scratch / name for name in
                                           ("home", "cargo home", "target", "build", "temp")]
    for directory in (home, cache, target, build, temporary):
        directory.mkdir()
    isolated = {key: environment[key] for key in BUILD_KEYS if key in environment}
    isolated.update({key: str(home) for key in ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA")})
    isolated.update({key: str(temporary) for key in ("TMP", "TEMP", "TMPDIR")})
    isolated.update({"CARGO_HOME": str(cache), "CARGO_TARGET_DIR": str(target),
        "CARGO_BUILD_BUILD_DIR": str(build), "RUSTC": str(tools["rustc"]), "RUSTDOC": str(tools["rustdoc"]),
        "CARGO_NET_OFFLINE": "true", "CARGO_NET_RETRY": "0", "CARGO_HTTP_TIMEOUT": "30",
        "CARGO_BUILD_JOBS": str(workers), "HOOKMAKER_MAX_TEST_WORKERS": str(workers),
        "RAYON_NUM_THREADS": str(workers), "OMP_NUM_THREADS": "1", "CARGO_INCREMENTAL": "0",
        "CARGO_TERM_COLOR": "never", "RUST_BACKTRACE": "0"})
    code, _, _ = command([tools["cargo"], "build", "--frozen", "--release", "--workspace", "--bins",
                           "-j", str(workers)], "extracted-source-build", isolated, log,
                          wall=900, idle=180, memory_mib=memory, cwd=project)
    if code:
        raise ValueError("Extracted locked source rebuild failed")
    verify_tree(project, rows)
    suffix = ".exe" if expected["target"] == "x86_64-pc-windows-msvc" else ""
    staged = scratch / "single-link native outputs"
    staged.mkdir()
    binaries = {name + suffix: stage_binary(target / "release" / (name + suffix), staged / (name + suffix))
                for name in ("mb", "mbcli", "megabasterd-cli")}
    log.event("INFO", "Extracted locked source rebuild completed", commit=expected["commit"],
              target=expected["target"], packages=packages, cargo_cache="initially empty",
              cargo_offline=True, os_network_isolation=False, release_ready=False)
    return project, binaries
