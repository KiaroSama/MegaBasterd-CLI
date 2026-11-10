# SPDX-License-Identifier: GPL-3.0-or-later
"""CI dependency-source inventory, bound to Cargo.lock and every vendored file."""

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tomllib

from archive import MAX_FILES, MAX_MEMBER, MAX_TOTAL, identity, member_name, prepare, verify

REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
HEX = re.compile(r"[0-9a-f]{64}")
CONFIG = ('[source.crates-io]\nreplace-with = "vendored-sources"\n\n'
          '[source.vendored-sources]\ndirectory = "vendor"\n')


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("Dependency checksum document contains duplicate fields")
        result[key] = value
    return result


def regular(path, directory=False):
    info = path.lstat()
    if (getattr(info, "st_file_attributes", 0) & 0x400
            or not (stat.S_ISDIR(info.st_mode) if directory else
                    stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= MAX_MEMBER)):
        raise ValueError("Dependency source contains a linked, special or oversized entry")
    return info


def vendor_config(output):
    if len(output) > 16 * 1024:
        raise ValueError("Cargo vendor configuration exceeds its bound")
    value = tomllib.loads(output.decode("utf-8", errors="strict"))
    expected = {"crates-io", "vendored-sources"}
    sources = value.get("source")
    if (set(value) != {"source"} or not isinstance(sources, dict) or set(sources) != expected
            or sources["crates-io"] != {"replace-with": "vendored-sources"}
            or not isinstance(sources["vendored-sources"], dict)
            or set(sources["vendored-sources"]) != {"directory"}
            or not isinstance(sources["vendored-sources"]["directory"], str)):
        raise ValueError("Cargo vendor configuration contains unexpected sources or options")
    return CONFIG


def inventory(vendor, lock):
    regular(vendor, directory=True)
    expected = {}
    if not isinstance(lock, dict) or not isinstance(lock.get("package"), list):
        raise ValueError("Dependency lock package inventory is invalid")
    for package in lock["package"]:
        if not isinstance(package, dict):
            raise ValueError("Dependency lock package is invalid")
        if "source" not in package:
            if package.get("name") != "megabasterd-cli":
                raise ValueError("Unbundled local dependency requires an explicit source contract")
            continue
        name, version, checksum = package.get("name"), package.get("version"), package.get("checksum")
        if (package["source"] != REGISTRY or not isinstance(name, str)
                or re.fullmatch(r"[A-Za-z0-9_-]+", name) is None or not isinstance(version, str)
                or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.+-]+)?", version) is None
                or not isinstance(checksum, str) or HEX.fullmatch(checksum) is None):
            raise ValueError("Dependency lock source or package identity is unsupported")
        directory = f"{name}-{version}"
        if directory in expected:
            raise ValueError("Dependency lock contains a duplicate package")
        expected[directory] = package
    if not 0 < len(expected) <= 1000:
        raise ValueError("Dependency lock inventory count is invalid")
    actual = set()
    for path in vendor.iterdir():
        actual.add(path.name)
        if len(actual) > len(expected):
            raise ValueError("Vendored directories exceed the locked inventory")
    if actual != set(expected):
        raise ValueError("Vendored directories differ from the exact locked packages")
    entries, packages, total, directory_count = {}, [], 0, 0
    for directory, package in sorted(expected.items()):
        root = vendor / directory
        regular(root, directory=True)
        checksum_path = root / ".cargo-checksum.json"
        if regular(checksum_path).st_size > 2 * 1024 * 1024:
            raise ValueError("Dependency checksum document exceeds its bound")
        checksum_bytes = checksum_path.read_bytes()
        checks = json.loads(checksum_bytes.decode("utf-8", errors="strict"), object_pairs_hook=pairs)
        if (not isinstance(checks, dict) or not {"package", "files"} <= set(checks)
                or set(checks) - {"package", "files", "$comment"}
                or checks["package"] != package["checksum"]
                or not isinstance(checks["files"], dict) or not 0 < len(checks["files"]) < MAX_FILES):
            raise ValueError("Vendored package checksum identity differs from Cargo.lock")
        hashes = checks["files"]
        for name, digest in hashes.items():
            member_name(name)
            if name == ".cargo-checksum.json" or not isinstance(digest, str) or HEX.fullmatch(digest) is None:
                raise ValueError("Vendored file checksum or path is invalid")
        found, executables = {}, []
        def walk_error(error):
            raise error
        for current, directories, files in os.walk(root, followlinks=False, onerror=walk_error):
            directory_count += len(directories)
            if directory_count > MAX_FILES:
                raise ValueError("Dependency source directory inventory exceeds its bound")
            for name in directories:
                regular(Path(current) / name, directory=True)
            for name in files:
                path = Path(current) / name
                relative = path.relative_to(root).as_posix()
                archive_name = member_name(f"vendor/{directory}/{relative}")
                info = regular(path)
                if os.name != "nt" and info.st_mode & 0o111:
                    executables.append(relative)
                total += info.st_size
                if len(entries) >= MAX_FILES - 3 or total > MAX_TOTAL:
                    raise ValueError("Dependency source inventory exceeds its aggregate bound")
                if relative != ".cargo-checksum.json":
                    with path.open("rb") as content:
                        digest = hashlib.file_digest(content, "sha256").hexdigest()
                    if hashes.get(relative) != digest:
                        raise ValueError("Vendored source bytes differ from their checksum")
                    found[relative] = digest
                entries[archive_name] = path
        if found != hashes:
            raise ValueError("Vendored source file inventory differs from its checksum document")
        manifest_path = root / "Cargo.toml"
        if "Cargo.toml" not in found or manifest_path.stat().st_size > 4 * 1024 * 1024:
            raise ValueError("Vendored source manifest is missing or oversized")
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))["package"]
        if (not isinstance(manifest, dict) or manifest.get("name") != package["name"]
                or manifest.get("version") != package["version"]):
            raise ValueError("Vendored manifest differs from its locked identity")
        packages.append({"name": package["name"], "version": package["version"],
                         "checksum": package["checksum"], "license": manifest.get("license"),
                         "files": found, "executables": sorted(executables),
                         "checksum_file_sha256": hashlib.sha256(checksum_bytes).hexdigest()})
    return entries, packages


def prepare_dependencies(root, work, current, target, cargo, environment, command, log, memory):
    lock_path = root / "Cargo.lock"
    lock_bytes = lock_path.read_bytes()
    lock = tomllib.loads(lock_bytes.decode("utf-8", errors="strict"))
    version = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))["package"]["version"]
    build = identity({"version": version, "commit": current["commit"], "target": target, "kind": "source"})
    base = work / "dependency-source"
    base.mkdir()
    vendor = base / "vendor"
    code, output, _ = command([*cargo, "vendor", "--locked", "--versioned-dirs", str(vendor)],
                              "distribution-vendor", environment, log, wall=600, idle=120, memory_mib=memory)
    if code:
        raise ValueError("Locked dependency source preparation failed")
    config = vendor_config(output)
    if lock_path.read_bytes() != lock_bytes:
        raise ValueError("Dependency source preparation changed Cargo.lock")
    entries, packages = inventory(vendor, lock)
    generated = base / "metadata"
    generated.mkdir()
    config_path = generated / "config.toml"
    config_path.write_text(config, encoding="utf-8", newline="\n")
    manifest_path = generated / "dependency-manifest.json"
    manifest_path.write_text(json.dumps({"identity": build, "lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
        "packages": packages}, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    entries.update({"Cargo.lock": lock_path, ".cargo/config.toml": config_path,
                    "dependency-manifest.json": manifest_path})
    destination = base / f"megabasterd-cli-{version}-{current['commit'][:12]}-dependency-source.zip"
    executables = {f"vendor/{package['name']}-{package['version']}/{name}"
                   for package in packages for name in package["executables"]}
    report = prepare(destination, entries, build, executables=executables)
    manifest = verify(destination)
    expected = {}
    for package in packages:
        prefix = f"vendor/{package['name']}-{package['version']}/"
        expected.update({prefix + name: digest for name, digest in package["files"].items()})
        expected[prefix + ".cargo-checksum.json"] = package["checksum_file_sha256"]
    actual = {row["path"]: row["sha256"] for row in manifest["files"] if row["path"].startswith("vendor/")}
    actual_modes = {row["path"] for row in manifest["files"] if row["mode"] == 0o755}
    if actual != expected or actual_modes != executables or lock_path.read_bytes() != lock_bytes:
        raise ValueError("Archived dependency sources changed after inventory verification")
    log.event("INFO", "Locked dependency source archive prepared", commit=current["commit"],
              packages=len(packages), bytes=report["bytes"], sha256=report["sha256"],
              release_ready=False, offline_build="unverified", signing="separate gate")
    return destination, report
