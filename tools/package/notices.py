# SPDX-License-Identifier: GPL-3.0-or-later
"""Preserve locked dependency notice bytes and their package association, not legal approval."""

import hashlib
import json
from pathlib import PurePosixPath
import re
import tomllib

from archive import _open_input, identity, member_name
from dependencies import inventory, regular

NOTICE = re.compile(r"(?:licen[cs]e|copying|copyright|notice|unlicense)(?:[._-].*)?", re.IGNORECASE)
GRANT = re.compile(r"(?:licen[cs]e|copying|unlicense)(?:[._-].*)?", re.IGNORECASE)
MAX_NOTICE = 2 * 1024 * 1024
MAX_NOTICES_TOTAL = 32 * 1024 * 1024
INDEX = "licenses/dependencies/index.json"


def notice_entries(project, output, build):
    """Inventory every locked package, preserving root, declared and nested notice files."""
    build = identity(build)
    lock_bytes = (project / "Cargo.lock").read_bytes()
    sources, packages = inventory(project / "vendor", tomllib.loads(lock_bytes.decode("utf-8")))
    entries, digests, records, total = {}, {}, [], 0
    for package in packages:
        directory = f"{package['name']}-{package['version']}"
        prefix = f"vendor/{directory}/"
        manifest = tomllib.loads(sources[prefix + "Cargo.toml"].read_text(encoding="utf-8"))["package"]
        declared = manifest.get("license-file")
        license_name = package["license"]
        if (license_name is not None and (not isinstance(license_name, str) or not license_name.strip())):
            raise ValueError("Dependency license expression is invalid")
        if declared is not None:
            member_name(declared)
            if declared not in package["files"]:
                raise ValueError("Declared dependency license file is absent")
        if license_name is None and declared is None:
            raise ValueError("Dependency has neither a license expression nor a license file")
        selected = set()
        for name in package["files"]:
            path = PurePosixPath(name)
            if (NOTICE.fullmatch(path.name)
                    or any(part.casefold() in {"licenses", "licences"} for part in path.parts[:-1])):
                selected.add(name)
        if declared is not None:
            selected.add(declared)
        if declared is None and not any("/" not in name and GRANT.fullmatch(name) for name in selected):
            raise ValueError("Dependency needs an actual root or declared license file")
        documents = []
        for name in sorted(selected):
            source = sources[prefix + name]
            info = regular(source)
            if not 0 < info.st_size <= MAX_NOTICE:
                raise ValueError("Dependency notice is empty or exceeds its bound")
            total += info.st_size
            if total > MAX_NOTICES_TOTAL:
                raise ValueError("Dependency notices exceed their aggregate bound")
            stream, held = _open_input(source)
            with stream:
                content = stream.read(MAX_NOTICE + 1)
            if len(content) != info.st_size or held.st_size != info.st_size:
                raise ValueError("Dependency notice length changed after source inventory")
            text = content.decode("utf-8", errors="strict")
            digest = hashlib.sha256(content).hexdigest()
            if not text.strip() or digest != package["files"][name]:
                raise ValueError("Dependency notice is blank or changed after source inventory")
            destination = member_name(f"licenses/dependencies/{directory}/{name}")
            entries[destination], digests[destination] = source, digest
            documents.append({"source": prefix + name, "path": destination,
                              "bytes": len(content), "sha256": digest})
        records.append({"name": package["name"], "version": package["version"],
                        "package_checksum": package["checksum"], "license": license_name,
                        "license_file": declared, "documents": documents})
    document = {"schema_version": 1, "identity": build,
                "lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
                "scope": "All locked registry dependencies, including build, development and other targets",
                "legal_review": "Required; preserved files do not establish complete license compliance",
                "packages": records}
    encoded = (json.dumps(document, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    output.mkdir()
    index = output / "index.json"
    with index.open("xb") as stream:
        stream.write(encoded)
    entries[INDEX], digests[INDEX] = index, hashlib.sha256(encoded).hexdigest()
    return entries, digests
