# SPDX-License-Identifier: GPL-3.0-or-later
"""Bounded distribution inventory and ZIP preparation, not signing or publication.

The CI caller owns logging, deadlines, approved inputs and final signature/runtime checks.
An archive prepared here is never evidence of a completed application build.
"""

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile
import zipfile

TARGETS = {"x86_64-pc-windows-msvc", "x86_64-unknown-linux-gnu",
           "x86_64-apple-darwin", "aarch64-apple-darwin"}
MAX_FILES = 20_000
MAX_MEMBER = 128 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024
MAX_MANIFEST = 2 * 1024 * 1024
BLOCK = 1024 * 1024
STAGE = "prepared; signing and runtime verification required"
REQUIRED_SOURCE = frozenset({
    "Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "deny.toml", "README.md", "CONTRIBUTING.md",
    "LICENSE", "ATTRIBUTION.md", "licenses/MIT-historical.txt", "licenses/Unicode-3.0.txt",
    "src/main.rs", "src/lib.rs", "src/error.rs", "tools/launcher/Run.Native.ps1",
    "docs/ARCHITECTURE.md", "docs/COMMANDS.md", "docs/CONFIG.md", "docs/USAGE.md",
    ".github/workflows/ci.yml", ".github/workflows/release.yml",
})
PRIVATE = {".git", ".ai", ".specify", "specs", "plans", "graphify-out", ".codebase-memory",
           ".agents", ".claude", ".codex", ".kiro", ".cursor", ".cline", ".ignoreme",
           "user", "logs", "log", ".venv", "venv", "__pycache__", ".ci-work", ".ci-cache"}
PRIVATE_FILES = {"secrets.md", "explain-ai.md", "reference.md", "claude.md", "agents.md"}
RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)),
            *(f"lpt{i}" for i in range(1, 10))}
BINARY_NAMES = {"mb", "mbcli", "megabasterd-cli", "mb.exe", "mbcli.exe", "megabasterd-cli.exe"}


def member_name(name):
    if not isinstance(name, str) or not name or len(name.encode("utf-8")) > 512:
        raise ValueError("Distribution member name is empty or exceeds its bound")
    parts = name.split("/")
    if any(not part or part in {".", ".."} or part.rstrip(" .") != part
           or any(ord(char) < 32 or ord(char) == 127 or char in '\\:<>"|?*' for char in part)
           or part.split(".", 1)[0].casefold() in RESERVED for part in parts):
        raise ValueError("Distribution member has an unsafe path component")
    if any(part.casefold() in PRIVATE or part.casefold() in PRIVATE_FILES
           or part.casefold().startswith(".env") or part.casefold().endswith(".env") for part in parts):
        raise ValueError("Distribution member contains local-only material")
    if PurePosixPath(name).is_absolute():
        raise ValueError("Distribution member is absolute")
    return name


def identity(value):
    if not isinstance(value, dict) or set(value) != {"version", "commit", "target", "kind"}:
        raise ValueError("Distribution identity has unexpected fields")
    if (not isinstance(value["version"], str)
            or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value["version"]) is None
            or not isinstance(value["commit"], str)
            or re.fullmatch(r"[0-9a-f]{40}", value["commit"]) is None
            or not isinstance(value["target"], str) or value["target"] not in TARGETS
            or not isinstance(value["kind"], str) or value["kind"] not in {"runtime", "source"}):
        raise ValueError("Distribution identity is unsupported")
    return dict(value)


def source_names(candidates):
    """Select only declared native project source from a caller's Git file inventory."""
    roots = {"cli", "crypto", "platform", "protocol", "services", "storage", "terminal", "transfers"}
    selected = set()
    if not isinstance(candidates, (list, tuple)) or len(candidates) > MAX_FILES:
        raise ValueError("Distribution source inventory exceeds its count bound")
    for name in candidates:
        if not isinstance(name, str):
            raise ValueError("Distribution source inventory contains a non-string path")
        parts = name.split("/")
        suffix = PurePosixPath(name).suffix
        allowed = (name in REQUIRED_SOURCE
                   or (len(parts) >= 3 and parts[0] == "src" and parts[1] in roots and suffix == ".rs")
                   or (len(parts) >= 2 and parts[0] == "tests" and suffix == ".rs")
                   or (len(parts) >= 3 and parts[:2] == ["tests", "fixtures"]
                       and suffix in {".json", ".bin", ".der", ".txt", ".md", ".png", ".mp4", ".webm"})
                   or name == "tests/fixtures/generate_local_file_services.py"
                   or (len(parts) >= 3 and parts[0] == "tools" and parts[1] in {"ci", "oracle", "package"}
                       and suffix in {".py", ".ps1"})
                   or (len(parts) == 3 and parts[:2] == [".github", "workflows"] and suffix == ".yml")
                   or name == ".github/dependabot.yml")
        if allowed:
            selected.add(member_name(name))
    if not REQUIRED_SOURCE <= selected:
        raise ValueError("Distribution source inventory omits required source or notices")
    return sorted(selected)


def _regular(info, *, single_link=True):
    return (stat.S_ISREG(info.st_mode) and (info.st_nlink == 1 if single_link else info.st_nlink >= 1)
            and not getattr(info, "st_file_attributes", 0) & 0x400)


def _fingerprint(info):
    # Windows lstat/fstat disagree on deprecated ctime; birthtime has consistent semantics.
    changed = getattr(info, "st_birthtime_ns", None) if os.name == "nt" else info.st_ctime_ns
    mode = info.st_mode & ~0o111 if os.name == "nt" else info.st_mode
    return (info.st_dev, info.st_ino, mode, info.st_nlink, info.st_size,
            info.st_mtime_ns, changed)


def _open_input(path, *, single_link=True):
    path = Path(path).absolute()
    for parent in [path, *path.parents]:
        info = parent.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("Distribution input has a linked or reparse ancestor")
    before = path.lstat()
    if not _regular(before, single_link=single_link) or not 0 <= before.st_size <= MAX_MEMBER:
        raise ValueError("Distribution input is not a bounded single-link regular file")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        if _fingerprint(os.fstat(descriptor)) != _fingerprint(before):
            raise ValueError("Distribution input changed while opening")
        return os.fdopen(descriptor, "rb"), before
    except BaseException:
        os.close(descriptor)
        raise


def stage_binary(source, destination):
    """Copy a held Cargo output (possibly hardlinked) to an exclusive single-link input."""
    content, before = _open_input(source, single_link=False)
    with content, destination.open("xb") as output:
        if before.st_size == 0:
            raise ValueError("Compiler output is empty")
        count = 0
        while block := content.read(BLOCK):
            count += len(block)
            if count > before.st_size:
                raise ValueError("Compiler output grew while staging")
            output.write(block)
        if (count != before.st_size or _fingerprint(os.fstat(content.fileno())) != _fingerprint(before)
                or _fingerprint(Path(source).lstat()) != _fingerprint(before)):
            raise ValueError("Compiler output changed while staging")
    destination.chmod(0o755)
    if not _regular(destination.lstat()):
        raise ValueError("Staged compiler output is not single-link regular data")
    return destination


def _info(name, executable=False):
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.create_system = 3
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = (0o100755 if executable else 0o100644) << 16
    return info


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate distribution manifest field")
        value[key] = item
    return value


def _write(destination, entries, build_identity, executables):
    build_identity = identity(build_identity)
    if not isinstance(entries, dict) or not 0 < len(entries) <= MAX_FILES:
        raise ValueError("Distribution input count is invalid")
    names = [member_name(name) for name in entries]
    if (not isinstance(executables, (set, frozenset))
            or not executables <= set(names)):
        raise ValueError("Distribution executable inventory is invalid")
    if "manifest.json" in names or len({name.casefold() for name in names}) != len(names):
        raise ValueError("Distribution names collide or replace the manifest")
    rows, total = [], 0
    with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as output:
        for name in sorted(names):
            source, before = _open_input(entries[name])
            with source:
                total += before.st_size
                if total > MAX_TOTAL:
                    raise ValueError("Distribution inputs exceed their aggregate bound")
                digest, count = hashlib.sha256(), 0
                mode = 0o755 if name in executables or (
                    build_identity["kind"] == "runtime" and PurePosixPath(name).name in BINARY_NAMES) else 0o644
                with output.open(_info(name, mode == 0o755), "w") as target:
                    while block := source.read(BLOCK):
                        count += len(block)
                        if count > before.st_size:
                            raise ValueError("Distribution input grew during copy")
                        digest.update(block)
                        target.write(block)
                if (count != before.st_size or _fingerprint(os.fstat(source.fileno())) != _fingerprint(before)
                        or _fingerprint(Path(entries[name]).lstat()) != _fingerprint(before)):
                    raise ValueError("Distribution input changed during copy")
                rows.append({"path": name, "bytes": count, "sha256": digest.hexdigest(), "mode": mode})
        manifest = {"schema_version": 1, "stage": STAGE, "identity": build_identity, "files": rows}
        data = (json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
        if len(data) > MAX_MANIFEST:
            raise ValueError("Distribution manifest exceeds its bound")
        output.writestr(_info("manifest.json"), data)


def prepare(destination, entries, build_identity, *, executables=frozenset()):
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("Distribution destination already exists")
    # Publish a fully validated same-filesystem file without replacing any existing entry.
    with tempfile.TemporaryDirectory(prefix=".prepare-", dir=destination.parent) as temporary:
        staged = Path(temporary) / "archive.zip"
        _write(staged, entries, build_identity, executables)
        verify(staged)
        with staged.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        result = {"bytes": staged.stat().st_size, "sha256": digest}
        os.link(staged, destination)
    return result


def verify(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_TOTAL:
        raise ValueError("Distribution archive is missing, linked or oversized")
    with zipfile.ZipFile(path) as stream:
        items = stream.infolist()
        names = [member_name(item.filename) for item in items]
        if (not 1 < len(items) <= MAX_FILES + 1 or names.count("manifest.json") != 1
                or len({name.casefold() for name in names}) != len(names)):
            raise ValueError("Distribution archive member inventory is invalid")
        if (sum(item.file_size for item in items) > MAX_TOTAL + MAX_MANIFEST
                or any(item.flag_bits & 1 or item.is_dir() or not 0 <= item.file_size <= MAX_MEMBER
                       or item.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED} for item in items)):
            raise ValueError("Distribution archive member type or size is invalid")
        manifest_info = stream.getinfo("manifest.json")
        if (manifest_info.file_size > MAX_MANIFEST
                or manifest_info.external_attr >> 16 != 0o100644):
            raise ValueError("Distribution manifest size or regular-file mode is invalid")
        manifest = json.loads(stream.read("manifest.json").decode("utf-8"), object_pairs_hook=_pairs)
        if (not isinstance(manifest, dict) or set(manifest) != {"schema_version", "stage", "identity", "files"}
                or type(manifest["schema_version"]) is not int
                or manifest["schema_version"] != 1 or manifest["stage"] != STAGE):
            raise ValueError("Distribution manifest schema is invalid")
        identity(manifest["identity"])
        rows = manifest["files"]
        if not isinstance(rows, list) or not 0 < len(rows) <= MAX_FILES:
            raise ValueError("Distribution manifest member count is invalid")
        found = set()
        for row in rows:
            if not isinstance(row, dict) or set(row) != {"path", "bytes", "sha256", "mode"}:
                raise ValueError("Distribution manifest member is invalid")
            name = member_name(row["path"])
            if name == "manifest.json" or name in found or name not in names:
                raise ValueError("Distribution manifest member inventory differs")
            found.add(name)
            item = stream.getinfo(name)
            if (type(row["bytes"]) is not int or row["bytes"] != item.file_size
                    or type(row["mode"]) is not int or row["mode"] not in {0o644, 0o755}
                    or item.external_attr >> 16 != stat.S_IFREG | row["mode"]
                    or not isinstance(row["sha256"], str)
                    or re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) is None):
                raise ValueError("Distribution member metadata differs")
            with stream.open(item) as content:
                digest = hashlib.file_digest(content, "sha256").hexdigest()
            if digest != row["sha256"]:
                raise ValueError("Distribution member digest differs")
        if found | {"manifest.json"} != set(names):
            raise ValueError("Distribution archive contains an unlisted member")
        return manifest


def extract(package, destination, expected):
    """Extract verified regular members into a new directory, without the archive manifest."""
    manifest = verify(package)
    if manifest["identity"] != identity(expected):
        raise ValueError("Extracted archive identity differs")
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("Archive extraction destination already exists")
    destination.mkdir()
    with zipfile.ZipFile(package) as stream:
        for row in manifest["files"]:
            path = destination / row["path"]
            path.parent.mkdir(parents=True, exist_ok=True)
            digest, count = hashlib.sha256(), 0
            with stream.open(row["path"]) as source, path.open("xb") as output:
                while block := source.read(BLOCK):
                    count += len(block)
                    if count > row["bytes"]:
                        raise ValueError("Archive member exceeds its verified length")
                    digest.update(block)
                    output.write(block)
            if count != row["bytes"] or digest.hexdigest() != row["sha256"]:
                raise ValueError("Extracted archive member differs from verified bytes")
            path.chmod(row["mode"])
    return manifest
