# SPDX-License-Identifier: GPL-3.0-or-later
"""CI-only locked dependency/license audit using the existing bounded process owner."""

import hashlib
import importlib.util
import os
from pathlib import Path
import platform
import shutil
import signal
import sys
import tarfile
import time
import urllib.parse
import urllib.request
import uuid
import zipfile

VERSION = "0.20.2"
PREFIX = f"cargo-deny-{VERSION}-x86_64-unknown-linux-musl"
URL = f"https://github.com/EmbarkStudios/cargo-deny/releases/download/{VERSION}/{PREFIX}.tar.gz"
SHA256 = "9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f"
ARCHIVE_BYTES = 4_936_832
MAX_MEMBER = 32 * 1024 * 1024
MEMBERS = frozenset({"cargo-deny", "README.md", "LICENSE-APACHE", "LICENSE-MIT"})


class ReleaseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        target = urllib.parse.urlsplit(new_url)
        if (target.scheme != "https" or target.hostname not in
                {"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}
                or target.username is not None or target.password is not None
                or target.port not in {None, 443}):
            raise ValueError("Dependency tool download redirected outside its approved hosts")
        return super().redirect_request(request, fp, code, message, headers, new_url)


def download(destination):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), ReleaseRedirect())
    request = urllib.request.Request(URL, headers={"User-Agent": "native-dependency-ci"})
    digest, size = hashlib.sha256(), 0
    deadline = time.monotonic() + 120
    with opener.open(request, timeout=20) as response, destination.open("xb") as output:
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError("Dependency tool download exceeded its deadline")
            block = response.read(1024 * 1024)
            if not block:
                break
            size += len(block)
            if size > ARCHIVE_BYTES:
                raise ValueError("Dependency tool archive exceeds its pinned size")
            digest.update(block)
            output.write(block)
    if size != ARCHIVE_BYTES or digest.hexdigest() != SHA256:
        raise ValueError("Dependency tool archive differs from its pinned bytes")


def extract(archive, directory):
    """Validate the complete pinned archive before exposing its sole executable."""
    with tarfile.open(archive, mode="r:gz") as stream:
        found, total, count, root_seen = {}, 0, 0, False
        for member in stream:
            count += 1
            if count > len(MEMBERS) + 1:
                raise ValueError("Dependency tool archive has extra entries")
            if member.name.rstrip("/") == PREFIX and member.isdir() and not root_seen:
                root_seen = True
                continue
            name = member.name.removeprefix(PREFIX + "/")
            if (member.name != PREFIX + "/" + name or name not in MEMBERS or name in found
                    or not member.isfile() or member.linkname or member.sparse
                    or not 0 < member.size <= MAX_MEMBER or member.mode & 0o7000):
                raise ValueError("Dependency tool archive has an unsafe or unexpected member")
            total += member.size
            if total > 2 * MAX_MEMBER:
                raise ValueError("Dependency tool archive exceeds its expanded size bound")
            found[name] = member
        if set(found) != MEMBERS:
            raise ValueError("Dependency tool archive omits its executable or notices")
        destination = directory / "cargo-deny"
        member = found["cargo-deny"]
        source = stream.extractfile(member)
        if source is None:
            raise ValueError("Dependency tool member is unreadable")
        created = False
        try:
            with source, destination.open("xb") as output:
                created = True
                remaining = member.size
                while remaining:
                    block = source.read(min(1024 * 1024, remaining))
                    if not block:
                        raise ValueError("Dependency tool member is truncated")
                    output.write(block)
                    remaining -= len(block)
                if source.read(1):
                    raise ValueError("Dependency tool member exceeds its declared size")
            destination.chmod(0o700)
        except BaseException:
            if created:
                destination.unlink()
            raise
    return destination


def check(root, binary, environment, command, log, memory):
    lock = root / "Cargo.lock"
    before = hashlib.sha256(lock.read_bytes()).hexdigest()
    code, stdout, _ = command([binary, "--version"], "dependency-audit-version", environment, log,
                              wall=20, idle=10, memory_mib=memory)
    if code:
        return code
    if stdout.decode("ascii", errors="strict").strip() != f"cargo-deny {VERSION}":
        raise ValueError("Dependency audit tool version differs from its pin")
    code, _, _ = command([binary, "--locked", "--manifest-path", str(root / "Cargo.toml"),
                          "--config", str(root / "deny.toml"), "--color", "never", "check",
                          "advisories", "licenses", "sources"],
                         "dependency-audit-check", environment, log,
                         wall=600, idle=120, memory_mib=memory)
    if hashlib.sha256(lock.read_bytes()).hexdigest() != before:
        raise ValueError("Dependency audit changed the application lockfile")
    if code == 0:
        log.event("INFO", "Locked dependency, license and source checks passed",
                  tool_version=VERSION, lock_sha256=before, targets="full graph")
    return code


def main():
    if (os.environ.get("GITHUB_ACTIONS") != "true" or sys.platform != "linux"
            or platform.machine().lower() not in {"x86_64", "amd64"}):
        print("Dependency audit setup requires the owned GitHub Linux x86_64 job.", file=sys.stderr)
        return 125
    here = Path(__file__).resolve().parent
    if sys.argv[1:2] == ["--acquire"]:
        if len(sys.argv) != 3:
            raise ValueError("Dependency acquisition needs its owned work directory")
        work = Path(sys.argv[2]).resolve()
        allowed = here.parents[1] / ".ci-work" / "dependency-audit"
        if not work.is_relative_to(allowed) or work == allowed:
            raise ValueError("Dependency acquisition must stay in its owned work directory")
        archive = work / "download" / (PREFIX + ".tar.gz")
        download(archive)
        extract(archive, work / "tool")
        return 0
    if len(sys.argv) != 1:
        raise ValueError("Dependency audit arguments are unsupported")
    sys.path.insert(0, str(here))
    spec = importlib.util.spec_from_file_location("native_audit_owner", here / "run-native.py")
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    runner.RUN_DEADLINE = time.monotonic() + 1600
    work = runner.ROOT / ".ci-work" / "dependency-audit" / uuid.uuid4().hex
    work.mkdir(parents=True)
    try:
        log = runner.RunLog(work)
    except OSError:
        print("Dependency audit logging initialization failed; no log file was claimed.", file=sys.stderr)
        return 125
    previous, code = {}, 125
    def canceled(signum, frame):
        for owned in previous:
            signal.signal(owned, signal.SIG_IGN)
        raise KeyboardInterrupt
    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.signal(signum, canceled)
        runner.LINUX_SUBREAPER = runner.enable_linux_subreaper()
        workers, memory = runner.worker_budget()
        environment = runner.environment(work, workers)
        pinned = runner.tomllib.loads((runner.ROOT / "rust-toolchain.toml").read_text(encoding="utf-8"))
        if pinned["toolchain"]["channel"] != runner.TOOLCHAIN:
            raise ValueError("Dependency audit toolchain differs from the project pin")
        code, stdout, _ = runner.command(["git", "rev-parse", "HEAD"], "audit-candidate-identity",
                                          environment, log, wall=15, idle=5, memory_mib=memory)
        if code:
            raise ValueError("Dependency audit candidate identity could not be read")
        current = runner.evidence.identity(os.environ, stdout.decode("ascii", errors="strict").strip())
        code, stdout, _ = runner.command(["git", "status", "--porcelain", "--untracked-files=no"],
                                          "audit-candidate-clean", environment, log,
                                          wall=15, idle=5, memory_mib=memory)
        if code or stdout.strip():
            raise ValueError("Dependency audit tracked files differ from the dispatched commit")
        log.event("INFO", "Dependency audit starting", tool_version=VERSION, workers=workers,
                  commit=current["commit"])
        rustup = shutil.which("rustup", path=environment.get("PATH"))
        if rustup is None:
            raise OSError("Hosted Rustup prerequisite is missing")
        code, stdout, _ = runner.command([rustup, "--version"], "audit-rustup-prerequisite",
                                          environment, log, wall=30, idle=15, memory_mib=memory)
        version = runner.re.match(rb"rustup ([0-9]+)\.([0-9]+)\.([0-9]+)", stdout)
        if code or version is None or tuple(map(int, version.groups())) < (1, 29, 0):
            raise ValueError("Dependency audit requires hosted Rustup >=1.29.0")
        code, _, _ = runner.command([rustup, "toolchain", "install", runner.TOOLCHAIN,
                                     "--profile", "minimal", "--no-self-update"],
                                    "audit-rust-toolchain", environment, log,
                                    wall=300, idle=120, memory_mib=memory)
        if code == 0:
            incoming, tools = work / "download", work / "tool"
            incoming.mkdir()
            tools.mkdir()
            code, _, _ = runner.command([sys.executable, "-I", "-B", str(Path(__file__).resolve()),
                                          "--acquire", str(work)],
                                         "dependency-audit-acquire", dict(environment, GITHUB_ACTIONS="true"), log,
                                         wall=150, idle=45, memory_mib=memory)
            if code == 0:
                code = check(runner.ROOT, tools / "cargo-deny", environment, runner.command, log, memory)
    except KeyboardInterrupt:
        code = 130
        log.event("ERROR", "Dependency audit interrupted")
    except (OSError, ValueError, KeyError, EOFError, tarfile.TarError,
            zipfile.BadZipFile, zipfile.LargeZipFile) as error:
        code = 125
        log.event("ERROR", "Dependency audit prerequisite or integrity check failed",
                  diagnostic=type(error).__name__)
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
        try:
            log.event("INFO" if code == 0 else "ERROR", "Dependency audit finished", exit_code=code,
                      source_bundle="separate gate", signing="separate gate")
        finally:
            log.close()
    return code if code >= 0 else 128-code


if __name__ == "__main__":
    sys.exit(main())
