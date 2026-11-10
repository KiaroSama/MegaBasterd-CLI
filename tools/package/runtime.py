# SPDX-License-Identifier: GPL-3.0-or-later
"""Prepare and smoke CI compiler intermediates, never sign/publish a final release."""

from pathlib import Path
import shutil
import tempfile
import tomllib

from archive import extract, identity, prepare, verify
from dependencies import prepare_dependencies
from notices import notice_entries
from rebuild import rebuild

ALIASES = ("mb", "mbcli", "megabasterd-cli")
RUNTIME_KEYS = {"SystemRoot", "WINDIR", "PATHEXT", "HOME", "USERPROFILE", "APPDATA",
                "LOCALAPPDATA", "TMP", "TEMP", "TMPDIR", "PATH", "NO_COLOR", "HOOKMAKER_MAX_TEST_WORKERS"}


def runtime_environment(home, environment):
    empty_path = home / "empty executable search path"
    empty_path.mkdir(exist_ok=True)
    runtime = {key: environment[key] for key in ("SystemRoot", "WINDIR", "PATHEXT") if key in environment}
    runtime.update({key: str(home) for key in ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
                                             "TMP", "TEMP", "TMPDIR")})
    runtime.update({"PATH": str(empty_path), "NO_COLOR": "1", "HOOKMAKER_MAX_TEST_WORKERS": "1"})
    return runtime


def smoke(paths, build, cwd, home, environment, command, log, memory):
    runtime = runtime_environment(home, environment)
    for name, binary in paths.items():
        for case, arguments in [("version", ["--version"]), ("help", ["--help"]),
                                ("invalid", ["--not-a-real-option"]), ("eof", []),
                                ("setting", ["--no-log-file", "config", "get", "max_workers"]),
                                ("path", ["--no-log-file", "config", "path"])]:
            code, stdout, stderr = command([binary, *arguments], f"relocated-{name}-{case}", runtime, log,
                                           wall=15, idle=5, memory_mib=memory, cwd=cwd)
            expected_code = 2 if case in {"invalid", "eof"} else 0
            if code != expected_code or b"\x1b" in stdout + stderr:
                raise ValueError("Relocated runtime command status or plain output differs")
            if case == "version" and (stdout != f"mb {build['version']}\n".encode("ascii") or stderr):
                raise ValueError("Relocated runtime version differs")
            if case == "help" and (stderr or not all(text in stdout for text in (b"Usage:", b"download", b"--help"))):
                raise ValueError("Relocated runtime help is incomplete")
            if case == "invalid" and (stdout or b"[ERROR]" not in stderr):
                raise ValueError("Relocated runtime invalid option is not refused cleanly")
            if case == "eof" and (stdout or stderr !=
                    b"[ERROR] No command provided. Use mb --help in noninteractive mode.\n"):
                raise ValueError("Relocated runtime noninteractive EOF differs")
            if case == "setting" and (stdout != b"8\n" or stderr):
                raise ValueError("Relocated runtime default configuration differs")
            if case == "path":
                if stderr or stdout.count(b"\n") != 1:
                    raise ValueError("Relocated runtime configuration path output differs")
                path = Path(stdout.decode("utf-8", errors="strict").strip()).resolve()
                if path != (binary.parent / "User/native-v2/Config/config.json").resolve():
                    raise ValueError("Relocated runtime depends on its build or caller directory")
    if any(cwd.iterdir()) or set(paths) != set(ALIASES):
        raise ValueError("Relocated runtime polluted the caller or omitted an alias")


def smoke_launcher(release, build, cwd, home, environment, command, log, memory):
    if build["target"] != "x86_64-pc-windows-msvc":
        return
    shell = next((found for name in ("pwsh.exe", "powershell.exe")
                  if (found := shutil.which(name, path=environment.get("PATH", "")))), None)
    if shell is None or not Path(shell).is_absolute():
        raise ValueError("Packaged Windows launcher requires an installed PowerShell host")
    launcher = release / "Run.ps1"
    if not launcher.is_file():
        raise ValueError("Packaged Windows launcher is absent")
    runtime = runtime_environment(home, environment)
    value = "launcher  literal & [safe]"
    for case, arguments in [
            ("version", ["--version"]), ("invalid", ["--not-a-real-option"]),
            ("path", ["--no-log-file", "config", "path"]),
            ("set", ["--no-log-file", "config", "set", "download_path", value]),
            ("get", ["--no-log-file", "config", "get", "download_path"])]:
        code, stdout, stderr = command(
            [Path(shell), "-NoLogo", "-NoProfile", "-NonInteractive", "-File", launcher, *arguments],
            "packaged-launcher-" + case, runtime, log, wall=15, idle=5, memory_mib=memory, cwd=cwd)
        stdout, stderr = (stream.replace(b"\r\n", b"\n") for stream in (stdout, stderr))
        if code != (2 if case == "invalid" else 0) or b"\x1b" in stdout + stderr:
            raise ValueError("Packaged Windows launcher status or plain output differs")
        if case == "version" and (stdout != f"mb {build['version']}\n".encode("ascii") or stderr):
            raise ValueError("Packaged Windows launcher version differs")
        if case == "invalid" and (stdout or b"[ERROR]" not in stderr):
            raise ValueError("Packaged Windows launcher did not preserve native refusal")
        if case == "path":
            expected = release / "User/native-v2/Config/config.json"
            if (stderr or stdout.count(b"\n") != 1
                    or Path(stdout.decode("utf-8", errors="strict").strip()).resolve() != expected.resolve()):
                raise ValueError("Packaged Windows launcher used the caller or build directory")
        if case == "set" and (stdout or stderr != b"[INFO] Configuration setting saved.\n"):
            raise ValueError("Packaged Windows launcher configuration write differs")
        if case == "get" and (stdout != (value + "\n").encode("utf-8") or stderr):
            raise ValueError("Packaged Windows launcher changed literal argument boundaries")
    if any(cwd.iterdir()):
        raise ValueError("Packaged Windows launcher polluted the caller directory")


def prepare_runtime(root, current, target, cargo, environment, command, log, workers, memory, *, project_archive):
    version = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))["package"]["version"]
    build = identity({"version": version, "commit": current["commit"], "target": target, "kind": "runtime"})
    base = root / ".ci-work" / "runtime-intermediate" / target
    base.mkdir(parents=True)
    dependency_archive, _ = prepare_dependencies(root, base, current, target, cargo, environment, command, log, memory)
    package = base / f"megabasterd-cli-{version}-{current['commit'][:12]}-{target}-UNSIGNED-INTERMEDIATE.zip"
    with tempfile.TemporaryDirectory(prefix="source rebuild ", dir=base) as temporary:
        project, binaries = rebuild(project_archive, dependency_archive, Path(temporary),
            {**build, "kind": "source"}, cargo, environment, command, log, workers, memory)
        entries = dict(binaries)
        for name in ("README.md", "LICENSE", "ATTRIBUTION.md", "licenses/MIT-historical.txt", "licenses/Unicode-3.0.txt"):
            entries[name] = project / name
        suffix = ".exe" if target == "x86_64-pc-windows-msvc" else ""
        if suffix:
            entries["Run.ps1"] = project / "tools/launcher/Run.Native.ps1"
        notices, notice_hashes = notice_entries(project, Path(temporary) / "dependency notices", build)
        entries.update(notices)
        report = prepare(package, entries, build)
        manifest = verify(package)
        if {row["path"] for row in manifest["files"]} != set(entries):
            raise ValueError("Runtime compiler intermediate inventory differs")
        archived_notices = {row["path"]: row["sha256"] for row in manifest["files"]
                            if row["path"] in notice_hashes}
        if archived_notices != notice_hashes:
            raise ValueError("Runtime dependency notice bytes differ from locked sources")
        scratch = Path(temporary) / "runtime smoke"
        scratch.mkdir()
        release, cwd, home = scratch / "native with spaces", scratch / "unrelated caller", scratch / "home"
        cwd.mkdir()
        home.mkdir()
        extract(package, release, build)
        smoke({name: release / (name + suffix) for name in ALIASES}, build, cwd, home,
              environment, command, log, memory)
        smoke_launcher(release, build, cwd, home, environment, command, log, memory)
    log.event("INFO", "Optimized compiler intermediate relocated smoke passed", target=target,
              version=version, commit=current["commit"], bytes=report["bytes"], sha256=report["sha256"],
              release_ready=False, signing="missing; not for publication", dependency_notices="preserved; legal review required")
    return package, report
