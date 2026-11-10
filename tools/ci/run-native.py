# SPDX-License-Identifier: GPL-3.0-or-later
"""Native CI: python -I tools/ci/run-native.py --target <triple> --baseline <checkout>."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid

if sys.version_info < (3, 11):
    print("Native CI requires Python >=3.11 for stdlib tomllib; use the hosted image tooling.", file=sys.stderr)
    sys.exit(125)
import tomllib

# -I excludes implicit script/CWD imports; add only the reviewed CI and package tooling.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from native_process import UnixTree, WindowsJob, available_memory, enable_linux_subreaper
from coverage_contract import BASELINE, load_inputs, reconcile_coverage, require_report
from media_toolchain import prepare as prepare_media, verify as verify_media
import native_evidence as evidence
from retirement_approvals import load as load_retirement_approvals
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "package"))
from source import prepare_project_source
from runtime import prepare_runtime

ROOT = Path(__file__).resolve().parents[2]
TOOLCHAIN = "1.99.1"
MAX_OUTPUT = 32 * 1024 * 1024
RUN_DEADLINE = None
LINUX_SUBREAPER = False


class RunLog:
    def __init__(self, directory):
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S_UTC")
        self.stream = (directory / f"run-native_{stamp}_{uuid.uuid4().hex}.log").open(
            "x", encoding="utf-8", newline="\n")

    def event(self, level, message, **fields):
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        details = " ".join(f"{key}={json.dumps(value, ensure_ascii=True)}"
                           for key, value in fields.items())
        line = f"[{stamp}] [{level}] [CI] {message} {details}".rstrip()
        self.stream.write(line + "\n")
        self.stream.flush()
        print(line, flush=True)

    def close(self):
        self.stream.close()


def guardian(arguments):
    # The one-byte gate is released ONLY after the parent assigns this guardian to its job.
    if sys.stdin.buffer.read(1) != b"G":
        return 125
    sys.stdin.close()
    child = subprocess.Popen(arguments, shell=False, stdin=subprocess.DEVNULL,
                             creationflags=subprocess.CREATE_NO_WINDOW, close_fds=True)
    return child.wait(timeout=3600)


def failure_diagnostics(output, label, log):
    # Only source/compiler identifiers and fixed categories leave RAM. Never display source,
    # panic/assertion operands, URLs, arbitrary paths, argv or environment values.
    categories = {"E0061": "Function argument count differs", "E0277": "Required trait is not implemented",
                  "E0282": "Type annotation required", "E0308": "Types differ", "E0382": "Value moved before use",
                  "E0425": "Value or function not found", "E0432": "Import unresolved", "E0433": "Path unresolved",
                  "E0502": "Borrow conflict", "E0599": "Method or associated item unavailable",
                  "E0609": "Field unavailable", "E0658": "Unstable feature used"}
    found = set()
    for index, line in enumerate(output[:1024*1024].splitlines()):
        code = re.fullmatch(rb"error\[(E[0-9]{4})\]:.*", line)
        if code:
            key = code.group(1).decode("ascii")
            found.add(("compiler", key, categories.get(key, "Rust compiler error; inspect reported source location")))
        heading = re.fullmatch(rb"(?:error|warning): ([a-z ]+)", line)
        if heading and heading.group(1) in {b"unused import", b"unused imports", b"unused variable",
                b"unused variables", b"unreachable expression", b"unreachable statement",
                b"unreachable pattern", b"mismatched closing delimiter", b"unexpected closing delimiter"}:
            found.add(("compiler", "heading", heading.group(1).decode("ascii")))
        lint = re.search(rb"clippy::([a-z_]+)", line)
        if lint:
            found.add(("clippy", lint.group(1).decode("ascii"), "Clippy lint rejected the candidate"))
        panic = re.match(rb"thread '[A-Za-z0-9_:.-]+' panicked at ((?:src|tests)/[A-Za-z0-9_./-]+\.rs:[0-9]+:[0-9]+):?", line)
        if panic:
            found.add(("test", panic.group(1).decode("ascii"), "Assertion/panic at source location"))
        for marker, category in [(b"failed to get ", "Dependency resolution failed"),
                (b"failed to download ", "Dependency download failed"),
                (b"failed to select a version", "Dependency version/feature selection failed"),
                (b"linking with ", "Native linking failed"), (b"linker ", "Native linker unavailable or failed")]:
            if line.startswith(b"error: ") and marker in line:
                found.add(("prerequisite", "category", category))
        if line.strip() == b"Diff in" or line.startswith(b"Diff in "):
            found.add(("format", "category", "Formatting differs; run cargo fmt before final candidate"))
        if index >= 8192:
            break
    for kind, identifier, message in sorted(found)[:32]:
        log.event("ERROR", message, command=label, kind=kind, identifier=identifier)
    if not found:
        log.event("ERROR", "Raw failure payload suppressed; use validated test/compiler location",
                  command=label)


def command(argv, label, environment, log, *, wall, idle, memory_mib, cwd=ROOT):
    if not re.fullmatch(r"[a-zA-Z0-9_.-]+", label) or wall <= 0 or idle <= 0 or memory_mib <= 0:
        raise ValueError("Invalid CI command bounds or label")
    if RUN_DEADLINE is not None:
        wall = min(wall, RUN_DEADLINE-time.monotonic()-15)
        if wall <= 0:
            log.event("ERROR", "Whole-run deadline exhausted", command=label)
            return 124, b"", b""
    started, last_progress = time.monotonic(), time.monotonic()
    child, owner = None, None
    readers, captures = [], {"stdout": bytearray(), "stderr": bytearray()}
    events = queue.Queue(maxsize=64)
    stop_readers = threading.Event()
    reason, code, last_cpu, next_sample = "exit", 125, 0.0, 0.0
    timed = False
    last_test = None
    monitor_state = {"processes": 0, "cpu": 0, "memory": 0}
    ignored_test = False
    capture_error = threading.Event()
    parse_tail = {"stdout": b"", "stderr": b""}
    log.event("INFO", "Command starting", command=label, wall_seconds=wall,
              idle_seconds=idle, memory_mib=memory_mib)

    def drain(pipe, name):
        try:
            while not stop_readers.is_set():
                block = os.read(pipe.fileno(), 8192)
                if not block:
                    break
                while not stop_readers.is_set():
                    try:
                        events.put((name, block), timeout=0.1)
                        break
                    except queue.Full:
                        continue
        except (OSError, ValueError):
            capture_error.set()
            while not stop_readers.is_set():
                try:
                    events.put(("error", b""), timeout=0.1)
                    break
                except queue.Full:
                    continue
        finally:
            try:
                pipe.close()
            except OSError:
                capture_error.set()

    def consume(name, block):
        nonlocal last_progress, last_test, ignored_test
        if name == "error":
            raise OSError("CI stream capture failed")
        if len(captures[name]) + len(block) > MAX_OUTPUT:
            raise OSError("CI command output exceeded its bound")
        captures[name].extend(block)
        last_progress = time.monotonic()
        # Never echo raw child output/argv/env: only validated test names and code locations.
        data = parse_tail[name] + block
        lines = data.split(b"\n")
        parse_tail[name] = lines.pop()[-1024:]
        for line in lines:
            # Native suites use their separate libtest result file, never application streams.
            if label == "doctests":
                summary = re.fullmatch(rb"test result: .*; ([0-9]+) ignored;.*\r?", line)
                if summary:
                    ignored_test |= int(summary.group(1)) != 0
                test = re.fullmatch(rb"test ([A-Za-z0-9_:./() -]+) \.\.\. (ok|FAILED|ignored)\r?", line)
                if test:
                    last_test = test.group(1).decode("ascii")
                    ignored_test |= test.group(2) == b"ignored"
            location = re.fullmatch(rb"\s*--> ((?:src|tests)/[A-Za-z0-9_./-]+\.rs:[0-9]+:[0-9]+)\r?", line)
            if location:
                log.event("INFO", "Compiler location", command=label,
                          location=location.group(1).decode("ascii"))

    try:
        executable = shutil.which(str(argv[0]), path=environment.get("PATH"))
        if executable is None:
            raise OSError("CI command executable is unavailable")
        argv = [executable, *map(str, argv[1:])]
        options = dict(cwd=cwd, env=environment, shell=False,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        if os.name == "nt":
            owner = WindowsJob(memory_mib)
            child = subprocess.Popen([sys.executable, "-I", str(Path(__file__).resolve()),
                                      "--guardian", "--", *argv], stdin=subprocess.PIPE,
                                     creationflags=subprocess.CREATE_NO_WINDOW, **options)
            log.event("INFO", "Gated guardian owned", command=label, pid=child.pid)
            owner.assign(child.pid)
            child.stdin.write(b"G")
            child.stdin.close()
        else:
            child = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                                     start_new_session=True, **options)
            log.event("INFO", "Native session owned", command=label, pid=child.pid)
            owner = UnixTree(child.pid)
            owner.reap_adopted = LINUX_SUBREAPER
        for name, pipe in [("stdout", child.stdout), ("stderr", child.stderr)]:
            reader = threading.Thread(target=drain, args=(pipe, name), daemon=True)
            reader.start()
            readers.append(reader)
        while True:
            if capture_error.is_set():
                raise OSError("CI stream capture failed")
            now = time.monotonic()
            if now >= next_sample:
                state = owner.sample()
                if (state["cpu"] > last_cpu + 0.02 or state["processes"] != monitor_state["processes"]
                        or state["memory"] > monitor_state["memory"] + 1024*1024):
                    last_progress = now
                monitor_state = state
                last_cpu = state["cpu"]
                next_sample = now + 1
                log.event("INFO", "Owned resource sample", command=label,
                          elapsed_seconds=round(now-started, 2),
                          idle_seconds=round(now-last_progress, 2), last_test=last_test,
                          processes=state["processes"], zombies=state.get("zombies", 0),
                          cpu_seconds=round(last_cpu, 2),
                          memory_mib=state["memory"] // (1024*1024))
                if state["memory"] > memory_mib * 1024 * 1024:
                    reason, code, timed = "memory", 124, True
                    break
            if now-started >= wall or now-last_progress >= idle:
                reason, code, timed = ("wall" if now-started >= wall else "idle"), 124, True
                break
            status = child.poll()
            if status is not None:
                owner.stop()
                if not any(reader.is_alive() for reader in readers) and events.empty():
                    code = status
                    break
            try:
                name, block = events.get(timeout=min(0.1, wall-(now-started), idle-(now-last_progress)))
                consume(name, block)
            except queue.Empty:
                pass
    except (OSError, ValueError, subprocess.SubprocessError):
        reason, code = "infrastructure", 125
        log.event("ERROR", "Command infrastructure failed", command=label)
    finally:
        # Kill even after success: descendants may have closed pipes and survived their parent.
        cleanup_ok = True
        try:
            if owner is not None:
                owner.stop()
            if owner is None and child is not None:
                if os.name != "nt":
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                elif child.poll() is None:
                    child.kill()
            elif os.name == "nt" and child is not None and child.poll() is None:
                # Also handles guardian-assignment failure before it entered the job.
                child.kill()
            deadline = time.monotonic() + 10
            if child is not None:
                actual = child.wait(timeout=max(0.001, deadline-time.monotonic()))
                if reason == "exit" and not timed:
                    code = actual
            while owner is not None and owner.sample()["processes"]:
                if time.monotonic() >= deadline:
                    raise OSError("CI child cleanup did not converge")
                owner.stop()
                # Deadline-bound native liveness polling; no readiness or arbitrary fixed sleep.
                threading.Event().wait(min(0.05, deadline-time.monotonic()))
        except (OSError, subprocess.SubprocessError):
            cleanup_ok = False
        finally:
            if owner is not None:
                try:
                    owner.close()
                except OSError:
                    cleanup_ok = False
        drain_deadline = time.monotonic() + 3
        while (any(reader.is_alive() for reader in readers) or not events.empty()) and time.monotonic() < drain_deadline:
            try:
                name, block = events.get(timeout=0.05)
                consume(name, block)
            except queue.Empty:
                pass
            except (OSError, ValueError):
                cleanup_ok = False
                stop_readers.set()
        stop_readers.set()
        for reader in readers:
            reader.join(timeout=0.1)
            cleanup_ok &= not reader.is_alive()
        if child is not None:
            for pipe in (child.stdout, child.stderr):
                if pipe is not None and not pipe.closed and not any(reader.is_alive() for reader in readers):
                    pipe.close()
        if child is not None and child.stdin is not None and not child.stdin.closed:
            child.stdin.close()
        if capture_error.is_set():
            reason, code = "capture", 125
        if ignored_test and code == 0:
            reason, code = "ignored-test", 1
        if not cleanup_ok:
            reason, code = "cleanup", 125
        log.event("INFO" if code == 0 else "ERROR", "Command finished", command=label,
                  exit_code=code, reason=reason, elapsed_seconds=round(time.monotonic()-started, 2),
                  cleanup="complete" if cleanup_ok else "unverified", last_test=last_test,
                  stdout_bytes=len(captures["stdout"]), stderr_bytes=len(captures["stderr"]),
                  stdout_sha256=hashlib.sha256(captures["stdout"]).hexdigest(),
                  stderr_sha256=hashlib.sha256(captures["stderr"]).hexdigest())
        if code != 0 and label not in {"runner-exit", "runner-idle", "runner-wall"}:
            failure_diagnostics(bytes(captures["stdout"]) + b"\n" + bytes(captures["stderr"]), label, log)
    return code, bytes(captures["stdout"]), bytes(captures["stderr"])


def environment(work, workers):
    # Toolchain/build prerequisites only; never inherit GITHUB_TOKEN/account/credential variables.
    allowed = {"PATH", "HOME", "USERPROFILE", "SystemRoot", "WINDIR", "COMSPEC", "PATHEXT",
               "RUSTUP_HOME", "CARGO_HOME", "INCLUDE", "LIB", "LIBPATH", "VCINSTALLDIR",
               "VSINSTALLDIR", "VCToolsInstallDir", "WindowsSdkDir", "SDKROOT",
               "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "SYSTEMDRIVE", "MEGABASTERD_FFMPEG"}
    current = {key.upper(): value for key, value in os.environ.items()}
    result = {name: current[name.upper()] for name in allowed if name.upper() in current}
    temporary = work / "temp"
    temporary.mkdir()
    result.update({"TMP": str(temporary), "TEMP": str(temporary), "TMPDIR": str(temporary),
                   "MEGABASTERD_PROJECT_ROOT": str(work / "runtime space"),
                   "MEGABASTERD_USER_DIR": str(work / "runtime space" / "User"),
                   "MEGABASTERD_LOG_DIR": str(work / "runtime space" / "Logs"),
                   "CARGO_TARGET_DIR": str(ROOT / ".ci-work" / "target"),
                   "CARGO_BUILD_BUILD_DIR": str(ROOT / ".ci-work" / "build"),
                   "CARGO_BUILD_JOBS": str(workers), "RUST_TEST_THREADS": str(workers),
                   "HOOKMAKER_MAX_TEST_WORKERS": str(workers), "RAYON_NUM_THREADS": str(workers),
                   "OMP_NUM_THREADS": "1", "CARGO_NET_RETRY": "0", "CARGO_HTTP_TIMEOUT": "30",
                   "CARGO_TERM_COLOR": "never", "RUST_BACKTRACE": "0", "PYTHONUTF8": "1",
                   "PYTHONDONTWRITEBYTECODE": "1"})
    return result


def worker_budget():
    requested = int(os.environ.get("HOOKMAKER_MAX_TEST_WORKERS", "2"))
    if requested < 1:
        raise ValueError("CI shared worker ceiling must be positive")
    memory = available_memory()
    workers = max(1, min(requested, 2, max(1, (os.cpu_count() or 1)-1),
                         max(1, (memory-1024**3)//(2*1024**3))))
    return workers, max(512, min(4096, (memory-512*1024**2)//1024**2))


def inventory(metadata, log):
    manifest = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    declarations = [manifest.get("lib", {}), *manifest.get("bin", []),
                    *manifest.get("test", []), *manifest.get("bench", []), *manifest.get("example", [])]
    if manifest.get("package", {}).get("autotests", True) is False or any(
            value.get("harness", True) is False for value in declarations):
        raise ValueError("Disabled/custom Rust test harness needs an explicit CI contract")
    package = next(value for value in metadata["packages"]
                   if Path(value["manifest_path"]).resolve() == ROOT / "Cargo.toml")
    if len(metadata["workspace_members"]) != 1:
        raise ValueError("CI suite guard needs explicit multi-package workspace ownership")
    targets = package["targets"]
    discovered = {path.resolve() for path in (ROOT / "tests").glob("*.rs")}
    discovered.update(path.resolve() for path in (ROOT / "tests").glob("*/main.rs"))
    active = {Path(target["src_path"]).resolve() for target in targets if "test" in target["kind"]}
    if discovered != active:
        log.event("ERROR", "Rust disk suites and Cargo targets differ", disk_suites=len(discovered),
                  active_suites=len(active), missing_targets=len(discovered-active),
                  unexpected_targets=len(active-discovered))
        raise ValueError("Rust disk suites and Cargo integration targets differ")
    for target in targets:
        if "custom-build" not in target["kind"] and not target["test"]:
            raise ValueError("A Cargo target disables required native tests")
        if "lib" in target["kind"] and not target["doctest"]:
            raise ValueError("Cargo library disables doctests")
    for path in [*(ROOT / "src").rglob("*.rs"), *(ROOT / "tests").rglob("*.rs")]:
        text = path.read_text(encoding="utf-8", errors="strict")
        if len(text.splitlines()) > 800:
            raise ValueError("Rust source/test file exceeds the800line ceiling")
        if re.search(r"#\s*\[\s*ignore(?:\s|\(|\])", text) or re.search(
                r"#\s*\[\s*cfg_attr\s*\([^\]]*\bignore\b", text):
            raise ValueError("Ignored Rust test requires an explicit coverage decision")
    for path in [ROOT / "Cargo.toml", ROOT / "Cargo.lock", ROOT / "rust-toolchain.toml",
                 ROOT / ".github/workflows/ci.yml", *(ROOT / "tools/ci").glob("*.py")]:
        path.read_text(encoding="utf-8", errors="strict")
    log.event("INFO", "Cargo suite inventory verified", integration_suites=len(active),
              target_count=len(targets), doctests="separate --doc command", source_oracle="not claimed")
    return [target["name"] for target in targets if "bin" in target["kind"]]


def fixture(mode):
    if mode == "exit":
        return 7
    if mode == "stdin":
        assert sys.stdin.buffer.read() == b""
        return 0
    if mode == "native-output":
        for stream in (sys.stdout, sys.stderr):
            print("test application_text ... ignored", file=stream)
            print("test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out", file=stream)
        return 0
    if mode == "flood":
        for _ in range(64):
            sys.stdout.buffer.write(b"o" * 8192)
            sys.stderr.buffer.write(b"e" * 8192)
        return 0
    if mode == "descendant":
        options = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {"process_group": 0}
        subprocess.Popen([sys.executable, "-I", str(Path(__file__).resolve()), "--fixture", "wait"],
                         stdin=subprocess.DEVNULL, **options)
        return 0
    if mode == "wait":
        threading.Event().wait(30)
        return 0
    raise ValueError("Unknown runner fixture")


def selfcheck(env, log, memory):
    program = [sys.executable, "-I", str(Path(__file__).resolve()), "--fixture"]
    for mode, expected in [("exit", 7), ("stdin", 0), ("native-output", 0), ("flood", 0), ("descendant", 0)]:
        code, stdout, stderr = command([*program, mode], f"runner-{mode}", env, log,
                                       wall=15, idle=5, memory_mib=memory)
        if code != expected or (mode == "flood" and (len(stdout) != 524288 or len(stderr) != 524288)):
            raise ValueError("Native command ownership regression")
    code, _, _ = command([*program, "wait"], "runner-idle", env, log,
                          wall=10, idle=1, memory_mib=memory)
    if code != 124:
        raise ValueError("CI idle termination regression")
    code, _, _ = command([*program, "wait"], "runner-wall", env, log,
                          wall=1, idle=10, memory_mib=memory)
    if code != 124:
        raise ValueError("CI wall termination regression")
    log.event("INFO", "Native runner self-check passed")


def checked_inputs(baseline, env, log, memory):
    if baseline == ROOT or not baseline.is_relative_to(ROOT / ".ci-work") or not (baseline / ".git").is_dir():
        raise ValueError("Source assertion baseline must be an isolated project-owned checkout")
    code, stdout, _ = command(["git", "-C", str(baseline), "rev-parse", "HEAD"], "source-baseline-identity",
                              env, log, wall=15, idle=5, memory_mib=memory)
    if code or stdout.decode("ascii", errors="strict").strip() != BASELINE:
        raise ValueError("Source assertion baseline commit differs from the pinned recovery identity")
    code, stdout, _ = command(["git", "rev-parse", "HEAD"], "candidate-identity", env, log,
                              wall=15, idle=5, memory_mib=memory)
    if code:
        raise ValueError("Candidate Git identity could not be verified")
    current = evidence.identity(os.environ, stdout.decode("ascii", errors="strict").strip())
    code, stdout, _ = command(["git", "status", "--porcelain", "--untracked-files=no"],
                              "candidate-clean-tree", env, log, wall=15, idle=5, memory_mib=memory)
    if code or stdout.strip():
        raise ValueError("Candidate tracked files differ from the dispatched commit")
    env["MEGABASTERD_CI_BASELINE_ROOT"] = str(baseline)
    env["MEGABASTERD_CI_PYTHON"] = sys.executable
    env["MEGABASTERD_CI_COMMIT"] = current["commit"]
    return load_inputs(ROOT, baseline_root=baseline), current


def native(target, check_format, baseline, env, log, workers, memory):
    pinned = tomllib.loads((ROOT / "rust-toolchain.toml").read_text(encoding="utf-8"))
    if pinned["toolchain"]["channel"] != TOOLCHAIN:
        raise ValueError("CI toolchain and project pin differ")
    rustup = shutil.which("rustup", path=env.get("PATH"))
    if rustup is None:
        raise OSError("Hosted runner Rustup prerequisite is missing")
    code, stdout, _ = command([rustup, "--version"], "rustup-prerequisite", env, log,
                              wall=30, idle=15, memory_mib=memory)
    version = re.match(rb"rustup ([0-9]+)\.([0-9]+)\.([0-9]+)", stdout)
    if code != 0 or version is None or tuple(map(int, version.groups())) < (1, 29, 0):
        raise ValueError("Native CI requires hosted Rustup >=1.29.0; no bootstrap installation is authorized")
    log.event("INFO", "Hosted Rustup prerequisite verified", version=".".join(
        part.decode("ascii") for part in version.groups()), minimum="1.29.0")
    code, _, _ = command([rustup, "toolchain", "install", TOOLCHAIN, "--profile", "minimal",
                          "--component", "rustfmt", "--component", "clippy", "--no-self-update"],
                         "rust-toolchain", env, log, wall=600, idle=120, memory_mib=memory)
    if code != 0:
        return code
    code, stdout, _ = command(["rustc", f"+{TOOLCHAIN}", "-vV"], "rust-host", env, log,
                              wall=30, idle=15, memory_mib=memory)
    if code != 0 or f"host: {target}\n" not in stdout.decode("utf-8").replace("\r\n", "\n"):
        raise ValueError("Native Rust host differs from the declared CI target")
    cargo = ["cargo", f"+{TOOLCHAIN}"]
    code, stdout, _ = command([*cargo, "metadata", "--locked", "--no-deps", "--format-version", "1"],
                              "suite-discovery", env, log, wall=60, idle=30, memory_mib=memory)
    if code != 0:
        return code
    metadata = json.loads(stdout.decode("utf-8"))
    binaries = inventory(metadata, log)
    if not binaries:
        raise ValueError("Cargo binary smoke target inventory is empty")
    selfcheck(env, log, memory)
    inputs, current = checked_inputs(baseline, env, log, memory)
    retirements = load_retirement_approvals(inputs["ledger"], current["commit"], os.environ)
    coverage = reconcile_coverage(inputs, retirement_approvals=retirements)
    wanted = evidence.references(inputs["ledger"])
    log.event("INFO", "Source assertion accounting inspected", definitions=coverage["definitions"],
              statuses=coverage["statuses"], structure_complete=coverage["structure_complete"],
              accounting_ready=coverage["accounting_ready"], native_execution="pending")
    require_report(coverage, stage="structure")
    media = prepare_media(Path(env["TMP"]).parent, env, command, log, workers, memory)
    verify_media(media, env, command, log, memory)
    env["MEGABASTERD_FFMPEG"] = str(media)
    stages = [("tooling-tests", [sys.executable, "-I", str(ROOT / "tools/ci/tooling_tests.py")], 60, 20)]
    if check_format:
        stages.append(("format", [*cargo, "fmt", "--all", "--check"], 120, 30))
    stages.extend([
        ("clippy", [*cargo, "clippy", "--locked", "--workspace", "--all-targets",
                     "-j", str(workers), "--", "-D", "warnings"], 900, 180),
        ("native-compile", [*cargo, "test", "--locked", "--workspace", "--all-targets",
                             "--no-run", "--message-format=json", "-j", str(workers)], 900, 180),
        ("doctests", [*cargo, "test", "--locked", "--workspace", "--doc", "--no-fail-fast",
                       "-j", str(workers), "--", f"--test-threads={workers}", "--color=never"], 300, 60),
        ("binary-build", [*cargo, "build", "--locked", "--workspace", "--bins", "-j", str(workers)], 600, 180),
    ])
    failures = []
    binary_build = False
    suites = {}
    for label, argv, wall, idle in stages:
        if RUN_DEADLINE is not None and time.monotonic() >= RUN_DEADLINE-15:
            failures.append(124)
            log.event("ERROR", "Whole native run timed out before remaining stages", next_stage=label)
            break
        code, stdout, _ = command(argv, label, env, log, wall=wall, idle=idle, memory_mib=memory)
        if code:
            failures.append(code)
        elif label == "native-compile":
            harnesses = evidence.artifacts(stdout, metadata, ROOT, env["CARGO_TARGET_DIR"])
            for index, harness in enumerate(harnesses):
                prefix = f"native-{index:03}"
                flags = ["--format=pretty", "--color=never"]
                kind = {"lib": "--lib", "bin": "--bin", "test": "--test"}[harness["kind"][0]]
                selection = [kind] if kind == "--lib" else [kind, harness["name"]]
                suite_command = [*cargo, "test", "--locked", "--workspace", *selection, "-j", str(workers), "--"]
                code, listed, _ = command([*suite_command, "--list", *flags], prefix+"-list",
                                          env, log, wall=30, idle=10, memory_mib=memory)
                if code:
                    failures.append(code)
                    continue
                try:
                    discovered = evidence.discovery(listed)
                except ValueError:
                    log.event("ERROR", "Native harness discovery accounting failed", command=prefix)
                    failures.append(1)
                    continue
                result_path = Path(env["TMP"]).parent / f"{prefix}-results.txt"
                if result_path.exists():
                    raise ValueError("Native harness result path already exists")
                code, _, _ = command([*suite_command, *flags, f"--test-threads={workers}",
                                       "--logfile", result_path], prefix+"-run", env, log,
                                      wall=900, idle=120, memory_mib=memory)
                if code:
                    failures.append(code)
                    continue
                try:
                    passed = evidence.result_file(result_path, discovered)
                except ValueError:
                    log.event("ERROR", "Native harness result accounting failed", command=prefix)
                    failures.append(1)
                    continue
                if harness["source"] in suites and harness["kind"] != ["bin"]:
                    raise ValueError("Native harness source is duplicated")
                if harness["kind"] != ["bin"]:
                    suites[harness["source"]] = passed
                log.event("INFO", "Native harness assertions accounted", command=prefix, tests=len(passed))
        if label == "binary-build":
            binary_build = code == 0
    if binary_build:
        suffix = ".exe" if os.name == "nt" else ""
        for name in binaries:
            binary = Path(env["CARGO_TARGET_DIR"]) / "debug" / (name + suffix)
            # Exercise each actual alias, invalid input and noninteractive EOF, without live credentials.
            for case, arguments, expected in [("help", ["--help"], 0), ("version", ["--version"], 0),
                                               ("invalid", ["--not-a-real-option"], 2), ("eof", [], 2)]:
                code, stdout, stderr = command([binary, *arguments], f"smoke-{name}-{case}", env, log,
                                               wall=30, idle=10, memory_mib=memory)
                if code != expected or not stdout + stderr:
                    failures.append(code or 1)
                    log.event("ERROR", "Binary smoke assertion failed", binary=name, case=case,
                              expected=expected, actual=code)
    if not coverage["accounting_ready"]:
        log.event("ERROR", "Source parity accounting is incomplete; native success cannot waive missing invariants",
                  statuses=coverage["statuses"], problems=coverage["problems"])
        failures.append(1)
    if time.monotonic() >= RUN_DEADLINE:
        return 124
    if not failures:
        final_inputs, final_identity = checked_inputs(baseline, env, log, memory)
        if final_identity != current or final_inputs["targets"] != inputs["targets"]:
            raise ValueError("Native assertion source changed during execution")
        project_archive, _ = prepare_project_source(ROOT, current, target, env, command, log, memory)
        prepare_runtime(ROOT, current, target, cargo, env, command, log, workers, memory, project_archive=project_archive)
        final_inputs, final_identity = checked_inputs(baseline, env, log, memory)
        if final_identity != current or final_inputs["targets"] != inputs["targets"]:
            raise ValueError("Native source changed during compiler intermediate preparation")
        report = evidence.receipt(current, target, wanted, suites)
        evidence.write_receipt(ROOT / ".ci-work" / "evidence" / target / "receipt.json", report)
        log.event("INFO", "Exact native assertion receipt written", target=target,
                  suites=report["suite_count"], tests=report["test_count"], mapped=len(report["targets"]))
    return failures[0] if failures else 0


def main():
    global RUN_DEADLINE, LINUX_SUBREAPER
    if sys.argv[1:2] == ["--guardian"]:
        return guardian(sys.argv[3:])
    if sys.argv[1:2] == ["--fixture"]:
        return fixture(sys.argv[2])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=["x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc",
                                                           "x86_64-apple-darwin", "aarch64-apple-darwin"])
    parser.add_argument("--format", action="store_true")
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--aggregate", type=Path)
    args = parser.parse_args()
    if bool(args.target) == bool(args.aggregate) or (args.aggregate and args.format):
        parser.error("Select exactly one native target or aggregate directory")
    RUN_DEADLINE = time.monotonic() + (120 if args.aggregate else 3300)
    work = ROOT / ".ci-work" / "native" / uuid.uuid4().hex
    work.mkdir(parents=True)
    try:
        log = RunLog(work)
    except OSError:
        print("CI logging initialization failed; no log file was claimed.", file=sys.stderr)
        return 125
    code = 125
    previous = {}
    def canceled(signum, frame):
        # A second interrupt must not interrupt the first command's finally/sweep.
        for owned_signal in previous:
            signal.signal(owned_signal, signal.SIG_IGN)
        raise KeyboardInterrupt
    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.signal(signum, canceled)
        LINUX_SUBREAPER = enable_linux_subreaper()
        workers, memory = worker_budget()
        env = environment(work, workers)
        log.event("INFO", "Native run started", target=args.target, workers=workers,
                  memory_mib=memory, python=f"{sys.version_info.major}.{sys.version_info.minor}")
        baseline = (ROOT / args.baseline).resolve()
        if args.aggregate:
            directory = (ROOT / args.aggregate).resolve()
            if not directory.is_relative_to(ROOT / ".ci-work"):
                raise ValueError("Native receipts must remain in the project CI work root")
            inputs, current = checked_inputs(baseline, env, log, memory)
            retirements = load_retirement_approvals(inputs["ledger"], current["commit"], os.environ)
            report = evidence.aggregate(inputs, directory, current, retirement_approvals=retirements)
            log.event("INFO", "Native execution coverage verified", commit=current["commit"],
                      definitions=report["definitions"], targets=len(evidence.TARGETS))
            code = 0
        else:
            code = native(args.target, args.format, baseline, env, log, workers, memory)
    except KeyboardInterrupt:
        code = 130
        log.event("ERROR", "Native run interrupted; owned command cleanup was required")
    except (OSError, ValueError, KeyError, StopIteration, subprocess.SubprocessError) as error:
        code = 125
        messages = {"CI shared worker ceiling must be positive", "CI memory budget is unavailable",
                    "CI memory budget discovery failed", "CI Linux child-subreaper initialization failed",
                    "CI toolchain and project pin differ", "Hosted runner Rustup prerequisite is missing",
                    "Native CI requires hosted Rustup >=1.29.0; no bootstrap installation is authorized",
                    "Native Rust host differs from the declared CI target",
                    "CI suite guard needs explicit multi-package workspace ownership",
                    "Disabled/custom Rust test harness needs an explicit CI contract",
                    "Rust disk suites and Cargo integration targets differ",
                    "A Cargo target disables required native tests", "Cargo library disables doctests",
                    "Rust source/test file exceeds the800line ceiling",
                    "Ignored Rust test requires an explicit coverage decision",
                    "Cargo binary smoke target inventory is empty", "Native command ownership regression",
                    "CI idle termination regression", "CI wall termination regression",
                    "Source assertion baseline must be an isolated project-owned checkout",
                    "Source assertion baseline commit differs from the pinned recovery identity"}
        detail = str(error) if str(error) in messages else type(error).__name__
        log.event("ERROR", "Native run prerequisite, inventory or assertion failed", diagnostic=detail)
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
        # Ephemeral hosted runner owns fixture/cache directories; preserve failure diagnostics.
        try:
            log.event("INFO" if code == 0 else "ERROR", "Native run finished", exit_code=code,
                      packaging="source and unsigned compiler intermediates only; signed release gates remain", real_media="required native fixture suite")
        finally:
            log.close()
    return code if code >= 0 else 128-code


if __name__ == "__main__":
    sys.exit(main())
