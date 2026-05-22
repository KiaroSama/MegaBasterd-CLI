"""MEGA hashcash proof-of-work solver.

MEGA throttles abusive clients by returning HTTP 402 with an `X-Hashcash`
challenge. The client must compute a 4-byte nonce that, when prepended to a
48-byte token repeated 262144 times and SHA-256-hashed, yields a digest whose
first 4 bytes (big-endian uint32) fall below a difficulty threshold derived
from the `easiness` parameter of the challenge.

This module re-implements the algorithm from the original MegaBasterd
(`HashcashSolver.java`) in pure Python with multi-threaded nonce search.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import logging
import os
import platform
import shutil
import struct
import subprocess
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass
from pathlib import Path

TOKEN_BYTES = 48
PREFIX_BYTES = 4
REPEAT = 262_144
BUF_SIZE = PREFIX_BYTES + REPEAT * TOKEN_BYTES
DEFAULT_TIMEOUT_S = 300.0
NATIVE_TIMEOUT_MARGIN_S = 5.0

log = logging.getLogger(__name__)


@dataclass
class HashcashChallenge:
    """Parsed `X-Hashcash` header."""

    version: int  # Always 1 in current MEGA usage
    easiness: int  # 0..255, controls difficulty
    token: bytes  # 48 raw bytes (base64-decoded)

    @property
    def threshold(self) -> int:
        """Maximum allowed value of the first 4 bytes (big-endian) of SHA-256."""
        return (((self.easiness & 0x3F) << 1) + 1) << ((self.easiness >> 6) * 7 + 3)


def parse_challenge(header: str) -> HashcashChallenge:
    """Parse an `X-Hashcash` header of the form `1:easiness:b64token`."""
    parts = header.strip().split(":")
    if len(parts) != 3:
        raise ValueError(f"Malformed hashcash challenge: {header!r}")
    try:
        version = int(parts[0])
        easiness = int(parts[1])
    except ValueError as exc:
        raise ValueError(f"Bad numeric fields in challenge: {header!r}") from exc
    token_b64 = parts[2]
    # MEGA-style base64 (URL safe, no padding)
    token_b64 = token_b64.replace("-", "+").replace("_", "/")
    token_b64 += "=" * ((4 - len(token_b64) % 4) % 4)
    token = base64.b64decode(token_b64)
    if len(token) != TOKEN_BYTES:
        raise ValueError(f"Hashcash token must be {TOKEN_BYTES} bytes, got {len(token)}")
    return HashcashChallenge(version=version, easiness=easiness, token=token)


def _check_nonce(nonce_bytes: bytes, token_repeated: bytes, threshold: int) -> bool:
    """Return True if the given 4-byte nonce satisfies the challenge."""
    digest = hashlib.sha256(nonce_bytes + token_repeated).digest()
    head = struct.unpack(">I", digest[:4])[0]
    return head <= threshold


def _project_root() -> Path | None:
    """Return the source checkout root when running from a source tree."""
    for parent in Path(__file__).resolve().parents:
        if (parent / "Run.ps1").is_file():
            return parent
    return None


def _native_solver_commands() -> list[list[str]]:
    """Return native solver commands in preference order."""
    if os.environ.get("MEGABASTERD_HASHCASH_NATIVE", "").lower() in {
        "0",
        "false",
        "n",
        "no",
        "off",
    }:
        return []

    env_solver = os.environ.get("MEGABASTERD_HASHCASH_SOLVER")
    commands: list[list[str]] = []
    if env_solver:
        candidate = Path(env_solver).expanduser()
        if candidate.is_file():
            if candidate.suffix.lower() == ".ps1":
                powershell = shutil.which("pwsh.exe") or shutil.which("powershell.exe")
                if powershell:
                    commands.append(
                        [
                            powershell,
                            "-NoProfile",
                            "-ExecutionPolicy",
                            "Bypass",
                            "-File",
                            str(candidate),
                        ]
                    )
            else:
                commands.append([str(candidate)])
        return commands

    if platform.system() != "Windows":
        return commands

    roots = []
    source_root = _project_root()
    if source_root is not None:
        roots.append(source_root)

    for root in roots:
        exe = root / "Bin" / "hashcash-solver-win64.exe"
        if exe.is_file():
            commands.append([str(exe)])

    packaged_exe = (
        Path(__file__).resolve().parents[1] / "native" / "windows" / "hashcash_solver.exe"
    )
    if packaged_exe.is_file():
        commands.append([str(packaged_exe)])

    powershell = shutil.which("pwsh.exe") or shutil.which("powershell.exe")
    if powershell and source_root is not None:
        script = source_root / "tools" / "hashcash_solver_windows.ps1"
        if script.is_file():
            commands.append(
                [
                    powershell,
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(script),
                ]
            )
    return commands


def _parse_native_nonce(output: str) -> bytes:
    """Parse a native solver nonce printed as 8 hex characters."""
    for line in reversed(output.splitlines()):
        text = line.strip()
        if len(text) == 8:
            try:
                return bytes.fromhex(text)
            except ValueError:
                continue
    raise ValueError("Native solver did not return an 8-character hex nonce")


def _solve_with_native(
    challenge: HashcashChallenge,
    timeout: float,
    workers: int,
) -> bytes | None:
    """Try the Windows native helper. Return None when no helper is available."""
    commands = _native_solver_commands()
    if not commands:
        return None

    timeout_ms = max(1, int(timeout * 1000))
    workers = max(1, min(workers, 32))
    for base_command in commands:
        if base_command[-1].lower().endswith(".ps1"):
            args = [
                *base_command,
                "-Easiness",
                str(challenge.easiness),
                "-TokenHex",
                challenge.token.hex(),
                "-Workers",
                str(workers),
                "-TimeoutMs",
                str(timeout_ms),
            ]
        else:
            args = [
                *base_command,
                str(challenge.easiness),
                challenge.token.hex(),
                str(workers),
                str(timeout_ms),
            ]

        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=timeout + NATIVE_TIMEOUT_MARGIN_S,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError("Native hashcash solver timed out") from exc
        except OSError as exc:
            log.debug("Native hashcash solver failed to start: %s", exc)
            continue

        if proc.returncode == 0:
            try:
                return _parse_native_nonce(proc.stdout)
            except ValueError as exc:
                log.warning("Native hashcash solver returned invalid output: %s", exc)
                continue
        if proc.returncode == 2:
            raise TimeoutError("Hashcash challenge could not be solved in time")
        log.debug(
            "Native hashcash solver failed rc=%s stderr=%s",
            proc.returncode,
            proc.stderr.strip(),
        )
    return None


def solve(
    challenge: HashcashChallenge,
    timeout: float = DEFAULT_TIMEOUT_S,
    workers: int = 8,
) -> bytes:
    """Return a valid 4-byte nonce solving the challenge.

    Raises TimeoutError if no solution is found within `timeout` seconds.
    """
    native_nonce = _solve_with_native(challenge, timeout=timeout, workers=workers)
    if native_nonce is not None:
        token_repeated = challenge.token * REPEAT
        if _check_nonce(native_nonce, token_repeated, challenge.threshold):
            return native_nonce
        log.warning("Native hashcash solver returned a nonce that failed verification")

    token_repeated = challenge.token * REPEAT
    threshold = challenge.threshold
    deadline = time.monotonic() + timeout
    stop = threading.Event()
    result: list[bytes] = []
    result_lock = threading.Lock()

    def _worker(start: int, step: int) -> None:
        candidate = start
        while not stop.is_set():
            if time.monotonic() > deadline:
                return
            nonce = struct.pack(">I", candidate & 0xFFFFFFFF)
            if _check_nonce(nonce, token_repeated, threshold):
                with result_lock:
                    if not result:
                        result.append(nonce)
                stop.set()
                return
            candidate += step

    workers = max(1, min(workers, 32))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_worker, i, workers) for i in range(workers)]
        # Poll for completion or timeout
        while not stop.is_set() and time.monotonic() < deadline:
            done, _ = wait(futures, timeout=0.5, return_when=FIRST_COMPLETED)
            if done:
                break
        stop.set()
        for f in futures:
            with contextlib.suppress(Exception):
                f.result(timeout=1.0)

    if not result:
        raise TimeoutError("Hashcash challenge could not be solved in time")
    return result[0]


def build_solution_header(challenge_header: str, timeout: float = DEFAULT_TIMEOUT_S) -> str:
    """Solve a `X-Hashcash` challenge and return the matching `X-Hashcash` reply.

    The returned string is suitable for direct inclusion in the HTTP request
    that retries the rejected operation:

        X-Hashcash: <version>:<easiness>:<token_b64>:<nonce_b64>
    """
    challenge = parse_challenge(challenge_header)
    nonce = solve(challenge, timeout=timeout)
    nonce_b64 = (
        base64.b64encode(nonce).decode("ascii").rstrip("=").replace("+", "-").replace("/", "_")
    )
    token_b64 = (
        base64.b64encode(challenge.token)
        .decode("ascii")
        .rstrip("=")
        .replace("+", "-")
        .replace("/", "_")
    )
    return f"{challenge.version}:{challenge.easiness}:{token_b64}:{nonce_b64}"
