# SPDX-License-Identifier: GPL-3.0-or-later
"""Pinned CI-only media prerequisites; imported by the owned native runner."""

import hashlib
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import tarfile
import time
import urllib.request
import zipfile

VERSION = "9.0.2"
SOURCE_URL = "https://ffmpeg.org/releases/ffmpeg-9.0.2.tar.xz"
SOURCE_SHA = "8c3850283eb25fa026482078a04051e0be17347b09ef81a0849bec15a96e002e"
WINDOWS_URL = "https://www.gyan.dev/ffmpeg/builds/packages/ffmpeg-9.0.2-essentials_build.zip"
WINDOWS_SHA = "60f467265b1e312373dbcd92200c2618a74850f98d3d078e94296bb3fa2047ba"
MAX_ARCHIVE = 128 * 1024 * 1024
MAX_MEMBER = 256 * 1024 * 1024
MAX_EXPANDED = 512 * 1024 * 1024
MAX_ENTRIES = 32768


def download(url, destination, expected_sha):
    # Fixed public URL/expected digest; no caller credentials or proxy configuration inherited.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    digest, total = hashlib.sha256(), 0
    deadline = time.monotonic() + 180
    request = urllib.request.Request(url, headers={"User-Agent": "native-media-ci"})
    with opener.open(request, timeout=20) as response, destination.open("xb") as output:
        if response.geturl() != url:
            raise ValueError("Pinned media archive redirected to a different URL")
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError("Pinned media archive download exceeded its deadline")
            block = response.read(1024 * 1024)
            if not block:
                break
            total += len(block)
            if total > MAX_ARCHIVE:
                raise ValueError("Pinned media archive exceeds its size limit")
            digest.update(block)
            output.write(block)
    if digest.hexdigest() != expected_sha:
        raise ValueError("Pinned media archive digest differs")


def member_path(name):
    if not isinstance(name, str) or "\\" in name or ":" in name or "\x00" in name:
        raise ValueError("Unsafe media archive member")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in name.rstrip("/").split("/")):
        raise ValueError("Media archive member escapes extraction root")
    return path


def copy_exact(source, target, size):
    if size < 0 or size > MAX_MEMBER:
        raise ValueError("Media archive member exceeds its size limit")
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("xb") as output:
        remaining = size
        while remaining:
            block = source.read(min(1024 * 1024, remaining))
            if not block:
                raise ValueError("Media archive member is truncated")
            output.write(block)
            remaining -= len(block)
        if source.read(1):
            raise ValueError("Media archive member length differs")


def extract_source(archive, directory):
    seen, total = set(), 0
    with tarfile.open(archive, mode="r:xz") as stream:
        for index, member in enumerate(stream):
            path = member_path(member.name)
            if index >= MAX_ENTRIES or not path.parts or path.parts[0] != f"ffmpeg-{VERSION}":
                raise ValueError("Unexpected media source archive layout")
            if path in seen or not (member.isdir() or member.isfile()):
                raise ValueError("Duplicate, linked or special media archive member")
            seen.add(path)
            target = directory.joinpath(*path.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            total += member.size
            if total > MAX_EXPANDED:
                raise ValueError("Media source extraction exceeds its size limit")
            reader = stream.extractfile(member)
            if reader is None:
                raise ValueError("Media source member is unreadable")
            with reader:
                copy_exact(reader, target, member.size)
            target.chmod(0o700 if member.mode & 0o111 else 0o600)
    source = directory / f"ffmpeg-{VERSION}"
    if (source / "RELEASE").read_text(encoding="utf-8").strip() != VERSION:
        raise ValueError("Media source version differs from its pin")
    return source


def extract_windows(archive, directory):
    found = set()
    with zipfile.ZipFile(archive) as stream:
        if len(stream.infolist()) > MAX_ENTRIES:
            raise ValueError("Media binary archive exceeds its entry limit")
        for member in stream.infolist():
            path = member_path(member.filename)
            if len(path.parts) != 3 or path.parts[1] != "bin" or path.name not in {"ffmpeg.exe", "ffprobe.exe"}:
                continue
            mode = member.external_attr >> 16
            if member.is_dir() or (stat.S_IFMT(mode) not in {0, stat.S_IFREG}) or path.name in found:
                raise ValueError("Invalid media executable archive entry")
            with stream.open(member) as source:
                copy_exact(source, directory / path.name, member.file_size)
            found.add(path.name)
    if found != {"ffmpeg.exe", "ffprobe.exe"}:
        raise ValueError("Media binary archive lacks the exact tool pair")
    return directory / "ffmpeg.exe"


def prepare(work, environment, command, log, workers, memory):
    """Acquire pinned tools on ephemeral hosted CI only; all child runs use its existing owner."""
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise ValueError("Media prerequisite setup is restricted to GitHub Actions")
    base = work / "media-prerequisite"
    incoming, extracted, build = base / "download", base / "source", base / "build"
    for path in [incoming, extracted, build]:
        path.mkdir(parents=True, exist_ok=False)
    if os.name == "nt":
        archive = incoming / "ffmpeg.zip"
        download(WINDOWS_URL, archive, WINDOWS_SHA)
        executable = extract_windows(archive, build)
        log.event("INFO", "Pinned media binary pair extracted", version=VERSION)
        return executable
    archive = incoming / "ffmpeg.tar.xz"
    download(SOURCE_URL, archive, SOURCE_SHA)
    source = extract_source(archive, extracted)
    compiler, make, shell = (shutil.which(name, path=environment.get("PATH")) for name in ["cc", "make", "sh"])
    if not all([compiler, make, shell]):
        raise ValueError("Hosted native C compiler, make or shell is unavailable for media fixture tool")
    arguments = [shell, str(source / "configure"), "--disable-autodetect", "--disable-everything",
                 "--disable-network", "--disable-doc", "--disable-debug", "--disable-ffplay",
                 "--disable-avdevice", "--disable-x86asm", "--disable-shared", "--enable-static",
                 "--enable-decoder=h264,vp8", "--enable-parser=h264,vp8",
                 "--enable-demuxer=mov,matroska", "--enable-encoder=mjpeg",
                 "--enable-muxer=image2pipe", "--enable-protocol=fd,pipe", "--enable-filter=scale",
                 f"--cc={compiler}"]
    for label, argv, wall, idle in [("media-configure", arguments, 180, 45),
            ("media-build", [make, f"-j{workers}", "ffmpeg", "ffprobe"], 600, 120)]:
        code, _, _ = command(argv, label, environment, log, wall=wall, idle=idle,
                             memory_mib=memory, cwd=build)
        if code:
            raise ValueError("Pinned native media prerequisite build failed")
    log.event("INFO", "Minimal native media fixture tools built", version=VERSION,
              workers=workers, gpu="not provided by minimal CPU fixture build")
    return build / "ffmpeg"


def verify(executable, environment, command, log, memory):
    sibling = executable.with_name("ffprobe.exe" if os.name == "nt" else "ffprobe")
    for name, program in [("ffmpeg", executable), ("ffprobe", sibling)]:
        code, stdout, _ = command([program, "-version"], f"media-{name}-version", environment, log,
                                 wall=15, idle=5, memory_mib=memory)
        if code or not stdout.startswith(f"{name} version {VERSION}".encode("ascii")):
            raise ValueError("Native media executable version differs from approved pin")
        code, stdout, _ = command([program, "-hide_banner", "-protocols"], f"media-{name}-protocols",
                                 environment, log, wall=15, idle=5, memory_mib=memory)
        if code or b"fd" not in {line.strip() for line in stdout.splitlines()}:
            raise ValueError("Native media executable lacks seekable held-input protocol")
    log.event("INFO", "Native media versions and held-input protocol verified", version=VERSION,
              protocol="fd")
