"""The source distribution must contain everything the launcher loads at runtime.

`Run.ps1` used to carry its Windows secure-open helper inline. It now loads
`launcher/SecureLog.cs` with `Add-Type -Path`, and `MANIFEST.in` said nothing
about that directory - so an sdist shipped a launcher whose logging could not
start, and nothing in the test suite would have noticed, because every other
test runs from the working tree where the file is simply there.

Building an sdist is slow, so it happens once per session and both checks share
it.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from tests.launcher_helpers import REPO, pwsh, requires_pwsh, windows_only

MANIFEST = REPO / "MANIFEST.in"

# `python -m build .` writes src/megabasterd_cli.egg-info INSIDE the repo, and a
# session-scoped fixture runs once per xdist worker - so two workers built the
# same source tree at once and trod on each other's egg-info. One worker, one
# build.
pytestmark = pytest.mark.xdist_group("sdist_build")


def test_the_manifest_ships_the_helper_and_no_deleted_file():
    """Cheap guard that runs even where `python -m build` is unavailable."""
    manifest = MANIFEST.read_text(encoding="utf-8")
    assert "recursive-include launcher *.cs" in manifest, "the launcher helper is not packaged"
    assert "GITHUB_RELEASE_NOTES.md" not in manifest, "the manifest references a deleted file"


@pytest.fixture(scope="session")
def sdist(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("sdist")
    done = subprocess.run(
        [sys.executable, "-m", "build", "--sdist", "--outdir", str(out), str(REPO)],
        capture_output=True,
        text=True,
        timeout=900,
    )
    # Deliberately not a skip. `build` is a declared dev dependency, so it
    # being absent or failing is a broken environment, not a reason to pass -
    # and a skip here means the suite reports success having never built the
    # sdist this file exists to check.
    assert done.returncode == 0, (
        "python -m build failed; `build` is in the dev extra and must work:\n"
        + done.stdout[-1500:]
        + done.stderr[-1500:]
    )
    archives = list(out.glob("*.tar.gz"))
    assert len(archives) == 1, archives
    return archives[0]


def test_the_sdist_contains_the_launcher_and_its_helper(sdist):
    with tarfile.open(sdist) as archive:
        names = {"/".join(n.split("/")[1:]) for n in archive.getnames()}
    assert "Run.ps1" in names, sorted(n for n in names if n.endswith(".ps1"))
    assert "launcher/SecureLog.cs" in names, sorted(n for n in names if n.endswith(".cs"))


@windows_only
@requires_pwsh
def test_the_launcher_runs_from_an_extracted_sdist(sdist, tmp_path):
    """The check that actually matters: unpack it somewhere clean and run it.

    A manifest entry can be present and still name the wrong path, and the
    helper is only loaded when a log line is written - so this runs the real
    launcher and requires a clean exit with no warning.
    """
    extracted = tmp_path / "tree"
    with tarfile.open(sdist) as archive:
        archive.extractall(extracted)
    root = next(extracted.iterdir())
    assert (root / "launcher" / "SecureLog.cs").is_file(), "the helper did not survive packaging"

    logs = tmp_path / "logs"
    logs.mkdir()
    env = dict(os.environ)
    env["MEGABASTERD_LAUNCHER_LOG_DIR"] = str(logs)
    env["MEGABASTERD_NO_PAUSE"] = "1"
    done = subprocess.run(
        [pwsh, "-NoProfile", "-File", str(root / "Run.ps1"), "--help"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=tmp_path,  # from any working directory, not just the tree root
        env=env,
        timeout=600,
    )

    assert done.returncode == 0, done.stdout[-2000:] + done.stderr[-2000:]
    assert "file logging disabled" not in done.stderr, done.stderr
    written = list(logs.glob("launcher-*.log"))
    assert written and written[0].read_text(encoding="utf-8").strip(), "no launcher log was written"
