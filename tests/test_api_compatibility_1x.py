"""Public names removed during the cleanup pass, restored for the 1.x series.

A repo-wide dead-code pass deleted these because nothing inside this repository
called them. That is a different question from whether anything OUTSIDE it does:
they carry no leading underscore, so they were importable API, and 1.x is not a
boundary at which importable API may disappear.

They are restored as compatibility surfaces, not as a second implementation.
Production keeps using the newer path where one exists - `make_limiter` returns
a `TokenBucket`, destinations go through `claim_destination`, progress renders
via `MultiFileProgressView` - and the tests below assert that separation as well
as the imports themselves.

Deliberately NOT restored: `_V1_HEADER_LEN` and `_V2_HEADER_LEN`, which began
with an underscore and were never public.
"""

from __future__ import annotations

import ast
import hashlib
import inspect
import subprocess
import sys
from pathlib import Path

import pytest

from tests.launcher_helpers import REPO

SRC = REPO / "src" / "megabasterd_cli"

NOTE = "Compatibility surface retained for the 1.x series."

# Module-level constants: they carry the note in a nearby comment rather than a
# docstring, because an `int`/`str` has no docstring of its own to carry it.
CONSTANTS = {"REDACTED_KEY", "BUF_SIZE"}

# (module, attribute, owning class or None)
RESTORED = [
    ("megabasterd_cli.utils.helpers", "format_speed", None),
    ("megabasterd_cli.core.hashcash", "BUF_SIZE", None),
    ("megabasterd_cli.core.links", "normalize_link", None),
    ("megabasterd_cli.core.links", "needs_password", "ParsedLink"),
    ("megabasterd_cli.core.folder_downloader", "download_file_in_folder", "MegaFolderDownloader"),
    ("megabasterd_cli.core.auth", "restore_session", "AuthOperations"),
    ("megabasterd_cli.core.nodes", "find_inbox", "NodeOperations"),
    ("megabasterd_cli.core.chunks", "chunks_for_range", None),
    ("megabasterd_cli.utils.helpers", "ensure_unique_path", None),
    ("megabasterd_cli.utils.helpers", "file_md5", None),
    ("megabasterd_cli.ui.progress", "build_progress", None),
    ("megabasterd_cli.ui.progress", "ProgressReporter", None),
    ("megabasterd_cli.ui.progress", "progress_for", None),
    ("megabasterd_cli.ui.prompts", "print_panel", None),
    ("megabasterd_cli.utils.speed", "NoOpLimiter", None),
    ("megabasterd_cli.utils.redaction", "REDACTED_KEY", None),
]


def _resolve(module: str, attr: str, owner: str | None):
    __import__(module)
    obj = sys.modules[module]
    if owner:
        obj = getattr(obj, owner)
    return getattr(obj, attr)


# ---------------------------------------------------------------------------
# every name is importable again
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("module", "attr", "owner"),
    [(m, a, o) for m, a, o in RESTORED],
    ids=[f"{o + '.' if o else ''}{a}" for _, a, o in RESTORED],
)
def test_the_removed_public_name_imports_again(module, attr, owner):
    assert _resolve(module, attr, owner) is not None


@pytest.mark.parametrize(
    ("module", "attr", "owner"),
    [(m, a, o) for m, a, o in RESTORED if a not in CONSTANTS],
    ids=[f"{o + '.' if o else ''}{a}" for _, a, o in RESTORED if a not in CONSTANTS],
)
def test_every_restored_name_says_it_is_a_compatibility_surface(module, attr, owner):
    """Otherwise the next cleanup pass deletes them again for the same reason."""
    doc = inspect.getdoc(_resolve(module, attr, owner)) or ""
    assert NOTE in doc, f"{attr} does not declare itself a compatibility surface"


def test_the_private_header_constants_stay_deleted():
    """They began with an underscore, so they were never public API."""
    crypter = (SRC / "core" / "crypter.py").read_text(encoding="utf-8")
    assert "_V1_HEADER_LEN" not in crypter
    assert "_V2_HEADER_LEN" not in crypter


# ---------------------------------------------------------------------------
# the previous behaviour, not just the previous name
# ---------------------------------------------------------------------------


def test_normalize_link_is_exported_and_still_normalises():
    from megabasterd_cli.core import links

    assert "normalize_link" in links.__all__
    assert (
        links.normalize_link("  https://mega.nz/file/ABC#key  ") == "https://mega.nz/file/ABC#key"
    )


def test_ensure_unique_path_still_walks_to_a_free_name(tmp_path):
    target = tmp_path / "file.txt"
    from megabasterd_cli.utils.helpers import ensure_unique_path

    assert ensure_unique_path(target) == target
    target.write_text("x", encoding="utf-8")
    assert ensure_unique_path(target) == tmp_path / "file (1).txt"


def test_file_md5_still_matches_hashlib(tmp_path):
    from megabasterd_cli.utils.helpers import file_md5

    blob = b"megabasterd" * 5000  # larger than the 64 KiB read block
    path = tmp_path / "blob.bin"
    path.write_bytes(blob)
    assert file_md5(path) == hashlib.md5(blob).hexdigest()


def test_chunks_for_range_still_returns_only_overlapping_chunks():
    from megabasterd_cli.core.chunks import chunks_for_range, iter_chunks

    size = 10 * 1024 * 1024
    window = chunks_for_range(size, 200_000, 500_000)
    assert window, "an overlapping range returned nothing"
    for chunk in window:
        assert chunk.end > 200_000 and chunk.offset < 500_000
    assert chunks_for_range(size, 0, size) == list(iter_chunks(size))


def test_noop_limiter_still_swallows_both_calls():
    from megabasterd_cli.utils.speed import NoOpLimiter

    limiter = NoOpLimiter()
    assert limiter.consume(1 << 20) is None
    assert limiter.set_rate(4096) is None


def test_redacted_key_keeps_its_previous_value():
    from megabasterd_cli.utils.redaction import REDACTED_KEY

    assert REDACTED_KEY == "#<key>"


def test_format_speed_still_appends_per_second_to_a_byte_count():
    from megabasterd_cli.utils.helpers import format_bytes, format_speed

    assert format_speed(0) == "0 B/s"
    assert format_speed(1536) == f"{format_bytes(1536)}/s"
    # It took a float and truncated it; that is part of the signature.
    assert format_speed(1024.9) == format_speed(1024)


def test_buf_size_still_equals_the_solver_buffer_it_described():
    from megabasterd_cli.core import hashcash

    assert hashcash.BUF_SIZE == hashcash.PREFIX_BYTES + hashcash.REPEAT * hashcash.TOKEN_BYTES


def test_menu_still_accepts_a_subtitle_keyword():
    """A dataclass field, so losing it is a TypeError at the call site.

    It cannot ride in RESTORED: the default is None, and the import check there
    asserts the attribute is not None.
    """
    import dataclasses

    from megabasterd_cli.launcher_menu import Menu

    fields = {f.name: f for f in dataclasses.fields(Menu)}
    assert "subtitle" in fields, "the public constructor keyword is gone"
    assert Menu("Title").subtitle is None
    assert Menu("Title", subtitle="Second line").subtitle == "Second line"


def test_progress_for_is_still_a_context_manager_yielding_a_reporter():
    """The decorator is the easy thing to lose when restoring by hand.

    The reporter's methods are `update_download` / `update_upload` - the shim
    has to keep the API it actually had, not a plausible-looking one.
    """
    from megabasterd_cli.ui.progress import ProgressReporter, progress_for

    class _Progress:
        bytes_done = 5
        total_bytes = 10

    with progress_for("restoring", 10) as reporter:
        assert isinstance(reporter, ProgressReporter)
        assert hasattr(reporter, "update_download") and hasattr(reporter, "update_upload")
        reporter.update_download(_Progress())


def test_build_progress_renders_without_a_missing_style():
    """isinstance was not enough, and that is exactly how mb.command went missing.

    `Theme` does not validate that a referenced style exists - `MissingStyle` is
    raised when the segment is painted. A test that only checks the returned
    type passes over a progress bar that explodes on first draw.
    """
    from rich.console import Console
    from rich.progress import Progress

    from megabasterd_cli.ui.progress import build_progress
    from megabasterd_cli.ui.theme import THEME

    console = Console(theme=THEME, force_terminal=True, width=80, legacy_windows=False)
    progress = build_progress(console)
    assert isinstance(progress, Progress)
    task = progress.add_task("compat", total=10)
    progress.advance(task, 5)
    with console.capture() as captured:
        console.print(progress)
    assert "compat" in captured.get()


def test_every_style_the_progress_shim_names_exists_in_the_theme():
    """A missing one only fails at render, so name them explicitly too."""
    import re as _re

    from megabasterd_cli.ui.theme import THEME

    source = (SRC / "ui" / "progress.py").read_text(encoding="utf-8")
    for style in sorted(set(_re.findall(r"[\"']?\[?(mb\.[a-z.]+)\]?[\"']?", source))):
        assert style in THEME.styles, f"{style} is referenced but not defined"


# ---------------------------------------------------------------------------
# the shims must not become a second production implementation
# ---------------------------------------------------------------------------


def _calls_in(path: Path, name: str) -> list[str]:
    """Every function whose body calls `name`, excluding `name` itself."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name == name:
            continue
        for inner in ast.walk(node):
            if (
                isinstance(inner, ast.Name)
                and inner.id == name
                or isinstance(inner, ast.Attribute)
                and inner.attr == name
            ):
                found.append(node.name)
    return found


# NoOpLimiter is deliberately absent: `make_limiter` returning one is the 1.x
# contract, so production DOES hand it back and must keep doing so.
@pytest.mark.parametrize("name", ["ensure_unique_path", "file_md5", "progress_for", "format_speed"])
def test_no_production_module_routes_through_a_shim(name):
    """Restoring compatibility must not quietly revive the old code path."""
    callers = []
    for path in SRC.rglob("*.py"):
        callers += [f"{path.name}:{fn}" for fn in _calls_in(path, name)]
    assert not callers, f"{name} is being used by production again: {callers}"


def test_make_limiter_keeps_its_1x_return_contract():
    """Callers may branch on the type, so the union is part of the promise.

    Collapsing this to always-TokenBucket was defensible internally - `consume`
    does return immediately at rate 0 - but it changed what the package hands
    back, which is not an internal matter.
    """
    from megabasterd_cli.utils.speed import NoOpLimiter, TokenBucket, make_limiter

    for kbps in (0, -5, -0.001):
        assert isinstance(make_limiter(kbps), NoOpLimiter), kbps
    for kbps in (0.5, 128, 4096):
        limiter = make_limiter(kbps)
        assert isinstance(limiter, TokenBucket), kbps
        assert limiter.rate == kbps * 1024


def test_needs_password_is_a_property_not_a_bound_method():
    """It was `@property`; a restore that drops the decorator is truthy always."""
    from megabasterd_cli.core.links import LinkType, ParsedLink

    assert isinstance(ParsedLink.__dict__["needs_password"], property)
    protected = ParsedLink(type=LinkType.PASSWORD_PROTECTED, public_id="ABC")
    plain = ParsedLink(type=LinkType.FILE, public_id="DEF")
    assert protected.needs_password is True
    assert plain.needs_password is False


def test_the_package_still_imports_from_a_clean_interpreter():
    """Import smoke in a fresh process: a restored module could break at import."""
    done = subprocess.run(
        [sys.executable, "-c", "import megabasterd_cli.cli; print('ok')"],
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    assert "ok" in done.stdout
