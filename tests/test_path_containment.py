"""Regression tests for folder-download path traversal and output containment.

These cover Priority 1 of the security remediation: attacker-controlled MEGA
node names must never escape the chosen output directory.
"""

from pathlib import Path

import pytest

from megabasterd_cli.core.folder_downloader import FolderNode, MegaFolderDownloader
from megabasterd_cli.utils.helpers import (
    ensure_within_directory,
    is_within_directory,
    sanitize_filename,
)


# ---------------------------------------------------------------------------
# Component sanitization
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [".", "..", "...", "   ", "", ". .", " .. ", "....", "\t"],
)
def test_sanitize_filename_never_traversal_or_empty(name: str) -> None:
    result = sanitize_filename(name)
    assert result not in {"", ".", ".."}
    assert set(result) > {"."} or "." not in result  # not dot-only
    assert "/" not in result and "\\" not in result


def test_sanitize_filename_strips_path_separators() -> None:
    assert "/" not in sanitize_filename("a/b/c")
    assert "\\" not in sanitize_filename("a\\b\\c")


def test_sanitize_filename_dotfile_preserved() -> None:
    # A leading dot (legitimate on POSIX) is preserved; only traversal forms blocked.
    assert sanitize_filename(".gitignore") == ".gitignore"


def test_sanitize_filename_strips_trailing_dot_space() -> None:
    assert sanitize_filename("evil.") == "evil"
    assert sanitize_filename("name ") == "name"


def test_sanitize_filename_existing_behaviour_unchanged() -> None:
    assert sanitize_filename('a<b>c:d"e/f\\g|h?i*j') == "a_b_c_d_e_f_g_h_i_j"
    assert sanitize_filename("CON.txt").startswith("_CON")
    assert sanitize_filename("") == "unnamed"


# ---------------------------------------------------------------------------
# Containment helper
# ---------------------------------------------------------------------------


def test_is_within_directory_true_for_child(tmp_path: Path) -> None:
    assert is_within_directory(tmp_path, tmp_path / "a" / "b.txt")
    assert is_within_directory(tmp_path, tmp_path)


def test_is_within_directory_rejects_escape(tmp_path: Path) -> None:
    assert not is_within_directory(tmp_path, tmp_path / ".." / "evil.txt")
    assert not is_within_directory(tmp_path / "out", tmp_path / "out-evil")


def test_ensure_within_directory_raises(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        ensure_within_directory(tmp_path, tmp_path / ".." / "x")


# ---------------------------------------------------------------------------
# Folder downloader path building with malicious names
# ---------------------------------------------------------------------------


def _folder(handle: str, parent: str, name: str) -> FolderNode:
    return FolderNode(handle=handle, parent=parent, node_type=1, size=0, name=name, key=b"")


def _file(handle: str, parent: str, name: str) -> FolderNode:
    return FolderNode(
        handle=handle,
        parent=parent,
        node_type=0,
        size=10,
        name=name,
        key=b"",
        raw_key_a32=[0] * 8,
    )


def test_malicious_root_named_dotdot_stays_contained(tmp_path: Path) -> None:
    nodes = [
        _folder("root", "", ".."),
        _file("top", "root", "payload.exe"),
    ]
    jobs = MegaFolderDownloader._build_file_jobs(nodes, tmp_path, "root")
    dest = jobs[0][1]
    assert is_within_directory(tmp_path, dest)
    # The ".." root name was neutralized, not used as a parent reference.
    assert ".." not in dest.parts


def test_nested_dotdot_folder_stays_contained(tmp_path: Path) -> None:
    nodes = [
        _folder("root", "", "Root"),
        _folder("evil", "root", ".."),
        _file("f", "evil", "x.bin"),
    ]
    paths = MegaFolderDownloader._build_directory_paths(nodes, tmp_path, "root")
    for p in paths.values():
        assert is_within_directory(tmp_path, p)
    jobs = MegaFolderDownloader._build_file_jobs(nodes, tmp_path, "root")
    for _node, dest in jobs:
        assert is_within_directory(tmp_path, dest)


def test_malicious_file_component_stays_contained(tmp_path: Path) -> None:
    nodes = [
        _folder("root", "", "Root"),
        _file("f", "root", ".."),
    ]
    dest = MegaFolderDownloader._local_path_for_node(nodes, tmp_path, "root", nodes[-1])
    assert is_within_directory(tmp_path, dest)


def test_normal_layout_still_correct(tmp_path: Path) -> None:
    nodes = [
        _folder("root", "", "Root Folder"),
        _folder("sub", "root", "Season 01"),
        _file("deep", "sub", "Episode 01.mkv"),
    ]
    jobs = MegaFolderDownloader._build_file_jobs(nodes, tmp_path, "root")
    assert jobs[0][1] == tmp_path / "Root Folder" / "Season 01" / "Episode 01.mkv"


def test_no_files_created_outside_output_root(tmp_path: Path) -> None:
    output = tmp_path / "out"
    output.mkdir()
    nodes = [
        _folder("root", "", ".."),
        _folder("evil", "root", ".."),
        _file("f", "evil", "escape.bin"),
    ]
    # Building jobs creates the directory tree; verify nothing escaped `output`.
    MegaFolderDownloader._build_file_jobs(nodes, output, "root")
    siblings = [p for p in tmp_path.iterdir() if p != output]
    assert siblings == [], f"Unexpected files created outside output root: {siblings}"
