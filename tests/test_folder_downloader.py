from pathlib import Path

from megabasterd_cli.core.folder_downloader import FolderNode, MegaFolderDownloader


def _folder(handle: str, parent: str, name: str) -> FolderNode:
    return FolderNode(
        handle=handle,
        parent=parent,
        node_type=1,
        size=0,
        name=name,
        key=b"",
    )


def _file(handle: str, parent: str, name: str) -> FolderNode:
    return FolderNode(
        handle=handle,
        parent=parent,
        node_type=0,
        size=10,
        name=name,
        key=b"",
        raw_key_a32=[0, 0, 0, 0, 0, 0, 0, 0],
    )


def test_folder_layout_preserves_root_and_nested_paths(tmp_path: Path):
    nodes = [
        _folder("root", "", "Root Folder"),
        _folder("sub", "root", "Season 01"),
        _file("deep", "sub", "Episode 01.mkv"),
        _file("top", "root", "cover.jpg"),
    ]

    paths = MegaFolderDownloader._build_directory_paths(nodes, tmp_path, "root")
    jobs = MegaFolderDownloader._build_file_jobs(nodes, tmp_path, "root")

    assert paths["root"] == tmp_path / "Root Folder"
    assert paths["sub"] == tmp_path / "Root Folder" / "Season 01"
    assert {
        node.handle: destination for node, destination in jobs
    } == {
        "deep": tmp_path / "Root Folder" / "Season 01" / "Episode 01.mkv",
        "top": tmp_path / "Root Folder" / "cover.jpg",
    }


def test_folder_layout_overwrites_existing_paths_by_default(tmp_path: Path):
    nodes = [
        _folder("root", "", "Root Folder"),
        _file("top", "root", "cover.jpg"),
    ]
    existing = tmp_path / "Root Folder" / "cover.jpg"
    existing.parent.mkdir(parents=True)
    existing.write_bytes(b"old")

    jobs = MegaFolderDownloader._build_file_jobs(nodes, tmp_path, "root")

    assert jobs[0][1] == existing


def test_folder_in_folder_layout_uses_selected_subfolder_as_root(tmp_path: Path):
    nodes = [
        _folder("root", "", "Root Folder"),
        _folder("sub", "root", "Season 01"),
        _folder("nested", "sub", "Extras"),
        _file("deep", "nested", "Trailer.mkv"),
    ]
    keep = MegaFolderDownloader._subtree_handles(nodes, "sub")
    subtree = [node for node in nodes if node.handle in keep]

    jobs = MegaFolderDownloader._build_file_jobs(subtree, tmp_path, "sub")

    assert jobs[0][1] == tmp_path / "Season 01" / "Extras" / "Trailer.mkv"


def test_single_file_in_folder_keeps_full_mega_path(tmp_path: Path):
    nodes = [
        _folder("root", "", "Root Folder"),
        _folder("sub", "root", "Season 01"),
        _file("deep", "sub", "Episode 01.mkv"),
    ]

    destination = MegaFolderDownloader._local_path_for_node(
        nodes, tmp_path, "root", nodes[-1]
    )

    assert destination == tmp_path / "Root Folder" / "Season 01" / "Episode 01.mkv"
