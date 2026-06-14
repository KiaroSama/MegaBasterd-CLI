"""Public folder share traversal and bulk downloading.

A MEGA folder share gives access to a tree of nodes under a folder key. We:
1. Call the listing endpoint to get all nodes inside the folder.
2. Decrypt each node's metadata using the folder key.
3. Recreate the directory structure locally.
4. Download each file using MegaDownloader.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from ..utils.helpers import ensure_within_directory, sanitize_filename
from .crypto import (
    a32_to_bytes,
    aes_key_wrap_decrypt,
    b64_url_decode,
    bytes_to_a32,
    decrypt_attributes,
    str_to_a32,
    unpack_file_key,
)
from .downloader import DownloadProgress, DownloadResult, MegaDownloader
from .errors import TransferError
from .links import LinkType, parse_link

log = logging.getLogger(__name__)


@dataclass
class FolderNode:
    """A decrypted node inside a public folder share."""

    handle: str
    parent: str
    node_type: int  # 0=file, 1=folder
    size: int
    name: str
    key: bytes  # AES key for files, folder key for folders
    raw_key_a32: list[int] | None = None  # Full 8-int file key, only for files

    @property
    def is_file(self) -> bool:
        return self.node_type == 0


class MegaFolderDownloader:
    """Downloads an entire MEGA public folder share."""

    def __init__(self, downloader: MegaDownloader):
        self.downloader = downloader
        self.api = downloader.api

    def download_folder(
        self,
        url: str,
        output_dir: Path,
        on_progress: Callable[[DownloadProgress], None] | None = None,
        on_file_done: Callable[[DownloadResult], None] | None = None,
        on_folder_manifest: Callable[[list[tuple[FolderNode, Path]]], None] | None = None,
        on_file_progress: Callable[[Path, DownloadProgress], None] | None = None,
        parallel_files: int = 1,
    ) -> list[DownloadResult]:
        """Download every file inside a public folder share.

        `parallel_files` controls how many files are pulled simultaneously
        (each one still spawns the downloader's per-chunk workers internally).
        """
        parsed = parse_link(url)
        if parsed.type not in (LinkType.FOLDER, LinkType.FOLDER_IN_FOLDER):
            raise ValueError(f"Link is not a folder share: {parsed.type}")

        folder_key = a32_to_bytes(str_to_a32(parsed.key))
        listing = self.api.get_public_folder_listing(parsed.public_id)
        raw_nodes = listing.get("f", [])

        nodes = self._decrypt_folder_nodes(raw_nodes, folder_key)
        if not nodes:
            raise TransferError(message="No nodes returned for folder share")

        root_handle = (
            parsed.subpath
            if parsed.type == LinkType.FOLDER_IN_FOLDER and parsed.subpath
            else self._find_folder_root(nodes)
        )
        if parsed.type == LinkType.FOLDER_IN_FOLDER and not any(
            n.handle == root_handle and not n.is_file for n in nodes
        ):
            raise TransferError(message=f"Subfolder {root_handle!r} not found in share")
        if parsed.type == LinkType.FOLDER_IN_FOLDER:
            keep = self._subtree_handles(nodes, root_handle)
            nodes = [n for n in nodes if n.handle in keep]
        file_jobs = self._build_file_jobs(nodes, output_dir, root_handle)
        if on_folder_manifest:
            on_folder_manifest(file_jobs)

        return self._download_file_jobs(
            parsed.public_id,
            file_jobs,
            on_progress=on_progress,
            on_file_done=on_file_done,
            on_file_progress=on_file_progress,
            parallel_files=parallel_files,
        )

    def download_node_in_folder(
        self,
        url: str,
        output_dir: Path,
        on_progress: Callable[[DownloadProgress], None] | None = None,
        on_file_done: Callable[[DownloadResult], None] | None = None,
        on_folder_manifest: Callable[[list[tuple[FolderNode, Path]]], None] | None = None,
        on_file_progress: Callable[[Path, DownloadProgress], None] | None = None,
        parallel_files: int = 1,
    ) -> list[DownloadResult]:
        """Download a file or subfolder handle from a public folder share."""
        parsed = parse_link(url)
        if parsed.type != LinkType.FILE_IN_FOLDER or not parsed.subpath:
            raise ValueError(f"Link is not a node inside a folder share: {parsed.type}")

        folder_key = a32_to_bytes(str_to_a32(parsed.key))
        listing = self.api.get_public_folder_listing(parsed.public_id)
        nodes = self._decrypt_folder_nodes(listing.get("f", []), folder_key)
        if not nodes:
            raise TransferError(message="No nodes returned for folder share")

        target = next((n for n in nodes if n.handle == parsed.subpath), None)
        if target is None:
            raise TransferError(message=f"Node {parsed.subpath!r} not found in folder share")

        if target.is_file:
            root_handle = self._find_folder_root(nodes)
            destination = self._local_path_for_node(nodes, output_dir, root_handle, target)
            destination.parent.mkdir(parents=True, exist_ok=True)
            file_jobs = [(target, destination)]
        else:
            keep = self._subtree_handles(nodes, target.handle)
            subtree = [n for n in nodes if n.handle in keep]
            file_jobs = self._build_file_jobs(subtree, output_dir, target.handle)

        if on_folder_manifest:
            on_folder_manifest(file_jobs)

        return self._download_file_jobs(
            parsed.public_id,
            file_jobs,
            on_progress=on_progress,
            on_file_done=on_file_done,
            on_file_progress=on_file_progress,
            parallel_files=parallel_files,
        )

    def download_file_in_folder(
        self,
        url: str,
        output_dir: Path,
        on_progress: Callable[[DownloadProgress], None] | None = None,
    ) -> DownloadResult:
        """Download one file from a public folder while preserving its path."""
        parsed = parse_link(url)
        if parsed.type != LinkType.FILE_IN_FOLDER or not parsed.subpath:
            raise ValueError(f"Link is not a file inside a folder share: {parsed.type}")

        folder_key = a32_to_bytes(str_to_a32(parsed.key))
        listing = self.api.get_public_folder_listing(parsed.public_id)
        nodes = self._decrypt_folder_nodes(listing.get("f", []), folder_key)
        if not nodes:
            raise TransferError(message="No nodes returned for folder share")

        target = next(
            (n for n in nodes if n.handle == parsed.subpath and n.is_file),
            None,
        )
        if target is None:
            raise TransferError(message=f"File {parsed.subpath!r} not found in folder share")

        root_handle = self._find_folder_root(nodes)
        destination = self._local_path_for_node(nodes, output_dir, root_handle, target)
        destination.parent.mkdir(parents=True, exist_ok=True)
        return self._download_owned_file(parsed.public_id, target, destination, on_progress)

    def _download_file_jobs(
        self,
        folder_public_id: str,
        file_jobs: list[tuple[FolderNode, Path]],
        on_progress: Callable[[DownloadProgress], None] | None = None,
        on_file_done: Callable[[DownloadResult], None] | None = None,
        on_file_progress: Callable[[Path, DownloadProgress], None] | None = None,
        parallel_files: int = 1,
    ) -> list[DownloadResult]:
        """Download prepared folder-file jobs and fail if any file fails."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        results: list[DownloadResult] = []
        failures: list[str] = []
        if parallel_files <= 1:
            for node, destination in file_jobs:
                log.info("Downloading folder file: %s", destination)
                try:

                    def _progress(progress: DownloadProgress, path: Path = destination) -> None:
                        if on_file_progress:
                            on_file_progress(path, progress)
                        if on_progress:
                            on_progress(progress)

                    result = self._download_owned_file(
                        folder_public_id, node, destination, _progress
                    )
                    results.append(result)
                    if on_file_done:
                        on_file_done(result)
                except Exception as e:  # noqa: BLE001
                    log.error("Failed to download %s: %s", node.name, e)
                    failures.append(f"{node.name}: {e}")
        else:
            # Multiple files downloading in parallel: each needs its own downloader
            # instance because the downloader stores per-transfer state.
            from .downloader import MegaDownloader

            def _worker(job):
                node, destination = job
                worker_dl = MegaDownloader(
                    api=self.api,
                    max_workers=self.downloader.max_workers,
                    speed_limit_kbps=0,
                    verify_integrity=self.downloader.verify_integrity,
                    timeout=self.downloader.timeout,
                    proxies=self.downloader.proxies,
                    proxy_pool=self.downloader.proxy_pool,
                    force_proxy=self.downloader.force_proxy,
                    quota_wait_seconds=self.downloader.quota_wait_seconds,
                    quota_max_wait_loops=self.downloader.quota_max_wait_loops,
                    keep_state_files_on_error=self.downloader.keep_state_files_on_error,
                )
                worker_dl.limiter = self.downloader.limiter
                sub_folder = MegaFolderDownloader(worker_dl)

                def _progress(progress: DownloadProgress, path: Path = destination) -> None:
                    if on_file_progress:
                        on_file_progress(path, progress)
                    if on_progress:
                        on_progress(progress)

                return sub_folder._download_owned_file(
                    folder_public_id, node, destination, _progress
                )

            with ThreadPoolExecutor(max_workers=parallel_files) as pool:
                futures = {pool.submit(_worker, job): job for job in file_jobs}
                for fut in as_completed(futures):
                    node, _ = futures[fut]
                    try:
                        result = fut.result()
                        results.append(result)
                        if on_file_done:
                            on_file_done(result)
                    except Exception as e:  # noqa: BLE001
                        log.error("Failed to download %s: %s", node.name, e)
                        failures.append(f"{node.name}: {e}")

        if failures:
            sample = "; ".join(failures[:3])
            more = "" if len(failures) <= 3 else f"; and {len(failures) - 3} more"
            raise TransferError(message=f"{len(failures)} folder file(s) failed: {sample}{more}")
        return results

    def _decrypt_folder_nodes(self, raw_nodes: list[dict], folder_key: bytes) -> list[FolderNode]:
        """Decrypt the per-node attributes/keys using the folder share key."""
        decrypted: list[FolderNode] = []
        for raw in raw_nodes:
            raw_key = raw.get("k", "")
            node_type = raw.get("t", 0)

            if ":" in raw_key:
                _owner, wrapped = raw_key.split(":", 1)
            else:
                wrapped = raw_key
            if not wrapped:
                continue

            try:
                key_bytes = aes_key_wrap_decrypt(b64_url_decode(wrapped), folder_key)
            except Exception as e:
                log.warning("Skipping node %s (key decrypt failed: %s)", raw.get("h"), e)
                continue

            raw_key_a32 = None
            if node_type == 0:
                # File: 32-byte key, unpack for AES-CTR
                key_a32 = bytes_to_a32(key_bytes[:32])
                aes_key, _, _ = unpack_file_key(key_a32)
                attr_key = aes_key
                raw_key_a32 = key_a32
            else:
                attr_key = key_bytes[:16]

            attrs = decrypt_attributes(
                b64_url_decode(raw.get("a", "") or "") if raw.get("a") else b"",
                attr_key,
            )
            name = (attrs or {}).get("n") or raw.get("h", "unnamed")

            decrypted.append(
                FolderNode(
                    handle=raw["h"],
                    parent=raw.get("p", ""),
                    node_type=node_type,
                    size=raw.get("s", 0),
                    name=name,
                    key=key_bytes[:32],
                    raw_key_a32=raw_key_a32,
                )
            )
        return decrypted

    @staticmethod
    def _find_folder_root(nodes: list[FolderNode]) -> str:
        """The folder root has a parent that isn't in the listing."""
        handles = {n.handle for n in nodes}
        for n in nodes:
            if n.parent not in handles:
                return n.parent or n.handle
        return nodes[0].handle if nodes else ""

    @classmethod
    def _build_file_jobs(
        cls, nodes: list[FolderNode], output_dir: Path, root_handle: str
    ) -> list[tuple[FolderNode, Path]]:
        """Create local folders and file destinations for a folder subtree."""
        path_for_handle = cls._build_directory_paths(nodes, output_dir, root_handle)
        for path in path_for_handle.values():
            path.mkdir(parents=True, exist_ok=True)

        file_jobs: list[tuple[FolderNode, Path]] = []
        for node in nodes:
            if not node.is_file:
                continue
            parent_path = path_for_handle.get(node.parent, output_dir)
            parent_path.mkdir(parents=True, exist_ok=True)
            destination = parent_path / sanitize_filename(node.name)
            # Defense in depth: never write outside the chosen output root,
            # even if a symlink/reparse point inside it points elsewhere.
            ensure_within_directory(output_dir, destination)
            file_jobs.append((node, destination))
        return file_jobs

    @classmethod
    def _build_directory_paths(
        cls, nodes: list[FolderNode], output_dir: Path, root_handle: str
    ) -> dict[str, Path]:
        """Map folder handles to local paths, including the selected root name."""
        by_handle = {node.handle: node for node in nodes}
        root_node = by_handle.get(root_handle)
        if root_node and not root_node.is_file:
            root_path = output_dir / sanitize_filename(root_node.name)
        else:
            root_path = output_dir

        path_for_handle: dict[str, Path] = {root_handle: root_path}
        ensure_within_directory(output_dir, root_path)
        for node in cls._sort_by_depth(nodes, root_handle):
            if node.is_file or node.handle == root_handle:
                continue
            parent_path = path_for_handle.get(node.parent, root_path)
            child_path = parent_path / sanitize_filename(node.name)
            ensure_within_directory(output_dir, child_path)
            path_for_handle[node.handle] = child_path
        return path_for_handle

    @classmethod
    def _local_path_for_node(
        cls,
        nodes: list[FolderNode],
        output_dir: Path,
        root_handle: str,
        node: FolderNode,
    ) -> Path:
        """Return the exact local path for a single node inside a folder share."""
        by_handle = {item.handle: item for item in nodes}
        parts = [sanitize_filename(node.name)]
        current = by_handle.get(node.parent)
        while current is not None:
            parts.append(sanitize_filename(current.name))
            if current.handle == root_handle:
                break
            current = by_handle.get(current.parent)
        destination = output_dir.joinpath(*reversed(parts))
        ensure_within_directory(output_dir, destination)
        return destination

    @staticmethod
    def _sort_by_depth(nodes: list[FolderNode], root: str) -> list[FolderNode]:
        """Topologically sort nodes so parents come before children."""
        depth: dict[str, int] = {root: 0}
        by_handle = {n.handle: n for n in nodes}
        for n in nodes:
            if n.handle in depth:
                continue
            chain = []
            cur = n
            while cur and cur.handle not in depth:
                chain.append(cur)
                cur = by_handle.get(cur.parent)
            base = depth.get(cur.handle, 0) if cur else 0
            for i, c in enumerate(reversed(chain)):
                depth[c.handle] = base + i + 1
        return sorted(nodes, key=lambda n: depth.get(n.handle, 0))

    @staticmethod
    def _subtree_handles(nodes: list[FolderNode], root: str) -> set[str]:
        children: dict[str, list[str]] = {}
        for node in nodes:
            children.setdefault(node.parent, []).append(node.handle)
        keep = {root}
        stack = [root]
        while stack:
            current = stack.pop()
            for child in children.get(current, []):
                if child not in keep:
                    keep.add(child)
                    stack.append(child)
        return keep

    def _download_owned_file(
        self,
        folder_public_id: str,
        node: FolderNode,
        destination: Path,
        on_progress,
    ) -> DownloadResult:
        """Download one file from inside a public folder share."""
        info = self.downloader._get_with_quota_wait(
            lambda: self.api.request(
                {"a": "g", "g": 1, "n": node.handle},
                extra_params={"n": folder_public_id},
            )
        )
        if "g" not in info:
            raise TransferError(message=f"No download URL for {node.name}")

        from .crypto import unpack_file_key

        aes_key, nonce, mac_iv_a32 = unpack_file_key(node.raw_key_a32)

        # Closure that the downloader can call when the URL expires
        def _resolver() -> str:
            fresh = self.downloader._get_with_quota_wait(
                lambda: self.api.request(
                    {"a": "g", "g": 1, "n": node.handle},
                    extra_params={"n": folder_public_id},
                )
            )
            if "g" not in fresh:
                raise TransferError(message=f"Resolver got no URL for {node.handle}")
            return fresh["g"]

        return self.downloader._run_download(
            cdn_url=info["g"],
            file_size=int(info["s"]),
            aes_key=aes_key,
            nonce=nonce,
            mac_iv_a32=mac_iv_a32,
            destination=destination,
            source=f"folder:{folder_public_id}/{node.handle}",
            on_progress=on_progress,
            url_resolver=_resolver,
        )
