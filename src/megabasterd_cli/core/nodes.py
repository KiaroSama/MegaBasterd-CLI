"""The MEGA node tree: the node model, key/attribute decryption, and listings."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .api import MegaAPIClient
from .crypto import (
    aes_key_wrap_decrypt,
    b64_url_decode,
    bytes_to_a32,
    decrypt_attributes,
    unpack_file_key,
)
from .errors import AuthError, MegaError
from .responses import _expect_field, _expect_mapping

if TYPE_CHECKING:  # avoids a runtime import cycle with .auth
    from .auth import MegaSession

log = logging.getLogger(__name__)


@dataclass
class MegaNode:
    """A node (file or folder) in the user's MEGA tree or in a shared folder."""

    handle: str
    parent: str
    owner: str
    node_type: int  # 0=file, 1=folder, 2=root, 3=inbox, 4=trash
    size: int
    timestamp: int
    raw_attrs: bytes
    raw_key: str
    decrypted_key: bytes | None = None
    name: str | None = None
    file_key_a32: list[int] | None = None  # 8-int key for files only

    @property
    def is_file(self) -> bool:
        return self.node_type == 0

    @property
    def is_folder(self) -> bool:
        return self.node_type == 1

    @property
    def is_root(self) -> bool:
        return self.node_type == 2

    @property
    def is_trash(self) -> bool:
        return self.node_type == 4

    @property
    def is_inbox(self) -> bool:
        return self.node_type == 3


class NodeOperations:
    """Node decryption, the cached node listing, and lookups over it.

    Shared base of the client mixins: it owns the client state (`api`,
    `session`, `_node_cache`) every other mixin reads.
    """

    api: MegaAPIClient
    session: MegaSession | None
    _node_cache: list[MegaNode] | None

    def invalidate_cache(self) -> None:
        """Clear cached cloud node listings after a mutation."""
        self._node_cache = None

    # ------------------------------------------------------------------
    # Node decryption helpers
    # ------------------------------------------------------------------
    def _decrypt_node_key(self, encoded_key: str, master_key: bytes) -> bytes:
        """Decrypt a node's wrapped key. The format is 'user_handle:wrapped_key'.

        MEGA wraps node keys with key-wrap mode (each 16-byte block ECB-style
        with zero IV), NOT chained CBC. Use `aes_key_wrap_decrypt`.
        """
        if ":" in encoded_key:
            _, wrapped = encoded_key.split(":", 1)
        else:
            wrapped = encoded_key
        wrapped_bytes = b64_url_decode(wrapped)
        return aes_key_wrap_decrypt(wrapped_bytes, master_key)

    def decrypt_node(self, raw_node: dict, master_key: bytes | None = None) -> MegaNode:
        """Decrypt a node dict from the API into a MegaNode."""
        master_key = master_key or (self.session.master_key if self.session else None)
        if master_key is None:
            raise AuthError(message="No master key available")

        raw_node = _expect_mapping(raw_node, "node")
        raw_attrs_b64 = _expect_field(raw_node, "a", str, "node", default="")
        node = MegaNode(
            handle=_expect_field(raw_node, "h", str, "node"),
            parent=_expect_field(raw_node, "p", str, "node", default=""),
            owner=_expect_field(raw_node, "u", str, "node", default=""),
            node_type=_expect_field(raw_node, "t", int, "node"),
            size=_expect_field(raw_node, "s", int, "node", default=0),
            timestamp=_expect_field(raw_node, "ts", int, "node", default=0),
            raw_attrs=b64_url_decode(raw_attrs_b64) if raw_attrs_b64 else b"",
            raw_key=_expect_field(raw_node, "k", str, "node", default=""),
        )

        if node.raw_key:
            try:
                decrypted_key = self._decrypt_node_key(node.raw_key, master_key)
                node.decrypted_key = decrypted_key

                if node.is_file and len(decrypted_key) >= 32:
                    key_a32 = bytes_to_a32(decrypted_key[:32])
                    node.file_key_a32 = key_a32
                    aes_key, _, _ = unpack_file_key(key_a32)
                    attrs = decrypt_attributes(node.raw_attrs, aes_key)
                elif len(decrypted_key) >= 16:
                    attrs = decrypt_attributes(node.raw_attrs, decrypted_key[:16])
                else:
                    # The slice used to run unchecked, feeding AES a short key.
                    raise MegaError(
                        message=f"node key is {len(decrypted_key)} bytes, expected at least 16"
                    )

                if attrs:
                    node.name = attrs.get("n")
            except Exception as e:
                log.warning("Failed to decrypt node %s: %s", node.handle, e)

        return node

    # ------------------------------------------------------------------
    # File and folder listings
    # ------------------------------------------------------------------
    def list_files(self, refresh: bool = False) -> list[MegaNode]:
        """List all nodes in the user's MEGA tree (requires login)."""
        if not self.session:
            raise AuthError(message="Not logged in")
        if self._node_cache is not None and not refresh:
            return list(self._node_cache)
        result = _expect_mapping(self.api.request({"a": "f", "c": 1}), "file listing")
        raw_nodes = _expect_field(result, "f", list, "file listing", default=[])
        nodes = [self.decrypt_node(raw) for raw in raw_nodes]
        self._node_cache = nodes
        return list(nodes)

    def find_node(
        self,
        handle: str | None = None,
        path: str | None = None,
    ) -> MegaNode | None:
        """Find a node by handle or by path-like 'folder/sub/file.ext'."""
        nodes = self.list_files()
        if handle:
            for n in nodes:
                if n.handle == handle:
                    return n
            return None
        if path is None:
            return None

        parts = [p for p in path.replace("\\", "/").split("/") if p]
        # Start at root
        current_handle = self.find_root()
        if current_handle is None:
            return None
        by_parent: dict[str, list[MegaNode]] = {}
        for n in nodes:
            by_parent.setdefault(n.parent, []).append(n)

        cur = current_handle
        last_match: MegaNode | None = None
        for part in parts:
            children = by_parent.get(cur, [])
            match = next((c for c in children if c.name == part), None)
            if match is None:
                return None
            cur = match.handle
            last_match = match
        return last_match

    def find_root(self) -> str | None:
        """Find the root node handle (where uploads usually go)."""
        for node in self.list_files():
            if node.is_root:
                return node.handle
        return None

    def find_trash(self) -> str | None:
        for node in self.list_files():
            if node.is_trash:
                return node.handle
        return None

    def children_of(self, parent_handle: str) -> list[MegaNode]:
        return [n for n in self.list_files() if n.parent == parent_handle]

    def search(self, pattern: str, regex: bool = False) -> list[MegaNode]:
        """Search the user's cloud by filename. Case-insensitive substring or regex."""
        import re as _re

        nodes = self.list_files()
        if regex:
            rx = _re.compile(pattern, _re.IGNORECASE)
            return [n for n in nodes if n.name and rx.search(n.name)]
        needle = pattern.lower()
        return [n for n in nodes if n.name and needle in n.name.lower()]

    def find_inbox(self) -> str | None:
        """Compatibility surface retained for the 1.x series."""
        for node in self.list_files():
            if node.is_inbox:
                return node.handle
        return None
