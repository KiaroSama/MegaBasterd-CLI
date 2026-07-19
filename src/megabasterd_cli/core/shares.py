"""Public link export and importing a public folder share into the user's tree."""

from __future__ import annotations

import logging
from collections.abc import Iterable

from .crypto import (
    a32_to_bytes,
    aes_key_wrap_decrypt,
    aes_key_wrap_encrypt,
    b64_url_decode,
    b64_url_encode,
    str_to_a32,
)
from .errors import AuthError, MegaError
from .nodes import NodeOperations
from .responses import _expect_field, _expect_mapping, _first_node_handle

log = logging.getLogger(__name__)


class ShareOperations(NodeOperations):
    """Export nodes as public links and import public folder shares."""

    # ------------------------------------------------------------------
    # Public link generation
    # ------------------------------------------------------------------
    def export_link(self, handle: str, password: str | None = None) -> str:
        """Generate a public MEGA URL for a node owned by the current user.

        If `password` is supplied, a #P! password-protected link is returned;
        otherwise a standard #!/file or #!/folder link.
        """
        from .crypto import encrypt_password_link

        if not self.session:
            raise AuthError(message="Not logged in")
        node = self.find_node(handle=handle)
        if not node:
            raise MegaError(message=f"Node not found: {handle}")

        public_handle = self.api.export_node(handle)
        if not isinstance(public_handle, str):
            raise MegaError(message=f"Unexpected export response: {public_handle}")

        if node.is_file and node.file_key_a32:
            key_b64 = b64_url_encode(a32_to_bytes(node.file_key_a32))
            url = f"https://mega.nz/file/{public_handle}#{key_b64}"
            raw_key = a32_to_bytes(node.file_key_a32)
            node_type = 0
        elif node.is_folder and node.decrypted_key:
            key_b64 = b64_url_encode(node.decrypted_key[:16])
            url = f"https://mega.nz/folder/{public_handle}#{key_b64}"
            raw_key = node.decrypted_key[:16]
            node_type = 1
        else:
            raise MegaError(message="Cannot export node without a key")

        if password is None:
            return url

        blob = encrypt_password_link(
            node_type=node_type,
            public_handle=b64_url_decode(public_handle),
            raw_key=raw_key,
            password=password,
        )
        return f"https://mega.nz/#P!{blob}"

    def remove_export(self, handle: str) -> None:
        """Disable a previously created public link."""
        self.api.remove_export(handle)

    # ------------------------------------------------------------------
    # Importing a public folder share into the user's tree
    # ------------------------------------------------------------------
    def import_public_share(
        self,
        share_url: str,
        target_parent: str | None = None,
        include: Iterable[str] | None = None,
    ) -> list[str]:
        """Copy the contents of a public folder share into the user's account,
        preserving the folder hierarchy.

        Each node is imported with its correct type (file vs folder); folder
        nodes are processed before any of their children so the children land
        inside the freshly-imported parent. Source-node handles are mapped to
        the user's newly-created handles via `parent_map`.

        Returns the user-side handles of every imported node. No content
        bytes are transferred: MEGA does a server-side copy by re-wrapping
        each node's key with the caller's master key.
        """
        from .links import LinkType, parse_link

        if not self.session:
            raise AuthError(message="Not logged in")

        parsed = parse_link(share_url)
        if parsed.type not in (LinkType.FOLDER, LinkType.FOLDER_IN_FOLDER):
            raise MegaError(message="Only public folder shares can be imported")

        target = target_parent or self.find_root()
        if not target:
            raise MegaError(message="No target folder for import")

        folder_key = a32_to_bytes(str_to_a32(parsed.key))
        listing = _expect_mapping(
            self.api.get_public_folder_listing(parsed.public_id), "share listing"
        )
        raw_nodes = _expect_field(listing, "f", list, "share listing", default=[])
        if not raw_nodes:
            return []
        # Every loop below indexes `n["h"]`, `n.get("p")` and `n.get("t")`, so
        # the whole listing is proven well-formed once, here, rather than
        # failing halfway through an import with a bare KeyError.
        for raw in raw_nodes:
            _expect_field(_expect_mapping(raw, "shared node"), "h", str, "shared node")
            _expect_field(raw, "p", str, "shared node", default="")
            _expect_field(raw, "t", int, "shared node", default=0)
            _expect_field(raw, "k", str, "shared node", default="")
            _expect_field(raw, "a", str, "shared node", default="")

        # Identify the share root: its parent doesn't appear in the listing.
        by_handle = {n["h"]: n for n in raw_nodes if "h" in n}
        all_handles = set(by_handle.keys())
        root_candidates = [n for n in raw_nodes if n.get("p") and n.get("p") not in all_handles]
        if not root_candidates:
            root_candidates = [raw_nodes[0]]
        share_root_parent = root_candidates[0].get("p", "")

        if parsed.type == LinkType.FOLDER_IN_FOLDER:
            if not parsed.subpath or parsed.subpath not in by_handle:
                raise MegaError(message=f"Subfolder not found in share: {parsed.subpath}")
            children: dict[str, list[str]] = {}
            for node in raw_nodes:
                children.setdefault(node.get("p", ""), []).append(node["h"])
            keep = {parsed.subpath}
            stack = [parsed.subpath]
            while stack:
                current = stack.pop()
                for child in children.get(current, []):
                    if child not in keep:
                        keep.add(child)
                        stack.append(child)
            raw_nodes = [n for n in raw_nodes if n["h"] in keep]
            share_root_parent = by_handle[parsed.subpath].get("p", "")

        # Topologically order the listing so every parent precedes its
        # children (BFS from the share root).
        children_by_parent: dict[str, list[dict]] = {}
        for node in raw_nodes:
            children_by_parent.setdefault(node.get("p", ""), []).append(node)

        ordered: list[dict] = []
        seen: set[str] = set()
        # Start with the nodes whose parent is the share root parent
        queue_layer = list(children_by_parent.get(share_root_parent, []))
        while queue_layer:
            next_layer: list[dict] = []
            for node in queue_layer:
                if node["h"] in seen:
                    continue
                ordered.append(node)
                seen.add(node["h"])
                next_layer.extend(children_by_parent.get(node["h"], []))
            queue_layer = next_layer
        # Anything left (orphaned) — append at the end
        for node in raw_nodes:
            if node["h"] not in seen:
                ordered.append(node)
                seen.add(node["h"])

        # Optional include filter — if provided, also include every ancestor
        # of an included node so the hierarchy stays intact.
        if include:
            wanted = set(include)
            keep: set[str] = set()
            for h in wanted:
                node = by_handle.get(h)
                while node is not None and node["h"] not in keep:
                    keep.add(node["h"])
                    node = by_handle.get(node.get("p", ""))
            ordered = [n for n in ordered if n["h"] in keep]

        parent_map: dict[str, str] = {share_root_parent: target}
        new_handles: list[str] = []
        for raw in ordered:
            src_handle = raw["h"]
            node_type = raw.get("t", 0)
            if node_type not in (0, 1):
                continue  # Skip system nodes (root/inbox/trash) which won't appear here anyway

            raw_key = raw.get("k", "") or ""
            _, wrapped = raw_key.split(":", 1) if ":" in raw_key else ("", raw_key)
            if not wrapped:
                log.warning("Skipping %s: empty wrapped key", src_handle)
                continue
            try:
                shared_key_bytes = aes_key_wrap_decrypt(b64_url_decode(wrapped), folder_key)
            except Exception as exc:  # noqa: BLE001
                log.warning("Skipping %s: key decrypt failed: %s", src_handle, exc)
                continue
            key_len = 32 if node_type == 0 else 16
            node_key = shared_key_bytes[:key_len]
            user_wrapped = aes_key_wrap_encrypt(node_key, self.session.master_key)

            local_parent = parent_map.get(raw.get("p", ""), target)
            try:
                result = self.api.import_node_from_share(
                    target_parent=local_parent,
                    source_handle=src_handle,
                    encrypted_attrs=raw.get("a", "") or "",
                    wrapped_key=b64_url_encode(user_wrapped),
                    share_handle=parsed.public_id,
                    node_type=node_type,
                )
            except MegaError as exc:
                log.warning("Failed to import %s: %s", src_handle, exc)
                continue

            new_handle = _first_node_handle(result, "share import")
            if new_handle:
                new_handles.append(new_handle)
                parent_map[src_handle] = new_handle

        self.invalidate_cache()
        return new_handles
