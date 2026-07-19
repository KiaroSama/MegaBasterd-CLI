"""Cloud-tree mutations: mkdir, delete, move, rename, empty trash."""

from __future__ import annotations

import logging
import os

from .crypto import (
    a32_to_bytes,
    aes_key_wrap_encrypt,
    b64_url_encode,
    encrypt_attributes,
    unpack_file_key,
)
from .errors import AuthError, MegaError
from .nodes import NodeOperations
from .responses import _first_node_handle

log = logging.getLogger(__name__)


class CloudOperations(NodeOperations):
    """Mutating operations on the user's own cloud tree."""

    def mkdir(self, name: str, parent_handle: str | None = None) -> str:
        """Create a folder named `name` under `parent_handle` (default: root)."""
        if not self.session:
            raise AuthError(message="Not logged in")
        parent = parent_handle or self.find_root()
        if not parent:
            raise MegaError(message="No parent folder available")

        folder_key = os.urandom(16)
        enc_attrs = encrypt_attributes({"n": name}, folder_key)
        wrapped_key = aes_key_wrap_encrypt(folder_key, self.session.master_key)
        result = self.api.create_folder(
            parent_handle=parent,
            encrypted_attrs=b64_url_encode(enc_attrs),
            wrapped_key=b64_url_encode(wrapped_key),
        )
        self.invalidate_cache()
        return _first_node_handle(result, "folder creation")

    def delete(self, handle: str) -> None:
        """Move a node to trash."""
        if not self.session:
            raise AuthError(message="Not logged in")
        self.api.delete_node(handle)
        self.invalidate_cache()

    def move(self, handle: str, new_parent_handle: str) -> None:
        """Move a node to a different parent."""
        if not self.session:
            raise AuthError(message="Not logged in")
        self.api.move_node(handle, new_parent_handle)
        self.invalidate_cache()

    def rename(self, handle: str, new_name: str) -> None:
        """Rename a node by writing new encrypted attributes."""
        if not self.session:
            raise AuthError(message="Not logged in")
        node = self.find_node(handle=handle)
        if not node:
            raise MegaError(message=f"Node not found: {handle}")
        # Resolve the wrapping key in the SAME branch that proves which one
        # exists; recomputing the condition later just to pick a key made the
        # invariant impossible to follow (and impossible to type-check).
        if node.is_file and node.file_key_a32:
            aes_key, _, _ = unpack_file_key(node.file_key_a32)
            raw_key = a32_to_bytes(node.file_key_a32)
        elif node.decrypted_key:
            aes_key = node.decrypted_key[:16]
            raw_key = node.decrypted_key
        else:
            raise MegaError(message="Cannot rename: missing node key")

        enc_attrs = encrypt_attributes({"n": new_name}, aes_key)
        # Re-wrap the original raw key with the master key (key-wrap mode)
        wrapped_raw = aes_key_wrap_encrypt(raw_key, self.session.master_key)
        self.api.rename_node(
            handle=handle,
            encrypted_attrs=b64_url_encode(enc_attrs),
            wrapped_key=b64_url_encode(wrapped_raw),
        )
        self.invalidate_cache()

    def empty_trash(self) -> None:
        """Permanently delete every node in the trash."""
        if not self.session:
            raise AuthError(message="Not logged in")
        trash = self.find_trash()
        if not trash:
            return
        for child in self.children_of(trash):
            try:
                self.api.delete_node(child.handle)
            except MegaError as exc:
                log.warning("Failed to delete %s: %s", child.handle, exc)
        self.invalidate_cache()
