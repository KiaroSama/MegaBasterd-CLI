"""High-level MEGA client: login, session management, file/folder operations."""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from .api import MegaAPIClient
from .crypto import (
    a32_to_bytes,
    aes_cbc_decrypt,
    aes_cbc_decrypt_a32,
    aes_cbc_encrypt,
    aes_key_wrap_decrypt,
    aes_key_wrap_encrypt,
    b64_url_decode,
    b64_url_encode,
    bytes_to_a32,
    decrypt_attributes,
    derive_key_legacy,
    derive_key_v2,
    encrypt_attributes,
    str_to_a32,
    stringhash,
    unpack_file_key,
)
from .errors import AuthError, MegaError

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


@dataclass
class MegaSession:
    """Active MEGA login session."""
    sid: str
    master_key: bytes  # 16 bytes
    rsa_private_key: bytes | None = None
    user_handle: str = ""
    email: str = ""


class MegaClient:
    """High-level MEGA client.

    Wraps MegaAPIClient and adds login, session restoration, and node decryption.
    """

    def __init__(self, api: MegaAPIClient | None = None):
        self.api = api or MegaAPIClient()
        self.session: MegaSession | None = None
        self._node_cache: list[MegaNode] | None = None

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------
    def login_anonymous(self) -> MegaSession:
        """Login without an account (ephemeral session)."""
        master_key = os.urandom(16)
        result = self.api.request({"a": "us0"})
        sid = result.get("tsid") or result.get("csid", "")

        self.session = MegaSession(sid=sid, master_key=master_key)
        self.api.set_session(sid)
        return self.session

    def login(
        self,
        email: str,
        password: str,
        mfa_code: str | None = None,
        mfa_prompt: Callable[[], str] | None = None,
    ) -> MegaSession:
        """Login with email and password.

        Tries account version 2 (PBKDF2) first, then falls back to legacy v1.
        If the account requires multi-factor authentication, `mfa_code` is used
        if supplied, otherwise `mfa_prompt()` is invoked to obtain a code.
        """
        # Step 1: get the account version and salt
        prelogin = self.api.request({"a": "us0", "user": email.lower()})
        version = prelogin.get("v", 1)
        salt_b64 = prelogin.get("s", "")

        if version == 2:
            salt = b64_url_decode(salt_b64)
            derived = derive_key_v2(password, salt)
            login_key = derived[:16]
            password_hash = b64_url_encode(derived[16:])
        else:
            derived_a32 = derive_key_legacy(password)
            login_key = a32_to_bytes(derived_a32)
            password_hash = stringhash(email.lower(), derived_a32)

        # Step 2: actual login (handle 2FA challenge)
        try:
            result = self.api.request(
                {"a": "us", "user": email.lower(), "uh": password_hash}
            )
        except MegaError as exc:
            if exc.code == -26:  # EMFAREQUIRED
                code = mfa_code
                if not code and mfa_prompt:
                    code = mfa_prompt()
                if not code:
                    raise AuthError(
                        code=-26,
                        message="Account requires 2FA; supply mfa_code or mfa_prompt",
                    ) from exc
                result = self.api.login_with_mfa(email, password_hash, code)
            else:
                raise

        # Step 3: decrypt the master key
        encrypted_master_a32 = str_to_a32(result["k"])
        master_a32 = aes_cbc_decrypt_a32(encrypted_master_a32, bytes_to_a32(login_key))
        master_key = a32_to_bytes(master_a32)

        # Step 4: derive the session ID
        if "tsid" in result:
            sid = result["tsid"]
            rsa_priv = None
        else:
            encrypted_rsa_priv = b64_url_decode(result["privk"])
            csid_encrypted = b64_url_decode(result["csid"])
            rsa_priv = aes_cbc_decrypt(encrypted_rsa_priv, master_key)
            sid = self._decode_session_id(csid_encrypted, rsa_priv)

        self.session = MegaSession(
            sid=sid,
            master_key=master_key,
            rsa_private_key=rsa_priv,
            user_handle=result.get("u", ""),
            email=email,
        )
        self.api.set_session(sid)
        return self.session

    def restore_session(self, session: MegaSession) -> bool:
        """Restore a previously-saved session. Returns True if the SID still works."""
        self.api.set_session(session.sid)
        self.session = session
        try:
            self.api.get_user_info()
            return True
        except MegaError as exc:
            log.info("Saved session is no longer valid: %s", exc)
            self.api.clear_session()
            self.session = None
            return False

    def _decode_session_id(self, csid_encrypted: bytes, rsa_priv_blob: bytes) -> str:
        """Decode the session ID using the RSA private key (account v1/v2).

        The RSA private key is stored as four big-endian length-prefixed integers
        (p, q, d, u). We decrypt CSID with d/n and take the first 43 bytes.
        """
        from Crypto.PublicKey import RSA

        parts = []
        cursor = 0
        for _ in range(4):
            if cursor + 2 > len(rsa_priv_blob):
                break
            bit_len = int.from_bytes(rsa_priv_blob[cursor:cursor + 2], "big")
            byte_len = (bit_len + 7) // 8
            cursor += 2
            parts.append(int.from_bytes(rsa_priv_blob[cursor:cursor + byte_len], "big"))
            cursor += byte_len

        if len(parts) < 4:
            raise AuthError(message="Malformed RSA private key in login response")

        p, q, d, _u = parts
        n = p * q
        key = RSA.construct((n, 0x10001, d, p, q))
        decrypted = key._decrypt(int.from_bytes(csid_encrypted, "big"))
        decrypted_bytes = decrypted.to_bytes((decrypted.bit_length() + 7) // 8, "big")
        return b64_url_encode(decrypted_bytes[:43])

    def logout(self) -> None:
        """Invalidate the current session."""
        if self.session:
            try:
                self.api.request({"a": "sml"})
            except MegaError:
                pass
        self.api.clear_session()
        self.session = None
        self._node_cache = None

    # ------------------------------------------------------------------
    # User info / quota
    # ------------------------------------------------------------------
    def get_quota(self) -> dict[str, Any]:
        """Return storage and bandwidth quota for the current session."""
        if not self.session:
            raise AuthError(message="Not logged in")
        return self.api.get_account_quota()

    def get_user_info(self) -> dict[str, Any]:
        if not self.session:
            raise AuthError(message="Not logged in")
        return self.api.get_user_info()

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

        node = MegaNode(
            handle=raw_node["h"],
            parent=raw_node.get("p", ""),
            owner=raw_node.get("u", ""),
            node_type=raw_node["t"],
            size=raw_node.get("s", 0),
            timestamp=raw_node.get("ts", 0),
            raw_attrs=b64_url_decode(raw_node.get("a", "") or "") if raw_node.get("a") else b"",
            raw_key=raw_node.get("k", ""),
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
                else:
                    attrs = decrypt_attributes(node.raw_attrs, decrypted_key[:16])

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
        result = self.api.request({"a": "f", "c": 1})
        nodes = [self.decrypt_node(raw) for raw in result.get("f", [])]
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

    def find_inbox(self) -> str | None:
        for node in self.list_files():
            if node.is_inbox:
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

    # ------------------------------------------------------------------
    # Folder / file mutations
    # ------------------------------------------------------------------
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
        nodes = result.get("f", []) if isinstance(result, dict) else []
        self._node_cache = None  # Invalidate
        return nodes[0]["h"] if nodes else ""

    def delete(self, handle: str) -> None:
        """Move a node to trash."""
        if not self.session:
            raise AuthError(message="Not logged in")
        self.api.delete_node(handle)
        self._node_cache = None

    def move(self, handle: str, new_parent_handle: str) -> None:
        """Move a node to a different parent."""
        if not self.session:
            raise AuthError(message="Not logged in")
        self.api.move_node(handle, new_parent_handle)
        self._node_cache = None

    def rename(self, handle: str, new_name: str) -> None:
        """Rename a node by writing new encrypted attributes."""
        if not self.session:
            raise AuthError(message="Not logged in")
        node = self.find_node(handle=handle)
        if not node:
            raise MegaError(message=f"Node not found: {handle}")
        if node.is_file and node.file_key_a32:
            aes_key, _, _ = unpack_file_key(node.file_key_a32)
        elif node.decrypted_key:
            aes_key = node.decrypted_key[:16]
        else:
            raise MegaError(message="Cannot rename: missing node key")

        enc_attrs = encrypt_attributes({"n": new_name}, aes_key)
        # Re-wrap the original raw key with the master key (key-wrap mode)
        wrapped_raw = aes_key_wrap_encrypt(
            a32_to_bytes(node.file_key_a32) if node.file_key_a32 else node.decrypted_key,
            self.session.master_key,
        )
        self.api.rename_node(
            handle=handle,
            encrypted_attrs=b64_url_encode(enc_attrs),
            wrapped_key=b64_url_encode(wrapped_raw),
        )
        self._node_cache = None

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
        self._node_cache = None

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
        listing = self.api.get_public_folder_listing(parsed.public_id)
        raw_nodes = listing.get("f", [])
        if not raw_nodes:
            return []

        # Identify the share root: its parent doesn't appear in the listing.
        by_handle = {n["h"]: n for n in raw_nodes if "h" in n}
        all_handles = set(by_handle.keys())
        root_candidates = [
            n for n in raw_nodes
            if n.get("p") and n.get("p") not in all_handles
        ]
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
        ordered: list[dict] = []
        seen: set[str] = set()
        # Start with the nodes whose parent is the share root parent
        queue_layer = [n for n in raw_nodes if n.get("p") == share_root_parent]
        while queue_layer:
            next_layer: list[dict] = []
            for node in queue_layer:
                if node["h"] in seen:
                    continue
                ordered.append(node)
                seen.add(node["h"])
                next_layer.extend(
                    c for c in raw_nodes if c.get("p") == node["h"]
                )
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
                shared_key_bytes = aes_key_wrap_decrypt(
                    b64_url_decode(wrapped), folder_key
                )
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

            imported_nodes = result.get("f", []) if isinstance(result, dict) else []
            if imported_nodes:
                new_handle = imported_nodes[0]["h"]
                new_handles.append(new_handle)
                parent_map[src_handle] = new_handle

        self._node_cache = None
        return new_handles

    # ------------------------------------------------------------------
    # Session persistence
    # ------------------------------------------------------------------
    def save_session(self, path: Path) -> None:
        """Serialize the current session to `path` as JSON (no encryption!)."""
        if not self.session:
            raise AuthError(message="Not logged in")
        data = {
            "sid": self.session.sid,
            "master_key": self.session.master_key.hex(),
            "rsa_private_key": (
                self.session.rsa_private_key.hex()
                if self.session.rsa_private_key else None
            ),
            "user_handle": self.session.user_handle,
            "email": self.session.email,
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f)
        try:
            os.chmod(path, 0o600)
        except (OSError, AttributeError):
            pass

    @staticmethod
    def load_session(path: Path) -> MegaSession | None:
        """Read a saved session JSON. Returns None if the file is missing/corrupt."""
        if not path.exists():
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            rsa = data.get("rsa_private_key")
            return MegaSession(
                sid=data["sid"],
                master_key=bytes.fromhex(data["master_key"]),
                rsa_private_key=bytes.fromhex(rsa) if rsa else None,
                user_handle=data.get("user_handle", ""),
                email=data.get("email", ""),
            )
        except (json.JSONDecodeError, KeyError, ValueError, OSError):
            return None
