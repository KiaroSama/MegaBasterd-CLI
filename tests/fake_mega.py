"""An in-memory MEGA account that speaks the real wire shapes.

WHY THIS EXISTS. Every bug that has actually hurt this project was found by a
human doing a live run, never by the unit suite - the double-base64'd upload
token, the MPI prefix fed into the RSA exponentiation, `logout()` in six
teardowns. The reason is structural: the suite stubs `MegaClient` methods, so
nothing ever exercises the layer where those bugs live, which is the assembly
between a decrypted node and an API payload.

So this harness does NOT stub the client. It stubs the SERVER: it stores nodes
exactly as MEGA returns them - `{"h","p","u","t","s","ts","a","k"}`, attributes
AES-encrypted, keys wrapped with the master key - and lets a real `MegaClient`
run against it. `decrypt_node`, `find_node`, `unpack_file_key` and the key
re-wrapping in `rename`/`export_link` all execute for real.

That cuts both ways and is the point: a fixture built with the same helper the
code under test uses can only prove self-consistency. Compare
`tests/test_login_rsa_session_id.py`, whose csid fixture omitted the MPI prefix
because it was written to match the buggy reader. So the encryption here is
written from the MEGA format description - `a32`/key-wrap/attribute prefix -
and `test_fake_mega_harness.py` pins the wire shapes independently.

Not a mock framework. Add only what a test needs to observe.
"""

from __future__ import annotations

import json
import os

from megabasterd_cli.core.auth import MegaSession
from megabasterd_cli.core.client import MegaClient
from megabasterd_cli.core.crypto import (
    aes_key_wrap_encrypt,
    b64_url_encode,
    bytes_to_a32,
    encrypt_attributes,
    pack_file_key,
)
from megabasterd_cli.core.errors import MegaError

# Node type codes, straight from the protocol.
FILE, FOLDER, ROOT, INBOX, TRASH = 0, 1, 2, 3, 4

MASTER_KEY = bytes(range(16))
OWNER = "self0000"


class FakeMegaAPI:
    """The subset of `MegaAPIClient` the node/cloud/share layers actually call.

    Every mutating call is recorded in `self.calls` as `(action, kwargs)` so a
    test can assert on the PAYLOAD - which is where the encoding bugs live -
    and not merely on the fact that something was called.
    """

    def __init__(self, master_key: bytes = MASTER_KEY):
        self.master_key = master_key
        self.nodes: list[dict] = []
        self.calls: list[tuple[str, dict]] = []
        self.exported: dict[str, str] = {}  # node handle -> public handle
        self.shares: dict[str, list[dict]] = {}  # public id -> raw listing
        self._next = 0
        self.closed = False
        self.sid: str | None = None

    # -- building an account -------------------------------------------------

    def _handle(self, prefix: str = "h") -> str:
        self._next += 1
        return f"{prefix}{self._next:07d}"

    def add_node(
        self,
        name: str | None,
        node_type: int = FOLDER,
        parent: str = "",
        size: int = 0,
        key: bytes | None = None,
    ) -> str:
        """Append one node, encrypted the way MEGA stores it. Returns its handle.

        A file gets the full 32-byte packed key (AES key, nonce, MAC IV); a
        folder gets 16 bytes. That difference is not cosmetic - it is the branch
        `decrypt_node`, `rename` and `export_link` each take separately, and the
        one a 16-byte-only fixture would hide.
        """
        handle = self._handle()
        raw_key = ""
        attrs = b""
        if node_type in (FILE, FOLDER):
            if key is None:
                key = os.urandom(32) if node_type == FILE else os.urandom(16)
            aes_key = bytes_from_a32_pair(bytes_to_a32(key)) if node_type == FILE else key[:16]
            attrs = encrypt_attributes({"n": name}, aes_key)
            raw_key = f"{OWNER}:{b64_url_encode(aes_key_wrap_encrypt(key, self.master_key))}"
        self.nodes.append(
            {
                "h": handle,
                "p": parent,
                "u": OWNER,
                "t": node_type,
                "s": size,
                "ts": 1_700_000_000,
                "a": b64_url_encode(attrs) if attrs else "",
                "k": raw_key,
            }
        )
        return handle

    def add_file(self, name: str, parent: str, size: int = 1024) -> str:
        return self.add_node(name, FILE, parent, size)

    def add_folder(self, name: str, parent: str) -> str:
        return self.add_node(name, FOLDER, parent)

    def with_default_tree(self) -> FakeMegaAPI:
        """root + trash + inbox, the three system nodes every real account has."""
        self.root = self.add_node(None, ROOT)
        self.trash = self.add_node(None, TRASH)
        self.inbox = self.add_node(None, INBOX)
        return self

    # -- the transport -------------------------------------------------------

    def set_session(self, sid):
        self.sid = sid

    def clear_session(self):
        self.sid = None

    def close(self):
        self.closed = True

    def clone(self):
        return self

    def request(self, payload, extra_params=None):
        self.calls.append(("request", {"payload": payload}))
        action = payload.get("a") if isinstance(payload, dict) else None
        if action == "f":
            return {"f": list(self.nodes)}
        if action == "ug":
            return {"u": OWNER}
        raise AssertionError(f"FakeMegaAPI got an unscripted action: {action!r}")

    # -- cloud mutations -----------------------------------------------------

    def create_folder(self, parent_handle, encrypted_attrs, wrapped_key):
        self.calls.append(
            (
                "create_folder",
                {
                    "parent_handle": parent_handle,
                    "encrypted_attrs": encrypted_attrs,
                    "wrapped_key": wrapped_key,
                },
            )
        )
        handle = self._handle()
        self.nodes.append(
            {
                "h": handle,
                "p": parent_handle,
                "u": OWNER,
                "t": FOLDER,
                "s": 0,
                "ts": 1_700_000_000,
                "a": encrypted_attrs,
                "k": f"{OWNER}:{wrapped_key}",
            }
        )
        return {"f": [{"h": handle}]}

    def delete_node(self, handle):
        self.calls.append(("delete_node", {"handle": handle}))
        before = len(self.nodes)
        self.nodes = [n for n in self.nodes if n["h"] != handle]
        if len(self.nodes) == before:
            raise MegaError(code=-9)
        return 0

    def move_node(self, handle, new_parent):
        self.calls.append(("move_node", {"handle": handle, "new_parent": new_parent}))
        for node in self.nodes:
            if node["h"] == handle:
                node["p"] = new_parent
                return 0
        raise MegaError(code=-9)

    def rename_node(self, handle, encrypted_attrs, wrapped_key):
        self.calls.append(
            (
                "rename_node",
                {
                    "handle": handle,
                    "encrypted_attrs": encrypted_attrs,
                    "wrapped_key": wrapped_key,
                },
            )
        )
        for node in self.nodes:
            if node["h"] == handle:
                node["a"] = encrypted_attrs
                node["k"] = f"{OWNER}:{wrapped_key}"
                return 0
        raise MegaError(code=-9)

    # -- shares --------------------------------------------------------------

    def export_node(self, handle):
        self.calls.append(("export_node", {"handle": handle}))
        public = self.exported.get(handle) or b64_url_encode(os.urandom(6))
        self.exported[handle] = public
        return public

    def remove_export(self, handle):
        self.calls.append(("remove_export", {"handle": handle}))
        self.exported.pop(handle, None)
        return 0

    def get_public_folder_listing(self, public_id):
        self.calls.append(("get_public_folder_listing", {"public_id": public_id}))
        if public_id not in self.shares:
            raise MegaError(code=-9)
        return {"f": list(self.shares[public_id])}

    def import_node_from_share(
        self, target_parent, source_handle, encrypted_attrs, wrapped_key, share_handle, node_type
    ):
        self.calls.append(
            (
                "import_node_from_share",
                {
                    "target_parent": target_parent,
                    "source_handle": source_handle,
                    "encrypted_attrs": encrypted_attrs,
                    "wrapped_key": wrapped_key,
                    "share_handle": share_handle,
                    "node_type": node_type,
                },
            )
        )
        handle = self._handle("i")
        self.nodes.append(
            {
                "h": handle,
                "p": target_parent,
                "u": OWNER,
                "t": node_type,
                "s": 0,
                "ts": 1_700_000_000,
                "a": encrypted_attrs,
                "k": f"{OWNER}:{wrapped_key}",
            }
        )
        return {"f": [{"h": handle}]}

    # -- assertions helpers --------------------------------------------------

    def actions(self) -> list[str]:
        return [name for name, _ in self.calls]

    def last(self, action: str) -> dict:
        for name, kwargs in reversed(self.calls):
            if name == action:
                return kwargs
        raise AssertionError(f"{action} was never called; saw {self.actions()}")


def bytes_from_a32_pair(key_a32: list[int]) -> bytes:
    """The AES key of a 32-byte file key: the first half XOR the second.

    Written out from the format rather than by calling `unpack_file_key`, so a
    change in that function cannot silently keep this fixture agreeing with it.
    """
    return bytes(
        b
        for word in (key_a32[i] ^ key_a32[i + 4] for i in range(4))
        for b in word.to_bytes(4, "big")
    )


def make_file_key() -> bytes:
    """A well-formed 32-byte file key (AES key + nonce + MAC IV)."""
    return bytes(
        b
        for word in pack_file_key(os.urandom(16), os.urandom(8), [0, 0])
        for b in word.to_bytes(4, "big")
    )


def logged_in_client(api: FakeMegaAPI | None = None) -> tuple[MegaClient, FakeMegaAPI]:
    """A real `MegaClient` wired to a fake account with the standard tree."""
    api = api or FakeMegaAPI().with_default_tree()
    client = MegaClient(api=api)
    client.session = MegaSession(
        sid="fake-sid",
        master_key=api.master_key,
        rsa_private_key=None,
        user_handle=OWNER,
        email="someone@example.invalid",
    )
    return client, api


def share_listing(folder_key: bytes, entries: list[tuple[str, str, str, int]]) -> list[dict]:
    """Build a public-folder listing: entries are (handle, parent, name, type).

    Keys are wrapped with the SHARE key rather than a master key, which is the
    distinction `import_public_share` has to get right when it re-wraps them.
    """
    listing = []
    for handle, parent, name, node_type in entries:
        node_key = os.urandom(32) if node_type == FILE else os.urandom(16)
        aes_key = (
            bytes_from_a32_pair(bytes_to_a32(node_key)) if node_type == FILE else node_key[:16]
        )
        listing.append(
            {
                "h": handle,
                "p": parent,
                "u": OWNER,
                "t": node_type,
                "s": 0,
                "ts": 1_700_000_000,
                "a": b64_url_encode(encrypt_attributes({"n": name}, aes_key)),
                "k": f"{OWNER}:{b64_url_encode(aes_key_wrap_encrypt(node_key, folder_key))}",
            }
        )
    return listing


def attrs_of(blob_b64: str, key: bytes) -> dict | None:
    """Decrypt an attribute blob the way MEGA's own reader would."""
    from megabasterd_cli.core.crypto import b64_url_decode, decrypt_attributes

    return decrypt_attributes(b64_url_decode(blob_b64), key)


def json_roundtrip(value):
    """Prove a payload is JSON-serializable - the wire carries JSON, not bytes."""
    return json.loads(json.dumps(value))
