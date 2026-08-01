"""`mkdir`, `delete`, `move`, `rename`, `empty_trash` - against a fake account.

`core/cloud.py` sat at 38% line coverage: `delete`, `move`, `rename` and
`empty_trash` had NO behavioural test at all. They are the irreversible half of
the tool - `mb rm`, `mb mv`, `mb rename`, `mb trash --empty` - and `rename` in
particular hand-assembles key material exactly the way `export_link` does and
the way the upload path did when it shipped a double-base64'd token that only a
live run caught.

These run a real `MegaClient` over `tests/fake_mega.py`, so the assertions can
be about the PAYLOAD that reached the wire, not about which method was called.
"""

from __future__ import annotations

import pytest

from megabasterd_cli.core.crypto import (
    a32_to_bytes,
    aes_key_wrap_decrypt,
    b64_url_decode,
    unpack_file_key,
)
from megabasterd_cli.core.errors import AuthError, MegaError

from .fake_mega import FakeMegaAPI, attrs_of, logged_in_client


@pytest.fixture()
def account():
    api = FakeMegaAPI().with_default_tree()
    client, _ = logged_in_client(api)
    return client, api


# ---------------------------------------------------------------------------
# mkdir
# ---------------------------------------------------------------------------


def test_mkdir_creates_a_folder_that_reads_back_by_name(account):
    client, api = account
    handle = client.mkdir("photos", api.root)

    found = client.find_node(handle=handle)
    assert found is not None and found.name == "photos" and found.is_folder


def test_mkdir_wraps_the_folder_key_with_the_master_key(account):
    """The wrapped key must open with the account's master key, or the folder
    is unreadable on every other device the user owns."""
    client, api = account
    client.mkdir("photos", api.root)

    payload = api.last("create_folder")
    key = aes_key_wrap_decrypt(b64_url_decode(payload["wrapped_key"]), api.master_key)
    assert len(key) == 16
    assert attrs_of(payload["encrypted_attrs"], key) == {"n": "photos"}


def test_mkdir_defaults_to_the_root(account):
    client, api = account
    client.mkdir("at-root")
    assert api.last("create_folder")["parent_handle"] == api.root


def test_mkdir_without_a_session_is_refused(account):
    client, _ = account
    client.session = None
    with pytest.raises(AuthError):
        client.mkdir("nope")


# ---------------------------------------------------------------------------
# delete / move
# ---------------------------------------------------------------------------


def test_delete_removes_the_node_and_refreshes_the_listing(account):
    client, api = account
    handle = api.add_folder("doomed", api.root)
    assert client.find_node(handle=handle) is not None

    client.delete(handle)

    assert api.last("delete_node")["handle"] == handle
    assert client.find_node(handle=handle) is None, "the cached tree still shows it"


def test_move_reparents_the_node_and_refreshes_the_listing(account):
    client, api = account
    src = api.add_folder("src", api.root)
    dst = api.add_folder("dst", api.root)
    moved = api.add_file("f.bin", src)

    client.move(moved, dst)

    assert client.find_node(handle=moved).parent == dst
    assert client.find_node(path="dst/f.bin") is not None


def test_deleting_something_absent_surfaces_the_error(account):
    client, _ = account
    with pytest.raises(MegaError):
        client.delete("nosuchhandle")


# ---------------------------------------------------------------------------
# rename - the branch that hand-assembles key material
# ---------------------------------------------------------------------------


def test_renaming_a_folder_keeps_its_key_and_changes_only_the_name(account):
    client, api = account
    handle = api.add_folder("before", api.root)
    original = client.find_node(handle=handle).decrypted_key

    client.rename(handle, "after")

    payload = api.last("rename_node")
    rewrapped = aes_key_wrap_decrypt(b64_url_decode(payload["wrapped_key"]), api.master_key)
    assert rewrapped == original, "rename must not rotate the key"
    assert attrs_of(payload["encrypted_attrs"], original[:16]) == {"n": "after"}


def test_renaming_a_file_encrypts_attributes_under_the_unpacked_aes_key(account):
    """A file's 32-byte key is not its AES key: the AES key is the two halves
    XORed. Encrypting attributes under the raw 32 bytes (or its first 16) would
    produce a name no MEGA client could read - and nothing but a real decrypt
    catches that, because both paths produce a plausible-looking blob."""
    client, api = account
    handle = api.add_file("before.bin", api.root)
    node = client.find_node(handle=handle)
    aes_key, _, _ = unpack_file_key(node.file_key_a32)

    client.rename(handle, "after.bin")

    payload = api.last("rename_node")
    assert attrs_of(payload["encrypted_attrs"], aes_key) == {"n": "after.bin"}
    assert attrs_of(payload["encrypted_attrs"], a32_to_bytes(node.file_key_a32)[:16]) is None


def test_renaming_a_file_rewraps_the_full_32_byte_key(account):
    """The wrapped key stays the whole file key - dropping to 16 bytes would
    lose the CTR nonce and the MAC IV, and the file would never verify again."""
    client, api = account
    handle = api.add_file("before.bin", api.root)
    original = client.find_node(handle=handle).decrypted_key

    client.rename(handle, "after.bin")

    payload = api.last("rename_node")
    rewrapped = aes_key_wrap_decrypt(b64_url_decode(payload["wrapped_key"]), api.master_key)
    assert len(rewrapped) == 32
    assert rewrapped == original


def test_the_renamed_node_reads_back_under_its_new_name(account):
    """End to end: what was written is what the next listing decrypts."""
    client, api = account
    handle = api.add_file("before.bin", api.root)

    client.rename(handle, "after.bin")

    assert client.find_node(handle=handle).name == "after.bin"
    assert client.find_node(path="after.bin") is not None


def test_renaming_a_missing_node_is_reported_not_silently_skipped(account):
    client, _ = account
    with pytest.raises(MegaError, match="Node not found"):
        client.rename("nosuchhandle", "x")


def test_renaming_a_keyless_node_is_refused(account):
    """A system node has no key; encrypting attributes would crash deeper in."""
    client, api = account
    with pytest.raises(MegaError, match="missing node key"):
        client.rename(api.trash, "x")


# ---------------------------------------------------------------------------
# empty_trash
# ---------------------------------------------------------------------------


def test_empty_trash_deletes_every_child_of_trash_only(account):
    client, api = account
    keep = api.add_folder("keep", api.root)
    doomed = [api.add_file(f"old{i}.bin", api.trash) for i in range(3)]

    client.empty_trash()

    deleted = {c["handle"] for name, c in api.calls if name == "delete_node"}
    assert deleted == set(doomed)
    assert client.find_node(handle=keep) is not None


def test_empty_trash_on_an_empty_trash_calls_nothing(account):
    client, api = account
    client.empty_trash()
    assert "delete_node" not in api.actions()


def test_empty_trash_keeps_going_when_one_delete_fails(account):
    """A partial failure must not abandon the rest: the user asked for empty."""
    client, api = account
    handles = [api.add_file(f"old{i}.bin", api.trash) for i in range(3)]
    real_delete = api.delete_node

    def flaky(handle):
        if handle == handles[1]:
            raise MegaError(code=-11)  # EACCESS
        return real_delete(handle)

    api.delete_node = flaky
    client.empty_trash()

    assert client.find_node(handle=handles[0]) is None
    assert client.find_node(handle=handles[2]) is None
    assert client.find_node(handle=handles[1]) is not None


def test_empty_trash_without_a_session_is_refused(account):
    client, _ = account
    client.session = None
    with pytest.raises(AuthError):
        client.empty_trash()
