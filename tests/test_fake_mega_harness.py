"""The harness itself must be right, or every test built on it is vacuous.

`tests/fake_mega.py` encrypts nodes the way MEGA does so a real `MegaClient`
can run against it. If that encryption is wrong in the same direction as a bug
in the reader, the two agree and the suite goes green on a broken pair - which
is exactly what happened to the csid fixture in
`tests/test_login_rsa_session_id.py`, written to match the reader that dropped
the MPI prefix.

So this file checks the harness against the FORMAT, not against the reader:
byte lengths, the attribute prefix, the `owner:key` split, the file-vs-folder
key-length branch. Then one round trip proves reader and writer meet.
"""

from __future__ import annotations

import pytest

from megabasterd_cli.core.crypto import b64_url_decode, bytes_to_a32, unpack_file_key

from .fake_mega import (
    FILE,
    FOLDER,
    OWNER,
    FakeMegaAPI,
    bytes_from_a32_pair,
    logged_in_client,
    make_file_key,
)


def test_the_default_tree_has_the_three_system_nodes():
    _, api = logged_in_client()
    types = sorted(n["t"] for n in api.nodes)
    assert types == [2, 3, 4], "root, inbox and trash are what a real account starts with"


def test_a_folder_key_is_16_bytes_and_a_file_key_is_32():
    """The branch `decrypt_node`, `rename` and `export_link` each take apart.

    A harness that only ever produced 16-byte keys would exercise one side of
    three separate `if node.is_file` branches and look complete doing it.
    """
    api = FakeMegaAPI().with_default_tree()
    folder = api.add_folder("docs", api.root)
    file_handle = api.add_file("a.bin", folder)

    client, _ = logged_in_client(api)
    as_folder = client.find_node(handle=folder)
    as_file = client.find_node(handle=file_handle)
    assert len(as_folder.decrypted_key) == 16
    assert len(as_file.decrypted_key) == 32
    # Length alone is satisfied by a key that is the right SIZE and the wrong
    # BYTES - `aes_key_wrap_decrypt` returns 32 bytes either way. Proving the
    # name came back is what separates "well-formed" from "correct": under a
    # chained-CBC mutation of the harness (the round-31 login bug's exact
    # shape) the lengths still pass and only this line goes red.
    assert as_folder.name == "docs"
    assert as_file.name == "a.bin"
    assert as_file.file_key_a32 is not None and len(as_file.file_key_a32) == 8


def test_the_wrapped_key_carries_the_owner_prefix():
    """`_decrypt_node_key` splits on ':' - a bare key would decode differently."""
    api = FakeMegaAPI().with_default_tree()
    handle = api.add_folder("docs", api.root)
    raw = next(n for n in api.nodes if n["h"] == handle)
    owner, _, wrapped = raw["k"].partition(":")
    assert owner == OWNER
    assert len(b64_url_decode(wrapped)) == 16


def test_attributes_carry_the_mega_prefix():
    """`decrypt_attributes` rejects a blob that does not start with `MEGA`."""
    from megabasterd_cli.core.crypto import ATTR_PREFIX

    api = FakeMegaAPI().with_default_tree()
    handle = api.add_folder("docs", api.root)
    client, _ = logged_in_client(api)
    node = client.find_node(handle=handle)

    plain = b64_url_decode(next(n for n in api.nodes if n["h"] == handle)["a"])
    assert len(plain) % 16 == 0, "the attribute blob is AES-CBC, so block-aligned"
    assert node.name == "docs", "and it decrypts back to the name we asked for"
    assert ATTR_PREFIX == b"MEGA"


def test_the_file_aes_key_is_the_two_halves_xored():
    """Pin the harness's own key derivation against `unpack_file_key`.

    Written out independently in the harness; if the two ever disagree, one of
    them has changed and the fixtures stop meaning what they claim.
    """
    key = make_file_key()
    key_a32 = bytes_to_a32(key)
    assert bytes_from_a32_pair(key_a32) == unpack_file_key(key_a32)[0]


def test_a_real_client_decrypts_the_whole_tree():
    """The round trip: writer and reader meet on names, parents and types."""
    api = FakeMegaAPI().with_default_tree()
    docs = api.add_folder("docs", api.root)
    api.add_file("report.pdf", docs, size=4096)
    api.add_folder("empty", api.root)

    client, _ = logged_in_client(api)
    names = {n.name for n in client.list_files() if n.name}
    assert names == {"docs", "report.pdf", "empty"}

    found = client.find_node(path="docs/report.pdf")
    assert found is not None and found.size == 4096 and found.is_file


def test_the_listing_is_cached_until_invalidated():
    """Mutations call `invalidate_cache`; a stale tree hides their effect."""
    api = FakeMegaAPI().with_default_tree()
    client, _ = logged_in_client(api)
    client.list_files()
    api.add_folder("late", api.root)

    assert not any(n.name == "late" for n in client.list_files())
    client.invalidate_cache()
    assert any(n.name == "late" for n in client.list_files())


def test_an_unscripted_action_fails_loudly():
    """Silence would let a test pass while never reaching the server at all."""
    _, api = logged_in_client()
    with pytest.raises(AssertionError, match="unscripted"):
        api.request({"a": "whatever"})


def test_recorded_calls_expose_the_payload_not_just_the_name():
    """Encoding bugs live in the payload; a call counter cannot see them."""
    api = FakeMegaAPI().with_default_tree()
    client, _ = logged_in_client(api)
    client.mkdir("new", api.root)

    assert "create_folder" in api.actions()
    payload = api.last("create_folder")
    assert payload["parent_handle"] == api.root
    assert isinstance(payload["wrapped_key"], str), "the wire carries base64, not bytes"


@pytest.mark.parametrize("node_type", [FILE, FOLDER])
def test_every_node_field_survives_json(node_type):
    """MEGA speaks JSON; a bytes value anywhere would fail at the transport."""
    import json

    api = FakeMegaAPI().with_default_tree()
    api.add_node("thing", node_type, api.root)
    assert json.loads(json.dumps(api.nodes)) == api.nodes
