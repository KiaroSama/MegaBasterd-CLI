"""`export_link` and `import_public_share` - the two data-exposing operations.

`core/shares.py` sat at 9% line coverage: 127 of its 139 statements had never
executed. Only the imports and `def` lines ran. The one test that named
`export_link` (`tests/test_machine_output.py`) monkeypatched it away, so it
proved the caller's plumbing and nothing about the function.

That matters more here than raw percentage suggests. `export_link` decides
which key bytes go into a public URL - 32 for a file, 16 for a folder - and
`import_public_share` unwraps every node key with the SHARE key and re-wraps it
with the user's MASTER key. Both are the "crypto primitive is fine, the caller
passed it the wrong thing" shape: `tests/test_password_links.py` already
round-trips `encrypt_password_link`, and the upload path still shipped a
double-base64'd token past a green suite because nothing tested the assembly.

Run against `tests/fake_mega.py`, so the keys and attributes are real.
"""

from __future__ import annotations

import pytest

from megabasterd_cli.core.crypto import (
    a32_to_bytes,
    aes_key_wrap_decrypt,
    b64_url_decode,
    b64_url_encode,
    decrypt_password_link,
)
from megabasterd_cli.core.errors import AuthError, MegaError

from .fake_mega import FILE, FOLDER, FakeMegaAPI, attrs_of, logged_in_client, share_listing

FOLDER_KEY = bytes(range(16, 32))
SHARE_ID = "SHARE00001"
# The key in the URL and the key the listing was wrapped with MUST be the same
# 16 bytes: `import_public_share` does `a32_to_bytes(str_to_a32(link_key))` and
# unwraps every node key with the result. Writing the two independently is how
# the first draft of this file produced a share whose nodes imported with the
# right SHAPE - handles, ordering, node types, key lengths all correct - and
# contents that decrypted to nothing. Twenty-seven assertions passed on it.
# Derived here, and pinned to its literal so a change in the encoder shows up
# as a failure rather than as a quietly different fixture.
SHARE_KEY_B64 = b64_url_encode(FOLDER_KEY)
assert SHARE_KEY_B64 == "EBESExQVFhcYGRobHB0eHw", "the folder link key drifted"


@pytest.fixture()
def account():
    api = FakeMegaAPI().with_default_tree()
    client, _ = logged_in_client(api)
    return client, api


# ===========================================================================
# export_link
# ===========================================================================


def test_exporting_a_file_puts_the_whole_32_byte_key_in_the_url(account):
    """A file link carries the full key: AES key, CTR nonce and MAC IV. Ship
    only the first 16 bytes and the recipient can decrypt nothing."""
    client, api = account
    handle = api.add_file("report.pdf", api.root)
    node = client.find_node(handle=handle)

    url = client.export_link(handle)

    public, _, key_b64 = url.partition("#")
    assert public == f"https://mega.nz/file/{api.exported[handle]}"
    assert b64_url_decode(key_b64) == a32_to_bytes(node.file_key_a32)
    assert len(b64_url_decode(key_b64)) == 32


def test_exporting_a_folder_puts_only_the_16_byte_key_in_the_url(account):
    """The counterpart branch: a folder key is 16 bytes and the URL says
    /folder/, not /file/. Getting the pair crossed produces a link that parses
    and then fails to decrypt anything."""
    client, api = account
    handle = api.add_folder("album", api.root)
    node = client.find_node(handle=handle)

    url = client.export_link(handle)

    public, _, key_b64 = url.partition("#")
    assert public == f"https://mega.nz/folder/{api.exported[handle]}"
    assert b64_url_decode(key_b64) == node.decrypted_key[:16]
    assert len(b64_url_decode(key_b64)) == 16


def test_an_exported_link_round_trips_through_the_projects_own_parser(account):
    """The link has to be readable by the tool that produced it."""
    from megabasterd_cli.core.links import LinkType, parse_link

    client, api = account
    handle = api.add_file("report.pdf", api.root)

    parsed = parse_link(client.export_link(handle))

    assert parsed.type is LinkType.FILE
    assert parsed.public_id == api.exported[handle]


@pytest.mark.parametrize(
    "node_type,expected_type,key_len",
    [(FILE, 0, 32), (FOLDER, 1, 16)],
    ids=["file", "folder"],
)
def test_a_password_link_carries_the_right_node_type_and_key(
    account, node_type, expected_type, key_len
):
    """`encrypt_password_link` is already round-trip tested; what was never
    tested is what `export_link` FEEDS it. The node type is a literal 0/1 chosen
    per branch, and the key length differs per branch - two chances to hand a
    correct primitive the wrong argument."""
    client, api = account
    handle = api.add_node("thing", node_type, api.root)

    url = client.export_link(handle, password="hunter2")

    assert url.startswith("https://mega.nz/#P!")
    decoded_type, public_handle, raw_key = decrypt_password_link(
        url.removeprefix("https://mega.nz/#P!"), "hunter2"
    )
    assert decoded_type == expected_type
    assert public_handle == b64_url_decode(api.exported[handle])
    assert len(raw_key) == key_len


def test_a_password_link_does_not_open_with_the_wrong_password(account):
    client, api = account
    handle = api.add_file("secret.pdf", api.root)

    url = client.export_link(handle, password="right")

    with pytest.raises(Exception):  # noqa: B017 - any refusal is the point
        decrypt_password_link(url.removeprefix("https://mega.nz/#P!"), "wrong")


def test_a_plain_link_is_returned_when_no_password_is_given(account):
    client, api = account
    handle = api.add_file("open.pdf", api.root)
    assert "#P!" not in client.export_link(handle)


def test_exporting_without_a_session_is_refused(account):
    client, api = account
    handle = api.add_file("f.bin", api.root)
    client.session = None
    with pytest.raises(AuthError):
        client.export_link(handle)


def test_exporting_a_missing_node_is_reported(account):
    client, _ = account
    with pytest.raises(MegaError, match="Node not found"):
        client.export_link("nosuchhandle")


def test_exporting_a_keyless_node_is_refused(account):
    """A system node has no key, so there is nothing to put after the '#'."""
    client, api = account
    with pytest.raises(MegaError, match="without a key"):
        client.export_link(api.trash)


def test_remove_export_reaches_the_api(account):
    client, api = account
    handle = api.add_file("f.bin", api.root)
    client.export_link(handle)

    client.remove_export(handle)

    assert api.last("remove_export")["handle"] == handle
    assert handle not in api.exported


# ===========================================================================
# import_public_share
# ===========================================================================


def _share_url(subpath: str | None = None) -> str:
    base = f"https://mega.nz/folder/{SHARE_ID}#{SHARE_KEY_B64}"
    return f"{base}/folder/{subpath}" if subpath else base


def _install_share(api: FakeMegaAPI, entries):
    """`share_listing` wraps each key with FOLDER_KEY, which is what the link
    key decodes to - so the import path must use the LINK key to unwrap."""
    api.shares[SHARE_ID] = share_listing(FOLDER_KEY, entries)
    return api.shares[SHARE_ID]


@pytest.fixture()
def shared(account):
    client, api = account
    # The share root's parent is absent from the listing, which is how
    # `import_public_share` identifies the root.
    _install_share(
        api,
        [
            ("sroot0001", "outside01", "album", FOLDER),
            ("schild001", "sroot0001", "one.jpg", FILE),
            ("ssub00001", "sroot0001", "raw", FOLDER),
            ("sdeep0001", "ssub00001", "two.cr2", FILE),
        ],
    )
    return client, api


def test_only_folder_links_can_be_imported(account):
    client, _ = account
    with pytest.raises(MegaError, match="Only public folder shares"):
        client.import_public_share("https://mega.nz/file/ABCDEFGH#" + "A" * 43)


def test_importing_without_a_session_is_refused(account):
    client, _ = account
    client.session = None
    with pytest.raises(AuthError):
        client.import_public_share(_share_url())


def test_an_empty_share_imports_nothing_without_failing(account):
    client, api = account
    api.shares[SHARE_ID] = []
    assert client.import_public_share(_share_url()) == []


def test_every_node_in_the_share_is_imported(shared):
    client, api = shared
    handles = client.import_public_share(_share_url())
    assert len(handles) == 4


def test_the_hierarchy_is_preserved_under_the_target(shared):
    """Each child must land under its own imported parent, not flat at the
    root. The mapping is source-handle -> new-handle, rebuilt as it goes."""
    client, api = shared
    client.import_public_share(_share_url())

    assert client.find_node(path="album/one.jpg") is not None
    assert client.find_node(path="album/raw/two.cr2") is not None


def test_a_parent_is_imported_before_its_children(shared):
    """Otherwise a child is filed under the target root as a fallback."""
    client, api = shared
    client.import_public_share(_share_url())

    order = [c["source_handle"] for n, c in api.calls if n == "import_node_from_share"]
    assert order.index("sroot0001") < order.index("schild001")
    assert order.index("ssub00001") < order.index("sdeep0001")


def test_keys_are_rewrapped_with_the_users_master_key(shared):
    """The whole point of an import: the recipient must be able to open the
    node with THEIR key. Passing the share-wrapped key straight through would
    create nodes nobody can read - and would look successful doing it."""
    client, api = shared
    client.import_public_share(_share_url())

    for _, call in ((n, c) for n, c in api.calls if n == "import_node_from_share"):
        key = aes_key_wrap_decrypt(b64_url_decode(call["wrapped_key"]), api.master_key)
        assert len(key) == (32 if call["node_type"] == FILE else 16)


def test_an_imported_file_keeps_its_name(shared):
    """End to end: the re-wrapped key still opens the original attributes."""
    client, api = shared
    client.import_public_share(_share_url())

    node = client.find_node(path="album/one.jpg")
    assert node is not None and node.name == "one.jpg"


def test_the_node_type_is_carried_through_per_node(shared):
    client, api = shared
    client.import_public_share(_share_url())

    by_source = {c["source_handle"]: c["node_type"] for n, c in api.calls if n.startswith("import")}
    assert by_source["sroot0001"] == FOLDER
    assert by_source["schild001"] == FILE
    assert by_source["sdeep0001"] == FILE


def test_a_subfolder_link_imports_only_that_subtree(shared):
    """`/folder/<sub>` narrows the share; importing the whole thing instead
    would silently copy far more of someone's data than was asked for."""
    client, api = shared
    client.import_public_share(_share_url(subpath="ssub00001"))

    sources = {c["source_handle"] for n, c in api.calls if n == "import_node_from_share"}
    assert sources == {"ssub00001", "sdeep0001"}


def test_a_subfolder_link_naming_something_absent_is_refused(shared):
    client, _ = shared
    with pytest.raises(MegaError, match="Subfolder not found"):
        client.import_public_share(_share_url(subpath="nosuchhandle"))


def test_an_include_filter_keeps_the_ancestors_of_what_it_selects(shared):
    """Selecting one deep file must still create the folders above it, or the
    file lands somewhere the user did not choose."""
    client, api = shared
    client.import_public_share(_share_url(), include=["sdeep0001"])

    sources = [c["source_handle"] for n, c in api.calls if n == "import_node_from_share"]
    assert set(sources) == {"sroot0001", "ssub00001", "sdeep0001"}
    assert "schild001" not in sources


def test_a_node_whose_key_will_not_decrypt_is_skipped_not_fatal(account, caplog):
    """One corrupt entry must not abandon the rest of the import."""
    import logging

    client, api = account
    entries = _install_share(
        api,
        [
            ("sroot0001", "outside01", "album", FOLDER),
            ("sbad00001", "sroot0001", "bad.jpg", FILE),
            ("sgood0001", "sroot0001", "good.jpg", FILE),
        ],
    )
    entries[1]["k"] = "owner:!!!not-base64!!!"

    with caplog.at_level(logging.WARNING, logger="megabasterd_cli.core.shares"):
        handles = client.import_public_share(_share_url())

    sources = {c["source_handle"] for n, c in api.calls if n == "import_node_from_share"}
    assert sources == {"sroot0001", "sgood0001"}
    assert len(handles) == 2
    assert "sbad00001" in caplog.text


def test_a_node_with_an_empty_key_is_skipped(account):
    client, api = account
    entries = _install_share(
        api,
        [
            ("sroot0001", "outside01", "album", FOLDER),
            ("sempty001", "sroot0001", "nokey.jpg", FILE),
        ],
    )
    entries[1]["k"] = ""

    handles = client.import_public_share(_share_url())
    assert len(handles) == 1


def test_a_failing_import_call_does_not_abort_the_others(shared):
    client, api = shared
    real = api.import_node_from_share

    def flaky(**kwargs):
        if kwargs["source_handle"] == "schild001":
            raise MegaError(code=-11)
        return real(**kwargs)

    api.import_node_from_share = flaky
    handles = client.import_public_share(_share_url())

    assert len(handles) == 3, "one refusal must not lose the other three"


def test_a_malformed_share_listing_is_rejected_before_any_import(account):
    """The listing is remote input; a bad shape must fail cleanly, not
    half-way through with a bare KeyError."""
    client, api = account
    api.shares[SHARE_ID] = [{"p": "outside01", "t": 1}]  # no "h"

    with pytest.raises(MegaError):
        client.import_public_share(_share_url())
    assert "import_node_from_share" not in api.actions()


def test_the_listing_cache_is_invalidated_after_an_import(shared):
    """A stale tree would hide every node the import just created."""
    client, api = shared
    client.list_files()
    client.import_public_share(_share_url())
    assert client.find_node(path="album") is not None


def test_attributes_survive_the_import_unchanged(shared):
    """The attribute blob is copied verbatim; re-encrypting it under a new key
    while re-wrapping the old one would make the name unreadable."""
    client, api = shared
    source_attrs = {n["h"]: n["a"] for n in api.shares[SHARE_ID]}

    client.import_public_share(_share_url())

    for _, call in ((n, c) for n, c in api.calls if n == "import_node_from_share"):
        assert call["encrypted_attrs"] == source_attrs[call["source_handle"]]


def test_the_share_handle_is_passed_so_mega_can_do_a_server_side_copy(shared):
    """No content bytes move; MEGA needs the share id to authorise the copy."""
    client, api = shared
    client.import_public_share(_share_url())
    assert api.last("import_node_from_share")["share_handle"] == SHARE_ID


def test_an_imported_node_opens_with_the_master_key_end_to_end(shared):
    """The strongest single assertion here: decrypt what was stored, with the
    account key, and read the original name back out."""
    client, api = shared
    client.import_public_share(_share_url())

    call = next(c for n, c in api.calls if n == "import_node_from_share" and c["node_type"] == FILE)
    key = aes_key_wrap_decrypt(b64_url_decode(call["wrapped_key"]), api.master_key)
    from megabasterd_cli.core.crypto import bytes_to_a32, unpack_file_key

    aes_key, _, _ = unpack_file_key(bytes_to_a32(key))
    assert attrs_of(call["encrypted_attrs"], aes_key) == {"n": "one.jpg"}
