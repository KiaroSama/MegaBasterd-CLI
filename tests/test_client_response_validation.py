"""Consumers of API responses fail at the boundary with a typed error.

Before: `nodes[0]["h"]`, `raw_node["h"]`, `raw_node["t"]`, `result["k"]` and
friends were indexed blind. A server (or a proxy) returning a list where an
object was expected produced `TypeError: string indices are not integers`, and
`{"s": "1234"}` pushed a STRING all the way into `format_bytes` and the chunk
maths. The CLI catch-all rendered those as `Error: 'p'`.

`export_node` already did this correctly (isinstance check + typed MegaError);
these tests hold the rest of the file to the same standard.
"""

from __future__ import annotations

import pytest

from megabasterd_cli.core.client import MegaClient, MegaSession
from megabasterd_cli.core.errors import MegaError

MASTER_KEY = b"\x01" * 16


class _FakeAPI:
    """Returns canned responses; records nothing else."""

    def __init__(self, **responses):
        self._responses = responses

    def set_session(self, sid):  # pragma: no cover - not exercised here
        return None

    def request(self, commands, extra_params=None):
        return self._responses["request"]

    def create_folder(self, **kwargs):
        return self._responses["create_folder"]

    def close(self):
        return None


def _client(**responses) -> MegaClient:
    client = MegaClient(api=_FakeAPI(**responses))
    client.session = MegaSession(sid="sid", master_key=MASTER_KEY)
    return client


# ---------------------------------------------------------------------------
# decrypt_node: the node dict itself
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw_node",
    [
        pytest.param("not-a-dict", id="string_instead_of_object"),
        pytest.param(["h", "t"], id="list_instead_of_object"),
        pytest.param({"t": 0}, id="missing_handle"),
        pytest.param({"h": 12345, "t": 0}, id="handle_is_not_a_string"),
        pytest.param({"h": "abc"}, id="missing_type"),
        pytest.param({"h": "abc", "t": "0"}, id="type_is_a_string"),
        pytest.param({"h": "abc", "t": 0, "s": "1234"}, id="size_is_a_string"),
        pytest.param({"h": "abc", "t": 0, "ts": "now"}, id="timestamp_is_a_string"),
        pytest.param({"h": "abc", "t": 0, "k": 99}, id="key_is_not_a_string"),
    ],
)
def test_decrypt_node_rejects_malformed_nodes(raw_node):
    with pytest.raises(MegaError):
        _client().decrypt_node(raw_node, master_key=MASTER_KEY)


def test_decrypt_node_accepts_a_well_formed_node():
    node = _client().decrypt_node({"h": "abc", "t": 1, "s": 10, "ts": 5}, master_key=MASTER_KEY)
    assert node.handle == "abc"
    assert node.size == 10


def test_a_string_size_never_reaches_the_node():
    """The regression that made format_bytes and chunk maths receive a str."""
    with pytest.raises(MegaError, match="s"):
        _client().decrypt_node({"h": "abc", "t": 0, "s": "1234"}, master_key=MASTER_KEY)


# ---------------------------------------------------------------------------
# mkdir / list_files: the container around the nodes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "result",
    [
        pytest.param({"f": ["not-a-dict"]}, id="node_element_is_a_string"),
        pytest.param({"f": [{"no_handle": 1}]}, id="node_element_has_no_handle"),
        pytest.param({"f": [{"h": 42}]}, id="handle_is_not_a_string"),
    ],
)
def test_mkdir_rejects_a_malformed_node_list(result):
    client = _client(create_folder=result)
    with pytest.raises(MegaError):
        client.mkdir("newdir", parent_handle="parent")


def test_list_files_rejects_a_non_object_listing():
    client = _client(request=["not", "an", "object"])
    with pytest.raises(MegaError):
        client.list_files()


def test_list_files_rejects_a_non_list_f_field():
    client = _client(request={"f": {"h": "abc"}})
    with pytest.raises(MegaError):
        client.list_files()


# ---------------------------------------------------------------------------
# login: key material must be strings before it is decoded
# ---------------------------------------------------------------------------


def test_login_rejects_a_non_object_prelogin_response():
    client = _client(request=[1, 2, 3])
    with pytest.raises(MegaError):
        client.login("user@example.invalid", "password")


def test_login_anonymous_rejects_a_non_object_response():
    client = _client(request="surprise")
    with pytest.raises(MegaError):
        client.login_anonymous()


class _LoginAPI(_FakeAPI):
    """First call is the prelogin, second is the login itself."""

    def __init__(self, prelogin, login):
        super().__init__()
        self._queue = [prelogin, login]

    def request(self, commands, extra_params=None):
        return self._queue.pop(0)


# A well-formed (all-zero) 16-byte master-key blob, so the cases below fail on
# the field they are actually about rather than on the master-key decrypt.
VALID_K = "A" * 22


@pytest.mark.parametrize(
    "login_result",
    [
        pytest.param({"tsid": "x"}, id="master_key_missing"),
        pytest.param({"k": 1234, "tsid": "x"}, id="master_key_not_a_string"),
        pytest.param({"k": "not-block-aligned", "tsid": "x"}, id="master_key_blob_malformed"),
        pytest.param({"k": VALID_K, "privk": 1}, id="privk_not_a_string"),
        pytest.param({"k": VALID_K, "privk": VALID_K, "csid": None}, id="csid_not_a_string"),
    ],
)
def test_login_rejects_malformed_key_material(login_result):
    client = MegaClient(api=_LoginAPI({"v": 1, "s": ""}, login_result))
    with pytest.raises(MegaError):
        client.login("user@example.invalid", "password")
