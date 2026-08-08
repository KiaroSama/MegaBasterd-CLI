"""`mb info <folder-url> --json` lists the files a download would write.

There was no machine-readable way to see inside a public folder link. `info`
gave a count and a total, `ls` needs an account, and `download --select` prints
the list as human text in the middle of a download command - so a consumer had
to run `--select`, answer `none`, and regex the printed table. That works until
the first change to the layout.

The two properties that make this usable are easy to get subtly wrong, so both
are pinned here:

* `size` is an integer number of bytes. A consumer must never have to turn
  "103.03 MB" back into a number.
* `path` is the exact string `--include` matches against and the exact one a
  download writes. It comes from the downloader's own `plan_file_jobs` rather
  than a second implementation, because the drift would be silent: the listing
  would look right while a pattern copied out of it selected nothing.

Real MEGA names contain runs of spaces (`OAD -  09v2.mkv`), which is the reason
the text output was unparseable in the first place, so one fixture carries that
shape end to end.
"""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from megabasterd_cli.cli import cli
from megabasterd_cli.core.crypto import (
    a32_to_bytes,
    aes_key_wrap_encrypt,
    b64_url_encode,
    encrypt_attributes,
    str_to_a32,
)

# The 22-char folder link key, and the same 16 bytes the listing is wrapped
# with. Writing the two independently is how a share ends up structurally
# right and undecryptable.
KEY_B64 = "EBESExQVFhcYGRobHB0eHw"
FOLDER_KEY = a32_to_bytes(str_to_a32(KEY_B64))
SHARE_ID = "PUBLICID0"
URL = f"https://mega.nz/folder/{SHARE_ID}#{KEY_B64}"

FILE, FOLDER = 0, 1


def _node(handle, parent, name, node_type, size=0):
    key = bytes(range(32)) if node_type == FILE else bytes(range(16))
    aes_key = (
        bytes(a ^ b for a, b in zip(key[:16], key[16:32], strict=True))
        if node_type == FILE
        else key[:16]
    )
    return {
        "h": handle,
        "p": parent,
        "t": node_type,
        "s": size,
        "a": b64_url_encode(encrypt_attributes({"n": name}, aes_key)),
        "k": f"owner:{b64_url_encode(aes_key_wrap_encrypt(key, FOLDER_KEY))}",
    }


TREE = [
    _node("rootAAAA", "outsideX", "Season 1", FOLDER),
    _node("fileAAAA", "rootAAAA", "OAD -  09v2.mkv", FILE, size=108_036_378),
    _node("subBBBBB", "rootAAAA", "extras", FOLDER),
    _node("fileBBBB", "subBBBBB", "clip.mkv", FILE, size=1024),
]


@pytest.fixture()
def listing(monkeypatch):
    """Answer the one API call `info` makes for a folder share."""
    calls = []

    def fake(self, public_id):
        calls.append(public_id)
        return {"f": list(TREE)}

    monkeypatch.setattr("megabasterd_cli.core.api.MegaAPIClient.get_public_folder_listing", fake)
    return calls


def _run(*args):
    return CliRunner().invoke(cli, ["-q", "info", *args])


def _payload(result):
    assert result.exit_code == 0, result.output
    return json.loads(result.output.strip())


# ---------------------------------------------------------------------------
# the listing
# ---------------------------------------------------------------------------


def test_a_folder_link_reports_every_file(listing):
    files = _payload(_run(URL, "--json"))["files"]
    assert {f["path"] for f in files} == {
        "Season 1/OAD -  09v2.mkv",
        "Season 1/extras/clip.mkv",
    }


def test_size_is_an_integer_number_of_bytes(listing):
    """Not "103.03 MB" - the consumer must not have to parse a rendering."""
    files = _payload(_run(URL, "--json"))["files"]
    big = next(f for f in files if f["path"].endswith("09v2.mkv"))
    assert big["size"] == 108_036_378
    assert isinstance(big["size"], int)


def test_a_name_with_a_double_space_survives_verbatim(listing):
    """The shape that made the printed table unparseable."""
    files = _payload(_run(URL, "--json"))["files"]
    assert any(f["path"] == "Season 1/OAD -  09v2.mkv" for f in files)


def test_each_file_carries_a_stable_handle(listing):
    files = _payload(_run(URL, "--json"))["files"]
    assert {f["handle"] for f in files} == {"fileAAAA", "fileBBBB"}


def test_the_scalars_are_machine_values_too(listing):
    payload = _payload(_run(URL, "--json"))
    assert payload["total_size"] == 108_036_378 + 1024
    assert payload["node_count"] == len(TREE)
    assert payload["type"] == "Folder share"


def test_the_file_count_and_the_file_list_do_not_collide(listing):
    """`files` is the ARRAY; the count is `file_count`.

    Both once mapped to `files` and the array was assigned second, so the
    count disappeared without a word - a consumer asking for it got a list.
    Caught while documenting the shape, not by the tests above, which is why
    this one names both keys explicitly.
    """
    payload = _payload(_run(URL, "--json"))
    assert isinstance(payload["files"], list)
    assert payload["file_count"] == 2
    assert len(payload["files"]) == payload["file_count"]


# ---------------------------------------------------------------------------
# the contract that makes it usable
# ---------------------------------------------------------------------------


def test_a_reported_path_is_accepted_by_the_include_filter(listing):
    """The whole point: a consumer's selection becomes `--include` unchanged.

    Checked against the real filter rather than by eye, because a listing that
    looks right and selects nothing is the failure this guards.
    """
    from pathlib import Path

    from megabasterd_cli.core.folder_downloader import MegaFolderDownloader
    from megabasterd_cli.utils.selection import build_folder_file_filter

    files = _payload(_run(URL, "--json"))["files"]
    chosen = next(f for f in files if f["path"].endswith("09v2.mkv"))

    nodes = MegaFolderDownloader._decrypt_folder_nodes(TREE, FOLDER_KEY)
    jobs = MegaFolderDownloader.plan_file_jobs(nodes, Path("."), "rootAAAA")
    file_filter = build_folder_file_filter([chosen["path"]], [], Path("."))

    assert file_filter is not None
    kept = file_filter(jobs)
    assert [d.name for _n, d in kept] == ["OAD -  09v2.mkv"]


def test_asking_creates_nothing_on_disk(listing, tmp_path, monkeypatch):
    """`info` must stay read-only; the download path makes directories and
    this one deliberately calls the half that does not."""
    monkeypatch.chdir(tmp_path)
    _payload(_run(URL, "--json"))
    assert list(tmp_path.iterdir()) == []


def test_stdout_is_exactly_one_json_document(listing):
    """The --json contract: nothing else may share the stream."""
    result = _run(URL, "--json")
    assert result.exit_code == 0
    json.loads(result.output.strip())  # raises if anything else is mixed in


def test_without_the_flag_the_human_table_is_unchanged(listing):
    result = _run(URL)
    assert result.exit_code == 0
    assert "Folder share" in result.output
    with pytest.raises(json.JSONDecodeError):
        json.loads(result.output.strip())


def test_no_account_or_mfa_is_involved(listing):
    """`info` is the no-credentials command and must stay that way."""
    import inspect

    from megabasterd_cli.commands import info_cmd as module

    source = inspect.getsource(module)
    for forbidden in ("login_client", "AccountManager", "ask_mfa_code", "restore_session"):
        assert forbidden not in source, f"info reached for {forbidden}"


def test_a_subfolder_link_lists_only_that_subtree(listing):
    files = _payload(_run(f"{URL}/folder/subBBBBB", "--json"))["files"]
    assert [f["path"] for f in files] == ["extras/clip.mkv"]
