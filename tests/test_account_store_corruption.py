"""A corrupt account vault must never become an empty, writable vault.

The worst data-loss path in the audit: `AccountStorage.load()` swallowed
malformed JSON and returned `AccountStore()` - an EMPTY vault. The next
`add_account` then saved that empty vault over the real file, destroying every
stored MEGA credential, which exists nowhere else. Three root shapes also
raised a raw AttributeError straight out of the CLI.
"""

from __future__ import annotations

import base64
import json

import pytest

from megabasterd_cli.accounts.storage import (
    AccountCorruptionError,
    AccountStorage,
    AccountStore,
    validate_account_document,
)

GOOD_BLOB = base64.b64encode(b"x" * 40).decode("ascii")


def _entry(**overrides) -> dict:
    entry = {"email": "user@example.com", "enc_password": GOOD_BLOB}
    entry.update(overrides)
    return entry


def _doc(**overrides) -> dict:
    doc = {"version": 1, "default_email": None, "accounts": [_entry()]}
    doc.update(overrides)
    return doc


BAD_ROOTS = {
    "malformed-json": b'{"accounts": [,,,',
    "root-list": b"[1, 2, 3]",
    "root-null": b"null",
    "root-string": b'"hello"',
    "root-number": b"42",
    "not-utf8": b"\xff\xfe not utf-8",
}

BAD_DOCS = {
    "accounts-not-a-list": _doc(accounts={"a": 1}),
    "entry-not-a-dict": _doc(accounts=["nope"]),
    "missing-email": _doc(accounts=[{"enc_password": GOOD_BLOB}]),
    "blank-email": _doc(accounts=[_entry(email="   ")]),
    "email-not-a-string": _doc(accounts=[_entry(email=123)]),
    "duplicate-email-exact": _doc(accounts=[_entry(), _entry()]),
    "duplicate-email-case": _doc(accounts=[_entry(email="User@Example.com"), _entry()]),
    "missing-enc-password": _doc(accounts=[{"email": "a@b.c"}]),
    "non-base64-ciphertext": _doc(accounts=[_entry(enc_password="!!! not base64 !!!")]),
    "truncated-ciphertext": _doc(
        accounts=[_entry(enc_password=base64.b64encode(b"short").decode("ascii"))]
    ),
    "duplicate-label": _doc(
        accounts=[_entry(label="work"), _entry(email="b@example.com", label="WORK")]
    ),
    "label-not-a-string": _doc(accounts=[_entry(label=7)]),
    "quota-negative": _doc(accounts=[_entry(quota_total=-1)]),
    "quota-absurd": _doc(accounts=[_entry(quota_used=1 << 70)]),
    "quota-bool": _doc(accounts=[_entry(quota_total=True)]),
    "quota-string": _doc(accounts=[_entry(quota_total="lots")]),
    "unknown-field": _doc(accounts=[_entry(surprise="value")]),
    "bad-timestamp-type": _doc(accounts=[_entry(last_used_iso=20260101)]),
    "default-email-missing-account": _doc(default_email="ghost@example.com"),
    "default-email-not-a-string": _doc(default_email=[1]),
    "version-bool": _doc(version=True),
    "version-string": _doc(version="1"),
}


@pytest.mark.parametrize("payload", BAD_ROOTS.values(), ids=list(BAD_ROOTS))
def test_bad_roots_are_corruption_not_an_empty_vault(tmp_path, payload):
    path = tmp_path / "accounts.json"
    path.write_bytes(payload)
    storage = AccountStorage(path)

    storage.load()  # must not raise
    assert storage.is_corrupt, "a malformed vault must be flagged, not silently emptied"

    with pytest.raises(AccountCorruptionError):
        storage.save(AccountStore())
    assert path.read_bytes() == payload, "the credentials file must survive byte-for-byte"


@pytest.mark.parametrize("doc", BAD_DOCS.values(), ids=list(BAD_DOCS))
def test_invalid_documents_are_rejected(tmp_path, doc):
    path = tmp_path / "accounts.json"
    raw = json.dumps(doc).encode("utf-8")
    path.write_bytes(raw)
    storage = AccountStorage(path)

    storage.load()
    assert storage.is_corrupt, f"{doc!r} must be rejected"
    with pytest.raises(AccountCorruptionError):
        storage.save(AccountStore())
    assert path.read_bytes() == raw


@pytest.mark.parametrize("doc", BAD_DOCS.values(), ids=list(BAD_DOCS))
def test_validator_raises_only_the_domain_error(doc):
    with pytest.raises(AccountCorruptionError):
        validate_account_document(doc)


def test_a_valid_vault_still_loads(tmp_path):
    path = tmp_path / "accounts.json"
    path.write_text(
        json.dumps(_doc(default_email="user@example.com")),
        encoding="utf-8",
    )
    storage = AccountStorage(path)
    store = storage.load()
    assert not storage.is_corrupt
    assert [a.email for a in store.accounts] == ["user@example.com"]
    assert store.default_email == "user@example.com"


def test_corruption_is_preserved_and_backed_up(tmp_path):
    path = tmp_path / "accounts.json"
    original = b'{"accounts": [,,, broken'
    path.write_bytes(original)
    storage = AccountStorage(path)
    storage.load()

    assert storage.corrupt_backup is not None
    assert storage.corrupt_backup.read_bytes() == original
    assert path.read_bytes() == original


def test_a_vault_corrupted_after_construction_is_not_overwritten(tmp_path):
    """The stale-snapshot path: object built while valid, file damaged after."""
    path = tmp_path / "accounts.json"
    path.write_text(json.dumps(_doc()), encoding="utf-8")
    storage = AccountStorage(path)
    store = storage.load()
    assert not storage.is_corrupt

    damaged = b"{ broken since we loaded"
    path.write_bytes(damaged)

    with pytest.raises(AccountCorruptionError):
        storage.save(store)
    assert path.read_bytes() == damaged


def test_manager_mutation_cannot_destroy_a_corrupt_vault(tmp_path):
    """End-to-end: this is the exact sequence that wiped stored credentials."""
    from megabasterd_cli.accounts.manager import AccountManager

    path = tmp_path / "accounts.json"
    original = b'{"accounts": [,,, broken'
    path.write_bytes(original)

    manager = AccountManager(path)
    manager.unlock("passphrase")
    with pytest.raises(AccountCorruptionError):
        manager.add_account("new@example.com", "password")
    assert path.read_bytes() == original, "the vault was overwritten by an empty one"


def test_saving_a_valid_vault_still_works(tmp_path):
    from megabasterd_cli.accounts.manager import AccountManager

    path = tmp_path / "accounts.json"
    manager = AccountManager(path)
    manager.unlock("passphrase")
    manager.add_account("a@example.com", "pw", make_default=True)
    manager.add_account("b@example.com", "pw2")

    reloaded = AccountStorage(path).load()
    assert sorted(a.email for a in reloaded.accounts) == ["a@example.com", "b@example.com"]
    assert reloaded.default_email == "a@example.com"
