"""Unified default-account resolution and the auto-account quota ledger."""

from __future__ import annotations

import threading

import megabasterd_cli.accounts.manager as manager_module
from megabasterd_cli.accounts.manager import AccountManager, resolve_account_id
from megabasterd_cli.upload_support import QuotaLedger


def _mgr(tmp_path, default_email=None) -> AccountManager:
    mgr = AccountManager(tmp_path / "accounts.json")
    mgr.store.default_email = default_email
    return mgr


def test_explicit_account_wins(tmp_path):
    mgr = _mgr(tmp_path, default_email="vault@example.com")
    assert resolve_account_id(mgr, "config@example.com", "explicit@example.com") == (
        "explicit@example.com"
    )


def test_vault_default_beats_legacy_config(tmp_path, monkeypatch):
    monkeypatch.setattr(manager_module, "_default_conflict_warned", False)
    mgr = _mgr(tmp_path, default_email="vault@example.com")
    assert resolve_account_id(mgr, "config@example.com") == "vault@example.com"


def test_legacy_config_fallback_keeps_working(tmp_path):
    mgr = _mgr(tmp_path, default_email=None)
    assert resolve_account_id(mgr, "config@example.com") == "config@example.com"
    assert resolve_account_id(mgr, None) is None


def test_conflict_warns_once(tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(manager_module, "_default_conflict_warned", False)
    mgr = _mgr(tmp_path, default_email="vault@example.com")
    with caplog.at_level("WARNING"):
        resolve_account_id(mgr, "config@example.com")
        resolve_account_id(mgr, "config@example.com")
    warnings = [r for r in caplog.records if "disagree" in r.getMessage()]
    assert len(warnings) == 1


# ---------------------------------------------------------------------------
# --auto-account quota ledger (per-file reservation at execution time)
# ---------------------------------------------------------------------------


def test_reserve_picks_roomiest_and_decrements():
    ledger = QuotaLedger({"big@example.com": 1000, "small@example.com": 300})
    assert ledger.reserve(600) == "big@example.com"
    assert ledger.free_of("big@example.com") == 400
    # 500 no longer fits big@ (400 left) nor small@ (300): no account.
    assert ledger.reserve(500) is None


def test_later_files_move_to_another_account_when_required():
    ledger = QuotaLedger({"a@example.com": 700, "b@example.com": 600})
    assert ledger.reserve(500) == "a@example.com"
    assert ledger.reserve(500) == "b@example.com"
    assert ledger.free_of("a@example.com") == 200
    assert ledger.free_of("b@example.com") == 100


def test_never_picks_account_with_insufficient_known_space():
    ledger = QuotaLedger({"tiny@example.com": 10})
    assert ledger.reserve(100) is None
    assert ledger.free_of("tiny@example.com") == 10, "failed reserve must not consume quota"


def test_release_and_set_free_reconcile_reservations():
    ledger = QuotaLedger({"a@example.com": 500})
    assert ledger.reserve(400) == "a@example.com"
    ledger.release("a@example.com", 400)  # non-quota failure: give it back
    assert ledger.free_of("a@example.com") == 500
    ledger.reconcile_free("a@example.com", 42)  # QuotaError refresh with live value
    assert ledger.free_of("a@example.com") == 42
    assert ledger.reserve(100) is None, "stale quota must not be trusted after refresh"


def test_exclude_prevents_infinite_account_cycling():
    ledger = QuotaLedger({"a@example.com": 1000, "b@example.com": 1000})
    first = ledger.reserve(10, exclude=set())
    second = ledger.reserve(10, exclude={"a@example.com", "b@example.com"})
    assert first is not None
    assert second is None, "excluding every attempted account bounds the retry loop"


def test_parallel_reservations_cannot_overcommit():
    ledger = QuotaLedger({"a@example.com": 1000})
    wins: list[str] = []
    barrier = threading.Barrier(8)

    def worker() -> None:
        barrier.wait()
        if ledger.reserve(300) is not None:
            wins.append("x")

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)
        assert not t.is_alive()
    assert len(wins) == 3, "1000 free admits exactly three 300-byte reservations"
    assert ledger.free_of("a@example.com") == 100
