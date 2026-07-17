"""Unified default-account resolution and auto-account quota planning."""

from __future__ import annotations

from pathlib import Path

import megabasterd_cli.accounts.manager as manager_module
from megabasterd_cli.accounts.manager import AccountManager, resolve_account_id
from megabasterd_cli.commands.upload_cmd import plan_auto_accounts


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
# --auto-account planning ledger
# ---------------------------------------------------------------------------


def test_per_file_sizes_drive_selection_and_ledger_decrements():
    ledger = {"big@example.com": 1000, "small@example.com": 300}
    jobs = [(Path("a.bin"), 600), (Path("b.bin"), 500)]
    assignment, unassigned = plan_auto_accounts(jobs, ledger)
    # First file goes to the roomiest account; the ledger decrement forces the
    # second file elsewhere even though big@ had the most space initially.
    assert assignment[Path("a.bin")] == "big@example.com"
    assert ledger["big@example.com"] == 400
    # 500 no longer fits big@ (400 left) nor small@ (300): unassigned.
    assert unassigned == [Path("b.bin")]
    assert Path("b.bin") not in assignment


def test_later_files_move_to_another_account_when_required():
    ledger = {"a@example.com": 700, "b@example.com": 600}
    jobs = [(Path("f1"), 500), (Path("f2"), 500)]
    assignment, unassigned = plan_auto_accounts(jobs, ledger)
    assert not unassigned
    assert assignment[Path("f1")] == "a@example.com"
    assert assignment[Path("f2")] == "b@example.com"
    assert ledger == {"a@example.com": 200, "b@example.com": 100}


def test_never_picks_account_with_insufficient_known_space():
    ledger = {"tiny@example.com": 10}
    assignment, unassigned = plan_auto_accounts([(Path("big"), 100)], ledger)
    assert assignment == {}
    assert unassigned == [Path("big")]
    assert ledger["tiny@example.com"] == 10, "failed planning must not consume quota"
