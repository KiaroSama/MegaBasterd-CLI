"""Centralized upload finalization: log/hook/share parity across modes."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import megabasterd_cli.utils.hooks as hooks_module
from megabasterd_cli.commands.upload_cmd import finalize_upload_success
from megabasterd_cli.core.errors import MegaError
from megabasterd_cli.core.uploader import UploadResult


class _FakeClient:
    def __init__(self, link="https://mega.nz/file/H#K", fail_share=False):
        self.session = SimpleNamespace(email="acc@example.com")
        self._link = link
        self._fail_share = fail_share
        self.export_calls: list[tuple] = []

    def export_link(self, handle, password=None):
        self.export_calls.append((handle, password))
        if self._fail_share:
            raise MegaError(message="share boom")
        return self._link


def _cfg(tmp_path, run_command=None):
    return SimpleNamespace(
        upload_log_path=str(tmp_path / "uploads.jsonl"),
        run_command=run_command,
    )


def _result(name="f.bin", size=4):
    return UploadResult(file_handle="H", name=name, size=size, elapsed_seconds=1.5)


def test_finalize_writes_log_runs_hook_and_shares(tmp_path, monkeypatch):
    hook_calls: list[tuple] = []
    monkeypatch.setattr(
        hooks_module,
        "run_post_transfer_command",
        lambda command, path: hook_calls.append((command, path)),
    )
    # The command module imported the symbol directly; patch there too.
    import megabasterd_cli.commands.upload_cmd as upload_cmd_module

    monkeypatch.setattr(
        upload_cmd_module,
        "run_post_transfer_command",
        lambda command, path: hook_calls.append((command, path)),
    )

    cfg = _cfg(tmp_path, run_command="notify.exe --token X")
    client = _FakeClient()
    notes: list[tuple[str, str]] = []
    local = tmp_path / "f.bin"
    local.write_bytes(b"data")

    link = finalize_upload_success(
        cfg,
        client,
        _result(),
        local,
        share=True,
        share_password="pw",
        note=lambda k, m: notes.append((k, m)),
    )

    assert link == "https://mega.nz/file/H#K"
    assert client.export_calls == [("H", "pw")]
    record = json.loads(Path(cfg.upload_log_path).read_text(encoding="utf-8"))
    assert record["handle"] == "H"
    assert record["public_link"] == link
    assert record["account"] == "acc@example.com"
    assert hook_calls == [("notify.exe --token X", local)]
    kinds = [k for k, _ in notes]
    assert kinds == ["success", "info"]


def test_share_failure_is_reported_separately_not_as_upload_failure(tmp_path):
    cfg = _cfg(tmp_path)
    client = _FakeClient(fail_share=True)
    notes: list[tuple[str, str]] = []
    local = tmp_path / "f.bin"
    local.write_bytes(b"data")

    link = finalize_upload_success(
        cfg, client, _result(), local, share=True, note=lambda k, m: notes.append((k, m))
    )

    assert link is None
    kinds = [k for k, _ in notes]
    assert "success" in kinds, "the upload itself still succeeded"
    assert "error" in kinds, "the share failure is reported separately"
    # Log record still written, without a link.
    record = json.loads(Path(cfg.upload_log_path).read_text(encoding="utf-8"))
    assert record["public_link"] is None


def test_hook_failure_never_breaks_the_transfer(tmp_path):
    cfg = _cfg(tmp_path, run_command="definitely-not-a-real-binary-xyz")
    client = _FakeClient()
    local = tmp_path / "f.bin"
    local.write_bytes(b"data")
    # Must not raise even though the hook cannot start.
    finalize_upload_success(cfg, client, _result(), local, note=lambda k, m: None)
