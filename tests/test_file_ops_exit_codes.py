"""Failure paths of split/merge/thumbnail must exit non-zero.

Historical bug: `merge` caught SplitterError, printed it, and returned from the
Click callback -- exit code 0. A refused merge (alias guard) therefore let
`mb merge ... && rm parts.*` delete the parts the guard had just protected.
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from megabasterd_cli.cli import cli


@pytest.fixture()
def cli_env(tmp_path, monkeypatch):
    monkeypatch.setenv("MEGABASTERD_USER_DIR", str(tmp_path / "user"))
    monkeypatch.setenv("MEGABASTERD_LOG_DIR", str(tmp_path / "logs"))
    return tmp_path


def _make_parts(tmp_path, data=b"hello world"):
    """Split a small file and return (source, list_of_parts)."""
    src = tmp_path / "payload.bin"
    src.write_bytes(data)
    result = CliRunner().invoke(cli, ["-q", "split", str(src), "1"])
    assert result.exit_code == 0, result.output
    return src, sorted(tmp_path.glob("payload.bin.part*"))


def test_merge_success_exits_zero(cli_env):
    _src, parts = _make_parts(cli_env)
    (cli_env / "payload.bin").unlink()
    result = CliRunner().invoke(cli, ["-q", "merge", str(parts[0])])
    assert result.exit_code == 0, result.output


def test_refused_merge_exits_nonzero(cli_env):
    """Output aliasing an input part: the guard refuses -- must not be exit 0."""
    _src, parts = _make_parts(cli_env)
    result = CliRunner().invoke(cli, ["-q", "merge", str(parts[0]), "-o", str(parts[0])])
    assert result.exit_code != 0, result.output
    assert parts[0].is_file()


def test_merge_missing_part_exits_nonzero(cli_env):
    _src, parts = _make_parts(cli_env, data=b"x" * (2 * 1024 * 1024 + 5))
    assert len(parts) > 1
    parts[-1].unlink()
    result = CliRunner().invoke(cli, ["-q", "merge", str(parts[0])])
    assert result.exit_code != 0, result.output


def test_merge_bad_name_exits_nonzero(cli_env):
    stray = cli_env / "not-a-part.bin"
    stray.write_bytes(b"x")
    result = CliRunner().invoke(cli, ["-q", "merge", str(stray)])
    assert result.exit_code != 0, result.output


def test_split_success_exits_zero(cli_env):
    src = cli_env / "ok.bin"
    src.write_bytes(b"data")
    result = CliRunner().invoke(cli, ["-q", "split", str(src), "1"])
    assert result.exit_code == 0, result.output


def test_split_empty_file_exits_nonzero(cli_env):
    src = cli_env / "empty.bin"
    src.write_bytes(b"")
    result = CliRunner().invoke(cli, ["-q", "split", str(src), "1"])
    assert result.exit_code != 0, result.output


def test_thumbnail_failure_exits_nonzero(cli_env):
    src = cli_env / "not-an-image.txt"
    src.write_text("definitely not a JPEG")
    result = CliRunner().invoke(cli, ["-q", "thumbnail", str(src), str(cli_env / "thumb.jpg")])
    assert result.exit_code != 0, result.output
