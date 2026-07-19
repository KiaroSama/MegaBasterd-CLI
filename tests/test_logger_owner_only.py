"""The CLI log file is owner-only from creation, and so is every rotated backup.

`RotatingFileHandler` opens through the ambient umask, so the log - which holds
redacted-but-not-secret-free request traces - was published as 0o644 on a
typical POSIX box. The rotated backups shared the same defect.
"""

from __future__ import annotations

import logging
import os
import subprocess

import pytest

from megabasterd_cli.utils.logger import setup_logging


@pytest.fixture
def logging_teardown():
    yield
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
        handler.close()
    root.filters.clear()


def _write_log(log_file):
    setup_logging(level="DEBUG", log_file=log_file, quiet=True, max_bytes=10_000, backup_count=2)
    handler = next(h for h in logging.getLogger().handlers if hasattr(h, "doRollover"))
    logging.getLogger("t").warning("before rollover")
    handler.doRollover()
    logging.getLogger("t").warning("after rollover")
    handler.flush()
    backup = log_file.with_name(log_file.name + ".1")
    assert log_file.exists(), "no primary log was produced - this test would prove nothing"
    assert backup.exists(), "no rotated backup was produced - this test would prove nothing"
    return backup


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits")
def test_log_and_rotated_backup_are_owner_only(tmp_path, logging_teardown):
    previous = os.umask(0o000)  # a strict umask would hide the bug
    try:
        backup = _write_log(tmp_path / "cli.log")
    finally:
        os.umask(previous)

    for path in ((tmp_path / "cli.log"), backup):
        assert path.stat().st_mode & 0o777 == 0o600, f"{path.name} is {oct(path.stat().st_mode)}"


@pytest.mark.skipif(os.name != "nt", reason="Windows ACLs")
def test_log_and_rotated_backup_do_not_inherit_acls(tmp_path, logging_teardown):
    backup = _write_log(tmp_path / "cli.log")

    for path in ((tmp_path / "cli.log"), backup):
        acl = subprocess.run(
            ["icacls", str(path)], capture_output=True, text=True, timeout=60
        ).stdout
        # "(I)" marks an ACE inherited from the parent directory; a protected
        # owner-only DACL has none.
        assert "(I)" not in acl, f"{path.name} still inherits ACLs:\n{acl}"
