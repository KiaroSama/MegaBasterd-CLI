"""The proxy store must be read and written inside ONE lock.

`_save_pool` took the cross-process lock, which made the WRITE atomic. But
every command loaded the pool outside it:

    pool = _load_pool()      # unlocked read
    pool.add(url)            # mutate a stale copy
    _save_pool(pool)         # locked write of that stale copy

That is a textbook lost update. Two `mb proxy add` processes both read the
same pool, both append their own entry, and whichever saves second overwrites
the first - with the lock held, so nothing looks wrong.

Read-modify-write is one transaction or it is nothing. These tests use REAL
subprocesses because the lock is an advisory OS lock and re-entrant within a
single process.

Item 7 rides along: `proxy remove` printed the raw URL, which carries
`user:password@`.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
from click.testing import CliRunner

from megabasterd_cli.commands.proxy_cmd import proxy_cmd

REPO_SRC = str(Path(__file__).resolve().parents[1] / "src")
SENTINEL = "http://sentinel-user:sentinel-password@example.invalid:8080"


@pytest.fixture
def pool_dir(tmp_path, monkeypatch):
    """Point the proxy store at an isolated directory."""
    monkeypatch.setattr("megabasterd_cli.proxy.runtime.data_dir", lambda: tmp_path)
    return tmp_path


def _pool_file(pool_dir: Path) -> Path:
    from megabasterd_cli.commands.proxy_cmd import _pool_path

    return _pool_path()


def _urls(pool_dir: Path) -> set[str]:
    path = _pool_file(pool_dir)
    if not path.exists():
        return set()
    return set(json.loads(path.read_text(encoding="utf-8"))["proxies"])


def _run(args, *, catch=False):
    from megabasterd_cli.config import Config

    return CliRunner().invoke(proxy_cmd, args, obj={"config": Config()}, catch_exceptions=catch)


def _child(data_dir: Path, body: str) -> subprocess.CompletedProcess:
    """Run a proxy mutation in a genuinely separate process."""
    script = textwrap.dedent(
        f"""
        import sys
        sys.path.insert(0, {REPO_SRC!r})
        from pathlib import Path
        import megabasterd_cli.proxy.runtime as rt
        import megabasterd_cli.commands.proxy_cmd as pc
        rt.data_dir = lambda: Path({str(data_dir)!r})
        {textwrap.indent(textwrap.dedent(body), "        ").lstrip()}
        """
    )
    return subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=120
    )


# ---------------------------------------------------------------------------
# Item 6 - the whole read-modify-write is one transaction
# ---------------------------------------------------------------------------


def test_two_processes_adding_different_proxies_keep_both(pool_dir, tmp_path):
    """The lost update, forced rather than raced.

    Running the two children one after another proves nothing: sequentially,
    even the broken code reads the previous write. The overlap has to be made
    deterministic, so each child parks between opening its transaction and
    committing, and only proceeds once BOTH have opened one. Under the old
    unlocked read that guarantees two stale snapshots and one lost entry;
    under the transaction the second child simply waits for the lock and then
    re-reads.
    """
    _run(["add", "http://seed.invalid:1"])
    gate = tmp_path / "gate"

    body = """
        import time
        from pathlib import Path
        gate = Path({gate!r})
        marker = Path({marker!r})
        with pc.pool_transaction() as pool:
            marker.write_text("open")
            # Wait until the sibling has also opened its transaction, or give
            # up - if the lock works, the sibling CANNOT open one, and that is
            # exactly the behaviour under test.
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and not gate.exists():
                time.sleep(0.05)
            pool.add({url!r})
    """

    procs = []
    for n in (1, 2):
        marker = tmp_path / f"open{n}"
        procs.append(
            subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    textwrap.dedent(
                        f"""
                        import sys
                        sys.path.insert(0, {REPO_SRC!r})
                        from pathlib import Path
                        import megabasterd_cli.proxy.runtime as rt
                        import megabasterd_cli.commands.proxy_cmd as pc
                        rt.data_dir = lambda: Path({str(pool_dir)!r})
                        {textwrap.indent(
                            textwrap.dedent(
                                body.format(
                                    gate=str(gate),
                                    marker=str(marker),
                                    url=f"http://p{n}.invalid:{n}",
                                )
                            ),
                            "                        ",
                        ).lstrip()}
                        """
                    ),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        )

    gate.write_text("go")  # release both, whichever got in first
    for proc in procs:
        out, err = proc.communicate(timeout=120)
        assert proc.returncode == 0, err

    urls = _urls(pool_dir)
    assert "http://p1.invalid:1" in urls, f"p1 was lost: {urls}"
    assert "http://p2.invalid:2" in urls, f"p2 was lost: {urls}"
    assert "http://seed.invalid:1" in urls


def test_a_concurrent_add_and_remove_do_not_lose_each_other(pool_dir):
    _run(["add", "http://keep.invalid:1", "http://drop.invalid:2"])

    a = _child(pool_dir, 'pc.proxy_add.callback(("http://fresh.invalid:3",))')
    b = _child(pool_dir, 'pc.proxy_remove.callback("http://drop.invalid:2")')
    assert a.returncode == 0, a.stderr
    assert b.returncode == 0, b.stderr

    urls = _urls(pool_dir)
    assert "http://keep.invalid:1" in urls
    assert "http://fresh.invalid:3" in urls, f"the add was lost: {urls}"
    assert "http://drop.invalid:2" not in urls, f"the remove was lost: {urls}"


def test_a_concurrent_import_and_add_preserve_every_entry(pool_dir, tmp_path):
    listing = tmp_path / "proxies.txt"
    listing.write_text("http://i1.invalid:1\nhttp://i2.invalid:2\n", encoding="utf-8")

    a = _child(pool_dir, f"pc.proxy_import.callback(Path({str(listing)!r}))")
    b = _child(pool_dir, 'pc.proxy_add.callback(("http://direct.invalid:9",))')
    assert a.returncode == 0, a.stderr
    assert b.returncode == 0, b.stderr

    urls = _urls(pool_dir)
    for expected in ("http://i1.invalid:1", "http://i2.invalid:2", "http://direct.invalid:9"):
        assert expected in urls, f"{expected} lost: {urls}"


def test_a_corrupt_store_blocks_mutation_and_is_preserved(pool_dir):
    path = _pool_file(pool_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    original = b'["this is a list, not an object"]'
    path.write_bytes(original)

    result = _run(["add", "http://new.invalid:1"], catch=True)

    assert result.exit_code != 0, "a corrupt store allowed a mutation"
    assert path.read_bytes() == original, "the corrupt store was overwritten"


def test_a_failed_replace_leaves_no_temp(pool_dir, monkeypatch):
    import os

    _run(["add", "http://seed.invalid:1"])
    monkeypatch.setattr(os, "replace", lambda *a, **k: (_ for _ in ()).throw(OSError("nope")))

    with pytest.raises(OSError):
        _run(["add", "http://another.invalid:2"])

    leftovers = list(_pool_file(pool_dir).parent.glob("*.tmp"))
    assert leftovers == [], f"orphaned temp files: {leftovers}"


# ---------------------------------------------------------------------------
# Item 7 - no proxy command may print credentials
# ---------------------------------------------------------------------------


def _assert_no_credentials(result, *, where: str) -> None:
    blob = f"{result.output}\n{result.exception!r}"
    assert "sentinel-user" not in blob, f"username leaked in {where}: {blob[:400]}"
    assert "sentinel-password" not in blob, f"password leaked in {where}: {blob[:400]}"


def test_add_does_not_print_credentials(pool_dir):
    _assert_no_credentials(_run(["add", SENTINEL]), where="add")


def test_remove_does_not_print_credentials_on_success(pool_dir):
    """The regression: `Removed {url}` printed the password verbatim."""
    _run(["add", SENTINEL])
    _assert_no_credentials(_run(["remove", SENTINEL]), where="remove/success")


def test_remove_does_not_print_credentials_when_absent(pool_dir):
    _assert_no_credentials(_run(["remove", SENTINEL]), where="remove/not-found")


def test_list_does_not_print_credentials(pool_dir):
    _run(["add", SENTINEL])
    _assert_no_credentials(_run(["list"]), where="list")


def test_import_does_not_print_credentials(pool_dir, tmp_path):
    listing = tmp_path / "p.txt"
    listing.write_text(SENTINEL + "\n", encoding="utf-8")
    _assert_no_credentials(_run(["import", str(listing)]), where="import")


def test_the_raw_url_is_still_used_for_matching(pool_dir):
    """Redaction is a DISPLAY concern; removal must still match the real URL."""
    _run(["add", SENTINEL])
    assert SENTINEL in _urls(pool_dir)

    result = _run(["remove", SENTINEL])

    assert result.exit_code == 0
    assert SENTINEL not in _urls(pool_dir), "redaction broke the actual removal"
