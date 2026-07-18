"""The post-transfer hook must fire in worker threads too.

`_run_hook_for` read `click.get_current_context()`, which is THREAD-LOCAL. In a
parallel download (`-P N`) every transfer runs on a worker thread, the context
was None there, and the user's configured `run_command` silently never ran -
no error, no log line, just a hook that worked sequentially and vanished in
parallel.

The configuration is now passed explicitly, so the helpers are Click-independent.
"""

from __future__ import annotations

import inspect
import threading
from pathlib import Path

import pytest

from megabasterd_cli.commands import download_support as ds


@pytest.fixture()
def recorded(monkeypatch):
    calls: list[tuple] = []
    monkeypatch.setattr(
        ds, "run_post_transfer_command", lambda command, path: calls.append((command, path))
    )
    return calls


def test_hook_fires_on_the_main_thread(recorded):
    ds._run_hook_for(Path("a.bin"), "notify.exe")
    assert recorded == [("notify.exe", Path("a.bin"))]


def test_hook_fires_on_a_worker_thread(recorded):
    """The regression: this silently did nothing."""
    thread = threading.Thread(target=ds._run_hook_for, args=(Path("b.bin"), "notify.exe"))
    thread.start()
    thread.join()
    assert recorded == [("notify.exe", Path("b.bin"))], "the hook did not run off-thread"


def test_parallel_workers_all_fire_the_hook(recorded):
    """Parity: N concurrent transfers produce N hook invocations."""
    from concurrent.futures import ThreadPoolExecutor

    paths = [Path(f"file{i}.bin") for i in range(8)]
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda p: ds._run_hook_for(p, "notify.exe"), paths))
    assert sorted(p.name for _cmd, p in recorded) == sorted(p.name for p in paths)


def test_no_hook_configured_is_a_no_op(recorded):
    ds._run_hook_for(Path("c.bin"), None)
    ds._run_hook_for(Path("c.bin"), "")
    assert recorded == []


def test_helpers_do_not_read_the_click_context():
    """Guard against the bug returning: worker helpers must stay Click-free.

    Checked against the CODE, not the docstring - which deliberately explains
    the old bug and would otherwise match.
    """
    import ast

    tree = ast.parse(inspect.getsource(ds._run_hook_for))
    function = tree.body[0]
    body = function.body[1:] if ast.get_docstring(function) else function.body
    code = "\n".join(ast.dump(node) for node in body)
    assert "get_current_context" not in code


def test_every_download_helper_accepts_the_hook_config():
    """If a helper cannot be given the hook, its callers cannot pass it."""
    for helper in (ds._download_file, ds._download_folder, ds._download_folder_file):
        assert "run_command" in inspect.signature(helper).parameters, helper.__name__


def test_the_command_passes_the_hook_to_every_helper_call():
    """A helper that supports the parameter is useless if a call site omits it."""
    from megabasterd_cli.commands import download_cmd

    source = inspect.getsource(download_cmd)
    helper_calls = source.count("_download_file(") + source.count("_download_folder")
    passed = source.count("run_command=cfg.run_command")
    assert passed >= 5, f"only {passed} of {helper_calls} call sites pass the hook config"
