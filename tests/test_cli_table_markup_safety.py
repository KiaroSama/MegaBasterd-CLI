"""`config show` and `proxy list` must render stored values literally.

Both built a raw `rich.table.Table`, so a plain `str` cell was parsed as Rich
markup. The cells hold stored config values and proxy URLs - and proxy URLs
arrive from `mb proxy fetch` (a remote public list) and `mb proxy import` (an
arbitrary file), so the content is not the user's own.

Two consequences, one of them permanent: a balanced tag picks the styling, and
an UNBALANCED tag raises `MarkupError`, killing the command with exit 1 on
every subsequent run until the stored file is hand-edited. `ui.theme.SafeTable`
exists for exactly this and is already used by `cloud_cmd`/`info_cmd`.
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from megabasterd_cli.cli import cli
from megabasterd_cli.commands import config_cmd as config_module
from megabasterd_cli.commands import proxy_cmd as proxy_module
from megabasterd_cli.ui.theme import make_console

STYLED = "[bold red]PWNED[/bold red]"
UNBALANCED = "agent[/bold]x"


@pytest.fixture()
def cli_env(tmp_path, monkeypatch):
    monkeypatch.setenv("MEGABASTERD_USER_DIR", str(tmp_path / "user"))
    monkeypatch.setenv("MEGABASTERD_LOG_DIR", str(tmp_path / "logs"))
    # The auto-detected width (80) would wrap a long cell and hide the evidence.
    monkeypatch.setattr(config_module, "_console", make_console(width=400))
    monkeypatch.setattr(proxy_module, "_console", make_console(width=400))
    return tmp_path


def _run(*args):
    return CliRunner().invoke(cli, list(args))


# ---------------------------------------------------------------------------
# config show
# ---------------------------------------------------------------------------


def test_config_show_prints_markup_literally(cli_env):
    assert _run("config", "set", "user_agent", STYLED).exit_code == 0
    result = _run("config", "show")
    assert result.exit_code == 0, result.output
    assert STYLED in result.output, "the stored value chose its own styling"


def test_config_show_survives_unbalanced_markup(cli_env):
    """The persistent brick: `config show` failed forever, config unreadable."""
    assert _run("config", "set", "user_agent", UNBALANCED).exit_code == 0
    result = _run("config", "show")
    assert result.exception is None, f"config show raised {result.exception!r}"
    assert result.exit_code == 0, result.output
    assert UNBALANCED in result.output


# ---------------------------------------------------------------------------
# proxy list
# ---------------------------------------------------------------------------


def test_proxy_list_prints_markup_literally(cli_env):
    url = f"http://{STYLED}.example:8080"
    assert _run("proxy", "add", url).exit_code == 0
    result = _run("proxy", "list")
    assert result.exit_code == 0, result.output
    assert STYLED in result.output


def test_proxy_list_survives_unbalanced_markup(cli_env):
    """One poisoned line from `proxy fetch`/`import` bricked the whole listing."""
    assert _run("proxy", "add", "http://evil[/bold].example:8080").exit_code == 0
    assert _run("proxy", "add", "http://good.example:8080").exit_code == 0
    result = _run("proxy", "list")
    assert result.exception is None, f"proxy list raised {result.exception!r}"
    assert result.exit_code == 0, result.output
    assert "evil[/bold].example:8080" in result.output
    assert "good.example:8080" in result.output
