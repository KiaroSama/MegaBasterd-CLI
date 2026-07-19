"""Unit tests for the launcher menu that moved out of Run.ps1.

Covers the three things that changed language: menu dispatch, prompt/input
validation, and argument construction - plus the launcher-log redaction, which
now composes the central sanitizer instead of duplicating it in PowerShell
regex. The PowerShell half that stayed behind (transcript scrubbing) is proved
separately in tests/test_launcher_transcript_redaction.py.
"""

from __future__ import annotations

import json

import pytest

from megabasterd_cli import launcher_menu as lm

# ---------------------------------------------------------------------------
# Redaction of the argument list written to the launcher log
# ---------------------------------------------------------------------------


def test_option_value_pairs_are_redacted():
    out = lm.redact_args(["stream", "FAKE", "--token", "s3cret", "--port", "8123"])
    assert "s3cret" not in " ".join(out)
    assert out[out.index("--token") + 1] == "<redacted>"
    # Unrelated arguments are neither consumed nor redacted.
    assert out[-2:] == ["--port", "8123"]


def test_inline_option_form_is_redacted():
    assert "--token=<redacted>" in lm.redact_args(["stream", "--token=s3cret"])


def test_short_password_option_is_redacted():
    out = lm.redact_args(["download", "-p", "hunter2"])
    assert "hunter2" not in " ".join(out)


def test_mega_links_are_redacted():
    out = lm.redact_args(["download", "https://mega.nz/file/ID#KEY"])
    assert out == ["download", "<redacted-link>"]


def test_json_positional_secret_is_redacted_by_value_not_option_name():
    """The ELC regression: the secret rides in a POSITIONAL, not after a flag."""
    payload = json.dumps({"host.example": {"user": "u", "api_key": "SUPERSECRET"}})
    out = lm.redact_args(["config", "set", "elc_accounts", payload])
    joined = " ".join(out)
    assert "SUPERSECRET" not in joined
    assert "<redacted>" in joined
    # Non-secret fields of the same payload survive, so the log stays useful.
    assert "host.example" in joined and '"u"' in joined


def test_nested_json_positional_secret_is_redacted():
    payload = json.dumps({"a": {"b": [{"password": "pw1", "note": "keep"}]}})
    out = lm.redact_args(["config", "set", "x", payload])
    assert "pw1" not in " ".join(out)
    assert "keep" in " ".join(out)


def test_non_json_positional_still_gets_free_text_redaction():
    out = lm.redact_args(["config", "set", "note", "password: hunter2"])
    assert "hunter2" not in " ".join(out)


def test_broken_json_positional_is_not_crashing_and_stays_redacted():
    out = lm.redact_args(["config", "set", "x", '{"api_key": "oops'])
    assert "oops" not in " ".join(out)


# ---------------------------------------------------------------------------
# Prompt / input validation
# ---------------------------------------------------------------------------


def _answers(monkeypatch, *lines):
    queue = list(lines)

    def fake_read(_prompt):
        assert queue, "prompt asked for more input than the test supplied"
        return queue.pop(0)

    monkeypatch.setattr(lm, "_read_line", fake_read)
    return queue


def test_blank_answer_keeps_the_default(monkeypatch):
    _answers(monkeypatch, "")
    assert lm.ask_text("Workers", "8") == "8"


def test_exit_token_raises_quit(monkeypatch):
    _answers(monkeypatch, " EXIT ")
    with pytest.raises(lm._Quit):
        lm.ask_text("Workers", "8")


def test_back_token_raises_back(monkeypatch):
    _answers(monkeypatch, "0")
    with pytest.raises(lm._Back):
        lm.ask_text("Workers", "8")


def test_back_token_is_disabled_when_not_allowed(monkeypatch):
    _answers(monkeypatch, "0")
    assert lm.ask_text("Press Enter", allow_back=False) == "0"


def test_custom_back_token_for_numeric_prompts(monkeypatch):
    """Speed-limit prompts use `back` so that `0` stays a valid value."""
    _answers(monkeypatch, "0")
    assert lm.ask_text("Speed limit", "0", back_token="back", numeric=True) == "0"
    _answers(monkeypatch, "back")
    with pytest.raises(lm._Back):
        lm.ask_text("Speed limit", "0", back_token="back", numeric=True)


def test_numeric_validation_reprompts_until_valid(monkeypatch):
    remaining = _answers(monkeypatch, "abc", "-4", "12")
    assert lm.ask_text("Workers", "8", numeric=True) == "12"
    assert remaining == []


def test_yes_no_parsing(monkeypatch):
    _answers(monkeypatch, "")
    assert lm.ask_yes_no("Keep?", True) is True
    _answers(monkeypatch, "")
    assert lm.ask_yes_no("Keep?", False) is False
    _answers(monkeypatch, "Y")
    assert lm.ask_yes_no("Keep?", False) is True
    _answers(monkeypatch, "nope")
    assert lm.ask_yes_no("Keep?", True) is False


def test_menu_choice_defaults_validates_and_navigates(monkeypatch):
    _answers(monkeypatch, "")
    assert lm.ask_choice(8) == "1"
    _answers(monkeypatch, "3")
    assert lm.ask_choice(8) == "3"
    _answers(monkeypatch, "99")
    assert lm.ask_choice(8) == ""  # out of range -> re-render, no dispatch
    _answers(monkeypatch, "abc")
    assert lm.ask_choice(8) == ""
    _answers(monkeypatch, "0")
    with pytest.raises(lm._Back):
        lm.ask_choice(8)
    _answers(monkeypatch, "exit")
    with pytest.raises(lm._Quit):
        lm.ask_choice(8)


def test_split_args_handles_quotes_and_bad_quoting():
    assert lm.split_args('-o "my folder" -w 4') == ["-o", "my folder", "-w", "4"]
    assert lm.split_args("") == []
    assert lm.split_args('a "unbalanced') == ["a", '"unbalanced']


# ---------------------------------------------------------------------------
# Wizard stepping and argument construction
# ---------------------------------------------------------------------------

STEPS = [
    lm.Step("src", "Source", required=True),
    lm.Step("workers", "Workers", default="8", option="-w", numeric=True),
    lm.Step("flag", "Skip?", kind="yesno", default=False, option="--no-verify"),
    lm.Step("extra", "Extra", raw=True),
]


def test_wizard_collects_values_and_builds_args(monkeypatch):
    _answers(monkeypatch, "LINK", "4", "y", '--proxy "http://h:1"')
    values = lm.run_wizard("", STEPS)
    assert values is not None
    args = lm.build_args(["download", str(values["src"])], STEPS, values)
    assert args == ["download", "LINK", "-w", "4", "--no-verify", "--proxy", "http://h:1"]


def test_wizard_omits_blank_values_and_unset_flags(monkeypatch):
    _answers(monkeypatch, "LINK", "", "", "")
    values = lm.run_wizard("", STEPS)
    assert lm.build_args(["download"], STEPS, values) == ["download", "-w", "8"]


def test_wizard_back_returns_to_the_previous_step(monkeypatch):
    remaining = _answers(monkeypatch, "LINK", "0", "LINK2", "5", "n", "")
    values = lm.run_wizard("", STEPS)
    assert remaining == []
    assert values["src"] == "LINK2"
    assert values["workers"] == "5"


def test_wizard_back_on_the_first_step_abandons(monkeypatch):
    _answers(monkeypatch, "0")
    assert lm.run_wizard("", STEPS) is None


def test_wizard_blank_required_answer_abandons(monkeypatch):
    _answers(monkeypatch, "")
    assert lm.run_wizard("", STEPS) is None


def test_download_wizard_treats_a_local_file_as_an_input_list(monkeypatch, tmp_path):
    listing = tmp_path / "links.txt"
    listing.write_text("x", encoding="utf-8")
    monkeypatch.setattr(lm, "ask_secret", lambda *a, **k: "")
    _answers(monkeypatch, str(listing), "", "", "", "", "", "", "")
    seen = []
    monkeypatch.setattr(lm, "dispatch", lambda args, **k: seen.append(list(args)) or 0)
    lm.download_wizard()
    assert seen[0][:3] == ["download", "-i", str(listing)]


def test_download_wizard_passes_a_link_through_as_a_positional(monkeypatch):
    monkeypatch.setattr(lm, "ask_secret", lambda *a, **k: "")
    _answers(monkeypatch, "https://mega.nz/file/ID#KEY", "", "", "", "", "", "", "")
    seen = []
    monkeypatch.setattr(lm, "dispatch", lambda args, **k: seen.append(list(args)) or 0)
    lm.download_wizard()
    assert seen[0][:2] == ["download", "https://mega.nz/file/ID#KEY"]
    assert "-i" not in seen[0]


def test_secret_step_is_passed_as_an_option_value(monkeypatch):
    monkeypatch.setattr(lm, "ask_secret", lambda *a, **k: "linkpw")
    _answers(monkeypatch, "LINK")
    steps = [
        lm.Step("url", "MEGA link", required=True),
        lm.Step("pw", "pw", kind="secret", option="--password"),
    ]
    values = lm.run_wizard("", steps)
    assert lm.build_args(["info"], steps, values) == ["info", "--password", "linkpw"]


def test_elc_wizard_builds_a_json_payload_positional(monkeypatch):
    monkeypatch.setattr(lm, "ask_secret", lambda *a, **k: "APIKEY")
    _answers(monkeypatch, "h.example", "u")
    seen = []
    monkeypatch.setattr(lm, "dispatch", lambda args, **k: seen.append(list(args)) or 0)
    lm.elc_credentials_wizard()
    assert seen[0][:3] == ["config", "set", "elc_accounts"]
    assert json.loads(seen[0][3]) == {"h.example": {"user": "u", "api_key": "APIKEY"}}
    # And that payload is safe to log.
    assert "APIKEY" not in " ".join(lm.redact_args(seen[0]))


# ---------------------------------------------------------------------------
# Menu dispatch
# ---------------------------------------------------------------------------


def test_menu_dispatches_the_selected_entry(monkeypatch):
    _answers(monkeypatch, "2", "0")
    calls = []
    menu = lm.Menu("T", [("a", lambda: calls.append("a")), ("b", lambda: calls.append("b"))])
    lm.run_menu(menu)
    assert calls == ["b"]


def test_menu_exit_propagates_out_of_a_submenu(monkeypatch):
    _answers(monkeypatch, "exit")
    with pytest.raises(lm._Quit):
        lm.run_menu(lm.Menu("T", [("a", lambda: None)]))


def test_invalid_selection_redraws_without_dispatching(monkeypatch):
    _answers(monkeypatch, "99", "0")
    calls = []
    lm.run_menu(lm.Menu("T", [("a", lambda: calls.append("a"))]))
    assert calls == []


def test_every_menu_entry_is_callable():
    menus = [lm._main_menu(), lm.ACCOUNT_MENU, lm.QUEUE_MENU, lm.TOOLS_MENU, lm.SETTINGS_MENU]
    for menu in menus:
        assert menu.entries
        for label, action in menu.entries:
            assert label and callable(action)


def test_main_dispatches_supplied_args_without_opening_the_menu(monkeypatch):
    seen = {}

    def fake_dispatch(args, return_to_menu=True):
        seen["args"] = list(args)
        seen["return_to_menu"] = return_to_menu
        return 3

    monkeypatch.setattr(lm, "dispatch", fake_dispatch)
    assert lm.main(["--help"]) == 3
    assert seen == {"args": ["--help"], "return_to_menu": False}


def test_dispatch_propagates_the_child_exit_code(monkeypatch):
    monkeypatch.setattr(lm.subprocess, "call", lambda cmd: 7)
    assert lm.dispatch(["config", "show"], return_to_menu=False) == 7


def test_dispatch_writes_a_redacted_line_to_the_launcher_log(monkeypatch, tmp_path):
    log_file = tmp_path / "launcher.log"
    monkeypatch.setenv("MEGABASTERD_LAUNCHER_LOG_FILE", str(log_file))
    monkeypatch.setattr(lm.subprocess, "call", lambda cmd: 0)
    payload = json.dumps({"h": {"api_key": "SUPERSECRET"}})
    lm.dispatch(["config", "set", "elc_accounts", payload, "--token", "TOKENVALUE"], False)
    text = log_file.read_text(encoding="utf-8")
    assert "SUPERSECRET" not in text
    assert "TOKENVALUE" not in text
    assert "Dispatching CLI args:" in text
    assert "elc_accounts" in text
