#![allow(clippy::unwrap_used)]

use std::{
    ffi::OsStr,
    io::{self, Cursor, Write},
    sync::{Arc, Mutex},
};

use super::Output;
use crate::terminal::{prompts, theme};

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut output = self.0.lock().unwrap();
        if bytes.len() > 8192usize.saturating_sub(output.len()) {
            return Err(io::Error::other("Theme fixture output bound exceeded"));
        }
        output.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn menu_rows_preserve_source_keys_default_marker_and_terminal_default_labels() {
    let stdout = Capture::default();
    let stderr = Capture::default();
    let mut output = Output::with_writers(false, false, stdout.clone(), stderr.clone());
    output.color = true;
    output
        .menu("Commands", &["First", "Second", "Upload file/folder"])
        .unwrap();
    let rendered = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
    assert_eq!(
        rendered,
        concat!(
            "\n\x1b[1;38;5;117mCommands:\x1b[0m\n",
            "  \x1b[38;5;117m1.\x1b[0m First\x1b[92m [1]\x1b[0m\n",
            "  \x1b[38;5;117m2.\x1b[0m Second\n",
            "  \x1b[38;5;117m3.\x1b[0m Upload file/folder\n",
        )
    );
    assert_eq!(rendered.matches("\x1b[92m").count(), 1);
    assert!(!rendered.contains("[INFO]"));
    assert!(stdout.0.lock().unwrap().is_empty());
    let mut labels = vec!["Other"; 10];
    labels[9] = "Tenth";
    output.menu("More", &labels).unwrap();
    let bytes = stderr.0.lock().unwrap();
    let rendered = std::str::from_utf8(&bytes).unwrap();
    assert!(rendered.contains("  \x1b[38;5;117m10.\x1b[0m Tenth\n"));
    assert!(!rendered.contains("\x1b[38;5;117m 1."));
}

#[test]
fn shared_prompt_keeps_punctuation_plain_and_styles_defaults_and_navigation_independently() {
    let question = "Output directory [./Out] {back=0, quit=exit}:";
    let expected = concat!(
        "\x1b[1mOutput directory \x1b[0m[\x1b[92m./Out\x1b[0m]",
        "\x1b[1m \x1b[0m{\x1b[38;5;166mback=0\x1b[0m, ",
        "\x1b[38;5;32mquit=exit\x1b[0m}\x1b[1m:\x1b[0m",
    );
    assert_eq!(theme::prompt(question, true), expected);
    let mut output = Vec::new();
    let answer = prompts::line_with_style_io(
        question,
        &mut Cursor::new("نام  فایل\r\n".as_bytes()),
        &mut output,
        true,
    )
    .unwrap();
    assert_eq!(answer.as_deref(), Some("نام  فایل"));
    assert_eq!(String::from_utf8(output).unwrap(), format!("{expected} "));
    for question in [
        "Vault passphrase [blank to skip] {back=0, quit=exit}:",
        "Choose [1] {back=0}:",
        "Password for user@example.invalid:",
    ] {
        let styled = theme::prompt(question, true);
        assert!(styled.starts_with("\x1b[1m"));
        if question.contains('[') {
            assert!(styled.contains("[\x1b[92m"));
            assert!(styled.contains("\x1b[0m]"));
        }
        assert_eq!(theme::prompt(question, false), question);
    }
}

#[test]
fn confirmation_uses_the_shared_prompt_shape_and_keeps_eof_fail_closed() {
    for (answer, default, expected) in [("y\n", false, true), ("\n", true, true), ("", true, false)]
    {
        let mut rendered = Vec::new();
        assert_eq!(
            prompts::confirm_with_style_io(
                "Proceed?",
                default,
                &mut Cursor::new(answer.as_bytes()),
                &mut rendered,
                true
            )
            .unwrap(),
            expected,
        );
        assert_eq!(
            String::from_utf8(rendered).unwrap(),
            if default {
                "\x1b[1mProceed? (y/n) \x1b[0m[\x1b[92mY\x1b[0m]\x1b[1m:\x1b[0m "
            } else {
                "\x1b[1mProceed? (y/n) \x1b[0m[\x1b[92mN\x1b[0m]\x1b[1m:\x1b[0m "
            },
        );
    }
    let mut rendered = Vec::new();
    assert!(
        !prompts::confirm_with_io("Proceed?", false, &mut Cursor::new(b"n\n"), &mut rendered)
            .unwrap()
    );
    assert_eq!(rendered, b"Proceed? (y/n) [N]: ");
}

#[test]
fn theme_plain_mode_is_literal_and_machine_or_quiet_outputs_have_no_menu_chrome() {
    let stdout = Capture::default();
    let stderr = Capture::default();
    let output = Output::with_writers(false, false, stdout.clone(), stderr.clone());
    output
        .menu("Menu", &["First", "[red]Literal[/red]\x1b[2J\nname"])
        .unwrap();
    assert_eq!(
        std::str::from_utf8(&stderr.0.lock().unwrap()).unwrap(),
        "\nMenu:\n  1. First [1]\n  2. [red]Literal[/red] [2J name\n"
    );
    assert!(stdout.0.lock().unwrap().is_empty());
    let question = "[red]Name[/red]\x1b[2J\n[default] {back=0, quit=exit}:";
    let plain = theme::prompt(question, false);
    assert!(!plain.contains('\x1b') && !plain.contains('\n'));
    assert!(plain.contains("[red]Name[/red]"));
    let styled = theme::prompt(question, true);
    assert!(!styled.contains("\x1b[2J"));
    assert!(
        !theme::prompt("Proxy [https://name:PRIVATE@proxy.invalid]:", true).contains("PRIVATE")
    );
    for (json, quiet) in [(true, false), (false, true)] {
        let stdout = Capture::default();
        let stderr = Capture::default();
        let mut output = Output::with_writers(json, quiet, stdout.clone(), stderr.clone());
        output.color = true;
        output.menu("Must not render", &["First"]).unwrap();
        assert!(stdout.0.lock().unwrap().is_empty());
        assert!(stderr.0.lock().unwrap().is_empty());
    }
}

#[test]
fn app_owned_success_color_keeps_message_markup_literal_and_respects_quiet_and_json_streams() {
    for color in [false, true] {
        for json in [false, true] {
            for quiet in [false, true] {
                let stdout = Capture::default();
                let stderr = Capture::default();
                let mut output = Output::with_writers(json, quiet, stdout.clone(), stderr.clone());
                output.color = color;
                output
                    .message("SUCCESS", "done [bold red]literal[/bold red] [oops")
                    .unwrap();
                let diagnostic = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
                assert_eq!(
                    diagnostic,
                    if quiet {
                        ""
                    } else if color {
                        "[\x1b[32mOK\x1b[0m] done [bold red]literal[/bold red] [oops\n"
                    } else {
                        "[OK] done [bold red]literal[/bold red] [oops\n"
                    }
                );
                assert!(!diagnostic.contains("[mb.success]"));
                assert!(stdout.0.lock().unwrap().is_empty());
                output
                    .record(&serde_json::json!({"event":"result","status":"success"}))
                    .unwrap();
                let machine = String::from_utf8(stdout.0.lock().unwrap().clone()).unwrap();
                assert_eq!(
                    machine,
                    if json {
                        "{\"event\":\"result\",\"status\":\"success\"}\n"
                    } else {
                        ""
                    }
                );
                assert!(!machine.contains('\x1b') && !machine.contains("SUCCESS"));
            }
        }
    }
}

#[test]
fn menu_and_cli_prompt_paths_share_the_same_prompt_renderer() {
    let menu = include_str!("../cli/menu.rs").replace("\r\n", "\n");
    let input = include_str!("prompt_input.rs").replace("\r\n", "\n");
    let prompts = include_str!("prompts.rs").replace("\r\n", "\n");
    let body = |source: &str, start: &str, end: &str| {
        assert_eq!(source.matches(start).count(), 1);
        source
            .split_once(start)
            .unwrap()
            .1
            .split_once(end)
            .unwrap()
            .0
            .to_owned()
    };
    let menu = body(&menu, "pub fn run(", "fn read_with_control(");
    assert!(
        menu.contains("crate::terminal::prompt_input::read(question, secret, &context.control)")
    );
    let reader = body(
        &input,
        "pub(crate) fn read(",
        "pub(crate) fn read_with_output(",
    );
    assert!(
        reader.contains("read_with_output(\n        question,\n        secret,\n        control,")
    );
    let writer = body(&input, "pub(crate) fn read_with_output(", "fn read_line(");
    assert_eq!(
        writer
            .matches("super::theme::prompt(question, color)")
            .count(),
        1
    );
    let cli = body(&prompts, "pub fn line(", "pub fn line_with_io(");
    assert!(cli.contains("super::prompt_input::read(question, false, &control)"));
    assert!(cli.contains("line_with_style_io("));
    let fallback = body(
        &prompts,
        "pub(crate) fn line_with_style_io(",
        "pub fn secret(",
    );
    assert_eq!(
        fallback
            .matches("super::theme::prompt(question, color)")
            .count(),
        1
    );
    assert!(!menu.contains("theme::prompt(") && !reader.contains("theme::prompt("));
}

#[test]
fn color_policy_requires_a_terminal_and_respects_nonempty_no_color_without_global_mutation() {
    for terminal in [false, true] {
        for (value, allowed) in [
            (None, true),
            (Some(""), true),
            (Some("1"), false),
            (Some("0"), false),
        ] {
            assert_eq!(
                theme::allows_color(terminal, value.map(OsStr::new)),
                terminal && allowed
            );
        }
    }
}
