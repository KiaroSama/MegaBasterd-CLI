use std::{ffi::OsStr, io::IsTerminal, sync::OnceLock};

use regex::Regex;

use super::redaction::{literal, text};

const MENU_KEY: &str = "38;5;117";
const DEFAULT: &str = "92";
const BACK: &str = "38;5;166";
const EXIT: &str = "38;5;32";

pub(crate) fn allows_color(terminal: bool, no_color: Option<&OsStr>) -> bool {
    terminal && no_color.is_none_or(OsStr::is_empty)
}

pub(crate) fn stderr_color() -> bool {
    allows_color(
        std::io::stderr().is_terminal(),
        std::env::var_os("NO_COLOR").as_deref(),
    )
}

fn append(output: &mut String, value: &str, style: &str, color: bool) {
    if value.is_empty() {
        return;
    }
    if color {
        output.push_str("\x1b[");
        output.push_str(style);
        output.push('m');
    }
    output.push_str(value);
    if color {
        output.push_str("\x1b[0m");
    }
}

pub(crate) fn menu(title: &str, labels: &[&str], color: bool) -> String {
    let mut output = String::from("\n");
    append(
        &mut output,
        &format!("{}:", literal(&text(title))),
        "1;38;5;117",
        color,
    );
    output.push('\n');
    for (index, label) in labels.iter().enumerate() {
        output.push_str("  ");
        append(&mut output, &format!("{}.", index + 1), MENU_KEY, color);
        output.push(' ');
        output.push_str(&literal(&text(label)));
        if index == 0 {
            append(&mut output, " [1]", DEFAULT, color);
        }
        output.push('\n');
    }
    output
}

pub(crate) fn prompt(question: &str, color: bool) -> String {
    // Strip untrusted controls before introducing application-owned ANSI sequences.
    let question = literal(&text(question));
    if !color {
        return question;
    }
    static PARTS: OnceLock<Option<Regex>> = OnceLock::new();
    let Some(parts) = PARTS.get_or_init(|| Regex::new(r"\[[^\]]*\]|\{[^}]*\}").ok()) else {
        return question;
    };
    let mut output = String::new();
    let mut offset = 0;
    for part in parts.find_iter(&question) {
        append(&mut output, &question[offset..part.start()], "1", true);
        let group = part.as_str();
        let inner = &group[1..group.len() - 1];
        if group.starts_with('[') {
            output.push('[');
            append(&mut output, inner, DEFAULT, true);
            output.push(']');
        } else {
            output.push('{');
            for (index, token) in inner.split(", ").enumerate() {
                if index != 0 {
                    output.push_str(", ");
                }
                let lower = token.to_lowercase();
                let style = if lower.contains("back") {
                    BACK
                } else if lower.contains("exit") {
                    EXIT
                } else if lower.contains("folder") {
                    "38;2;180;140;255"
                } else {
                    "97"
                };
                append(&mut output, token, style, true);
            }
            output.push('}');
        }
        offset = part.end();
    }
    append(&mut output, &question[offset..], "1", true);
    output
}
