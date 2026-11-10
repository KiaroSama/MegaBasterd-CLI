use std::io::{self, BufRead, IsTerminal, Read, Write};

use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub const MAX_PROMPT_BYTES: usize = 64 * 1024;

pub fn line(question: &str) -> Result<Option<String>> {
    if io::stdin().is_terminal()
        && let Some(control) = crate::platform::signals::current()?
    {
        return super::prompt_input::read(question, false, &control)
            .map(|answer| answer.map(|answer| answer.to_string()));
    }
    line_with_style_io(
        question,
        &mut io::stdin().lock(),
        &mut io::stderr().lock(),
        super::theme::stderr_color(),
    )
}

pub fn line_with_io(
    question: &str,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<Option<String>> {
    line_with_style_io(question, input, output, false)
}

pub(crate) fn line_with_style_io(
    question: &str,
    input: &mut impl BufRead,
    output: &mut impl Write,
    color: bool,
) -> Result<Option<String>> {
    write!(output, "{} ", super::theme::prompt(question, color))?;
    output.flush()?;
    let mut bytes = Vec::new();
    let count = input
        .take((MAX_PROMPT_BYTES + 1) as u64)
        .read_until(b'\n', &mut bytes)?;
    if count == 0 {
        return Ok(None);
    }
    if count > MAX_PROMPT_BYTES {
        return Err(Error::invalid("Prompt input exceeds 64 KiB"));
    }
    let answer =
        String::from_utf8(bytes).map_err(|_| Error::invalid("Prompt input is not UTF-8"))?;
    Ok(Some(answer.trim_end_matches(['\r', '\n']).to_owned()))
}

pub fn secret(question: &str, supplied: Option<&str>) -> Result<Zeroizing<String>> {
    if let Some(supplied) = supplied {
        return Ok(Zeroizing::new(supplied.to_owned()));
    }
    let answer = optional_secret(question)?;
    if answer.is_empty() {
        return Err(Error::Canceled);
    }
    Ok(answer)
}

pub fn optional_secret(question: &str) -> Result<Zeroizing<String>> {
    if io::stdin().is_terminal()
        && let Some(control) = crate::platform::signals::current()?
    {
        return super::prompt_input::read(question, true, &control)
            .map(|answer| answer.unwrap_or_default());
    }
    optional_secret_with(
        question,
        io::stdin().is_terminal(),
        super::theme::stderr_color(),
        |prompt| {
            let mut stderr = io::stderr().lock();
            stderr.write_all(prompt.as_bytes())?;
            stderr.flush()
        },
        rpassword::read_password,
    )
}

fn optional_secret_with(
    question: &str,
    terminal: bool,
    color: bool,
    write: impl FnOnce(&str) -> io::Result<()>,
    read: impl FnOnce() -> io::Result<String>,
) -> Result<Zeroizing<String>> {
    if !terminal {
        return Err(Error::Auth(
            "Missing secret input in noninteractive mode".into(),
        ));
    }
    write(&format!("{} ", super::theme::prompt(question, color)))?;
    let answer = Zeroizing::new(read()?);
    if answer.len() > MAX_PROMPT_BYTES {
        return Err(Error::invalid("Secret prompt input exceeds 64 KiB"));
    }
    Ok(answer)
}

pub fn confirm(question: &str, default: bool) -> Result<bool> {
    if io::stdin().is_terminal()
        && let Some(control) = crate::platform::signals::current()?
    {
        return confirm_controlled(
            question,
            default,
            &control,
            &mut io::stderr().lock(),
            super::theme::stderr_color(),
        );
    }
    confirm_with_style_io(
        question,
        default,
        &mut io::stdin().lock(),
        &mut io::stderr().lock(),
        super::theme::stderr_color(),
    )
}

pub fn confirm_with_io(
    question: &str,
    default: bool,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<bool> {
    confirm_with_style_io(question, default, input, output, false)
}

pub(crate) fn confirm_with_style_io(
    question: &str,
    default: bool,
    input: &mut impl BufRead,
    output: &mut impl Write,
    color: bool,
) -> Result<bool> {
    confirm_with(question, default, output, |question, output| {
        line_with_style_io(question, input, output, color)
    })
}

fn confirm_with<W: Write>(
    question: &str,
    default: bool,
    output: &mut W,
    mut read: impl FnMut(&str, &mut W) -> Result<Option<String>>,
) -> Result<bool> {
    let question = format!("{question} (y/n) [{}]:", if default { "Y" } else { "N" });
    loop {
        let Some(answer) = read(&question, output)? else {
            // Closed stdin never authorizes a destructive action; Enter still uses the default.
            return Ok(false);
        };
        match answer.trim().to_ascii_lowercase().as_str() {
            "" => return Ok(default),
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => writeln!(output, "Enter y or n.")?,
        }
    }
}

pub fn confirmed(question: &str, default: bool) -> Result<bool> {
    let accepted = confirm(question, default)?;
    if !accepted {
        let mut output = io::stderr().lock();
        writeln!(output, "Cancelled; nothing was changed.")?;
        output.flush()?;
    }
    Ok(accepted)
}

pub fn confirmed_with_io(
    question: &str,
    default: bool,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<bool> {
    confirmed_with_style_io(question, default, input, output, false)
}

fn confirmed_with_style_io(
    question: &str,
    default: bool,
    input: &mut impl BufRead,
    output: &mut impl Write,
    color: bool,
) -> Result<bool> {
    let accepted = confirm_with_style_io(question, default, input, output, color)?;
    if !accepted {
        writeln!(output, "Cancelled; nothing was changed.")?;
        output.flush()?;
    }
    Ok(accepted)
}

fn confirm_controlled(
    question: &str,
    default: bool,
    control: &crate::transfers::control::Control,
    output: &mut impl Write,
    color: bool,
) -> Result<bool> {
    confirm_with(question, default, output, |question, output| {
        super::prompt_input::read_with_output(question, false, control, output, color)
            .map(|answer| answer.map(|answer| answer.to_string()))
    })
}

pub(crate) fn select_controlled(
    count: usize,
    control: &crate::transfers::control::Control,
    output: &mut impl Write,
) -> Result<Vec<usize>> {
    select_with(count, output, |question, output| {
        super::prompt_input::read_with_output(question, false, control, output, false)
            .map(|answer| answer.map(|answer| answer.to_string()))
    })
}

pub fn select_with_io(
    count: usize,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<Vec<usize>> {
    select_with(count, output, |question, output| {
        line_with_io(question, input, output)
    })
}

fn select_with<W: Write>(
    count: usize,
    output: &mut W,
    mut read: impl FnMut(&str, &mut W) -> Result<Option<String>>,
) -> Result<Vec<usize>> {
    loop {
        let Some(answer) = read("Select files (all | none | 1,3-5):", output)? else {
            writeln!(output, "No answer (end of input); treating as 'none'.")?;
            output.flush()?;
            return Ok(Vec::new());
        };
        match crate::transfers::selection::parse(&answer, count) {
            Ok(selected) => return Ok(selected),
            Err(message) => writeln!(output, "Invalid selection: {message}")?,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::{cell::Cell, io::Cursor};

    use super::*;

    #[test]
    fn cli_question_default_routes_through_the_shared_prompt_renderer() {
        for (color, expected) in [
            (false, "Question [Y]: "),
            (
                true,
                "\x1b[1mQuestion \x1b[0m[\x1b[92mY\x1b[0m]\x1b[1m:\x1b[0m ",
            ),
        ] {
            let mut output = Vec::new();
            let mut input = Cursor::new(b"answer\n");
            assert_eq!(
                line_with_style_io("Question [Y]:", &mut input, &mut output, color)
                    .unwrap()
                    .as_deref(),
                Some("answer")
            );
            assert_eq!(output, expected.as_bytes());
            assert_eq!(
                expected,
                format!("{} ", super::super::theme::prompt("Question [Y]:", color))
            );
            assert_eq!(input.position(), 7);
        }
    }

    #[test]
    fn hidden_password_prompt_uses_the_shared_renderer_before_reading_without_echoing_the_secret() {
        for (question, styled) in [
            (
                "Password for user@example.com:",
                "\x1b[1mPassword for user@example.com:\x1b[0m ",
            ),
            (
                "Vault passphrase [blank to skip] {back=0, quit=exit}:",
                concat!(
                    "\x1b[1mVault passphrase \x1b[0m[\x1b[92mblank to skip\x1b[0m]",
                    "\x1b[1m \x1b[0m{\x1b[38;5;166mback=0\x1b[0m, ",
                    "\x1b[38;5;32mquit=exit\x1b[0m}\x1b[1m:\x1b[0m ",
                ),
            ),
        ] {
            for color in [false, true] {
                let written = Cell::new(false);
                let reads = Cell::new(0);
                let mut output = Vec::new();
                let answer: Zeroizing<String> = optional_secret_with(
                    question,
                    true,
                    color,
                    |prompt| {
                        output.write_all(prompt.as_bytes())?;
                        output.flush()?;
                        written.set(true);
                        Ok(())
                    },
                    || {
                        assert!(written.get(), "Secret read preceded prompt output");
                        reads.set(reads.get() + 1);
                        Ok("SECRET-NOT-ECHOED".into())
                    },
                )
                .unwrap();
                assert_eq!(answer.as_str(), "SECRET-NOT-ECHOED");
                assert_eq!(reads.get(), 1);
                let expected = if color {
                    styled.to_owned()
                } else {
                    format!("{question} ")
                };
                assert_eq!(output, expected.as_bytes());
                assert_eq!(
                    expected,
                    format!("{} ", super::super::theme::prompt(question, color))
                );
                assert!(
                    !String::from_utf8(output)
                        .unwrap()
                        .contains("SECRET-NOT-ECHOED")
                );
            }
        }
    }

    #[test]
    fn secret_prompt_refusals_preserve_noninteractive_io_and_utf8_byte_boundaries() {
        assert!(matches!(
            optional_secret_with(
                "Password:", false, true,
                |_| panic!("Noninteractive secret prompt wrote output"),
                || panic!("Noninteractive secret prompt read input"),
            ),
            Err(Error::Auth(message)) if message == "Missing secret input in noninteractive mode"
        ));
        assert!(matches!(
            optional_secret_with(
                "Password:", true, false,
                |_| Err(io::Error::new(io::ErrorKind::BrokenPipe, "prompt output failed")),
                || panic!("Failed prompt output reached the secret reader"),
            ),
            Err(Error::Io(error)) if error.kind() == io::ErrorKind::BrokenPipe
        ));
        assert!(matches!(
            optional_secret_with(
                "Password:", true, false, |_| Ok(()),
                || Err(io::Error::new(io::ErrorKind::Interrupted, "secret read failed")),
            ),
            Err(Error::Io(error)) if error.kind() == io::ErrorKind::Interrupted
        ));
        for text in [String::new(), "é".repeat(MAX_PROMPT_BYTES / 2)] {
            let expected = text.clone();
            let answer: Zeroizing<String> =
                optional_secret_with("Password:", true, false, |_| Ok(()), || Ok(text)).unwrap();
            assert_eq!(answer.as_str(), expected);
        }
        assert!(matches!(
            optional_secret_with(
                "Password:", true, false, |_| Ok(()),
                || Ok(format!("{}x", "é".repeat(MAX_PROMPT_BYTES / 2))),
            ),
            Err(Error::Invalid(message)) if message == "Secret prompt input exceeds 64 KiB"
        ));
    }
}
