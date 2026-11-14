use std::{
    io::{self, IsTerminal, Write},
    sync::atomic::{AtomicBool, Ordering},
};

use zeroize::{Zeroize, Zeroizing};

use super::prompts::MAX_PROMPT_BYTES;
use crate::{
    error::{Error, Result},
    transfers::control::Control,
};

#[cfg(unix)]
#[path = "prompt_input_unix.rs"]
mod native;
#[cfg(windows)]
#[path = "prompt_input_windows.rs"]
mod native;
#[cfg(test)]
#[path = "prompt_input_tests.rs"]
mod tests;

// Access is serialized by the stdin lock. CR-only Enter cannot wait for an optional LF.
static PENDING_LF: AtomicBool = AtomicBool::new(false);

pub(crate) fn read(
    question: &str,
    secret: bool,
    control: &Control,
) -> Result<Option<Zeroizing<String>>> {
    read_with_output(
        question,
        secret,
        control,
        &mut io::stderr().lock(),
        super::theme::stderr_color(),
    )
}

pub(crate) fn read_with_output(
    question: &str,
    secret: bool,
    control: &Control,
    output: &mut impl Write,
    color: bool,
) -> Result<Option<Zeroizing<String>>> {
    control.checkpoint()?;
    let stdin = io::stdin();
    if !stdin.is_terminal() {
        return Err(Error::invalid("Interactive menu input requires a terminal"));
    }
    let input = stdin.lock();
    let mut reader = native::Reader::new(&input, secret, control)?;
    write!(output, "{} ", super::theme::prompt(question, color))?;
    output.flush()?;
    let result = read_line(control, secret, &PENDING_LF, || reader.next());
    reader.finish()?;
    // Unix VEOL preserves CR for the collector; echo moves left but does not advance a row.
    if secret || (cfg!(unix) && PENDING_LF.load(Ordering::Relaxed)) {
        writeln!(output)?;
        output.flush()?;
    }
    control.checkpoint()?;
    result
}

fn read_line(
    control: &Control,
    secret: bool,
    pending_lf: &AtomicBool,
    mut read: impl FnMut() -> Result<Option<u8>>,
) -> Result<Option<Zeroizing<String>>> {
    // Reserve once so growing or editing a secret never leaves an earlier allocation behind.
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_PROMPT_BYTES));
    let mut scalar = Zeroizing::new([0; 4]);
    let mut scalar_bytes = 0;
    let mut escape = 0;
    let mut submitted = false;
    loop {
        control.checkpoint()?;
        let byte = read();
        control.checkpoint()?;
        let Some(byte) = byte? else {
            pending_lf.store(false, Ordering::Relaxed);
            break;
        };
        if pending_lf.swap(false, Ordering::Relaxed) && byte == b'\n' {
            continue;
        }
        if secret {
            if byte == 3 {
                control.cancel();
                return Err(Error::Canceled);
            }
            scalar[scalar_bytes] = byte;
            scalar_bytes += 1;
            let character = match std::str::from_utf8(&scalar[..scalar_bytes]) {
                Ok(value) => value
                    .chars()
                    .next()
                    .ok_or_else(|| Error::invalid("Prompt input is not UTF-8"))?,
                Err(error) if error.error_len().is_none() && scalar_bytes < scalar.len() => {
                    continue;
                }
                Err(_) => return Err(Error::invalid("Prompt input is not UTF-8")),
            };
            scalar_bytes = 0;
            scalar.zeroize();
            if matches!(character, '\r' | '\n') {
                pending_lf.store(character == '\r', Ordering::Relaxed);
                submitted = true;
                break;
            }
            if escape != 0 {
                escape = match (escape, character) {
                    (1, '[' | 'O') => 2,
                    (2, '\x40'..='\x7e') => 0,
                    (2, _) => 2,
                    _ => 0,
                };
                continue;
            }
            match character {
                '\x04' if bytes.is_empty() => return Ok(None),
                '\x08' | '\x7f' => {
                    erase_scalar(&mut bytes)?;
                    continue;
                }
                '\x15' => {
                    bytes.zeroize();
                    continue;
                }
                '\x17' => {
                    let value = std::str::from_utf8(&bytes)
                        .map_err(|_| Error::invalid("Prompt input is not UTF-8"))?;
                    let length = value.trim_end().rfind(' ').map_or(0, |space| space + 1);
                    bytes[length..].zeroize();
                    bytes.truncate(length);
                    continue;
                }
                '\x1b' => {
                    escape = 1;
                    continue;
                }
                value if value.is_control() => continue,
                _ => (),
            }
            if character.len_utf8() > MAX_PROMPT_BYTES - bytes.len() {
                return Err(input_too_long(true));
            }
            bytes.extend_from_slice(character.encode_utf8(&mut *scalar).as_bytes());
            scalar.zeroize();
            continue;
        }
        if bytes.len() == MAX_PROMPT_BYTES {
            return Err(input_too_long(false));
        }
        bytes.push(byte);
        if matches!(byte, b'\r' | b'\n') {
            pending_lf.store(byte == b'\r', Ordering::Relaxed);
            break;
        }
    }
    if scalar_bytes != 0 {
        return Err(Error::invalid("Prompt input is not UTF-8"));
    }
    if bytes.is_empty() && !submitted {
        return Ok(None);
    }
    let answer =
        std::str::from_utf8(&bytes).map_err(|_| Error::invalid("Prompt input is not UTF-8"))?;
    let answer = answer.trim_end_matches(['\r', '\n']);
    Ok(Some(Zeroizing::new(answer.to_owned())))
}

fn erase_scalar(bytes: &mut Vec<u8>) -> Result<()> {
    let value =
        std::str::from_utf8(bytes).map_err(|_| Error::invalid("Prompt input is not UTF-8"))?;
    let length = value
        .char_indices()
        .next_back()
        .map_or(0, |(index, _)| index);
    bytes[length..].zeroize();
    bytes.truncate(length);
    Ok(())
}

fn input_too_long(secret: bool) -> Error {
    Error::invalid(if secret {
        "Secret prompt input exceeds 64 KiB"
    } else {
        "Prompt input exceeds 64 KiB"
    })
}
