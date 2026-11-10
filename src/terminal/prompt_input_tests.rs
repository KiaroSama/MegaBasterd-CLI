#![allow(clippy::unwrap_used)]

use std::{cell::Cell, collections::VecDeque, io, sync::atomic::AtomicBool};

use super::*;

#[test]
fn bounded_cooked_input_preserves_unicode_lines_eof_and_refuses_excess_bytes() {
    for (bytes, expected) in [
        (b"".to_vec(), None),
        (b"\n".to_vec(), Some(String::new())),
        (
            "نام  file 🙂\r\nnext\n".as_bytes().to_vec(),
            Some("نام  file 🙂".into()),
        ),
        (
            "é".repeat(MAX_PROMPT_BYTES / 2).into_bytes(),
            Some("é".repeat(MAX_PROMPT_BYTES / 2)),
        ),
    ] {
        let control = Control::new();
        let mut input = VecDeque::from(bytes);
        let pending_lf = AtomicBool::new(false);
        let answer = read_line(&control, false, &pending_lf, || Ok(input.pop_front())).unwrap();
        assert_eq!(answer.as_deref().map(String::as_str), expected.as_deref());
        if !input.is_empty() {
            let next = read_line(&control, false, &pending_lf, || Ok(input.pop_front()))
                .unwrap()
                .unwrap();
            assert_eq!(next.as_str(), "next");
            assert!(input.is_empty());
        }
    }
    let reads = Cell::new(0);
    let error = read_line(&Control::new(), false, &AtomicBool::new(false), || {
        reads.set(reads.get() + 1);
        Ok(Some(b'x'))
    })
    .unwrap_err();
    assert_eq!(reads.get(), MAX_PROMPT_BYTES + 1);
    assert!(matches!(error, Error::Invalid(message) if message == "Prompt input exceeds 64 KiB"));
    let mut input = [0xff, b'\n'].into_iter();
    assert!(matches!(
        read_line(&Control::new(), false, &AtomicBool::new(false), || Ok(input.next())),
        Err(Error::Invalid(message)) if message == "Prompt input is not UTF-8"
    ));
}

#[test]
fn secret_byte_limit_excludes_line_endings_and_preserves_the_next_answer() {
    let limit = "é".repeat(MAX_PROMPT_BYTES / 2);
    for suffix in ["", "\n", "\r", "\r\n"] {
        for secret in [false, true] {
            let mut input = format!("{limit}{suffix}").bytes().collect::<VecDeque<_>>();
            let pending_lf = AtomicBool::new(false);
            let answer =
                read_line(&Control::new(), true, &pending_lf, || Ok(input.pop_front())).unwrap();
            assert_eq!(answer.as_deref().map(String::as_str), Some(limit.as_str()));
            // CR-only Enter cannot wait for a lookahead; its optional LF belongs to the next read.
            input.extend(b"next\n");
            let answer = read_line(&Control::new(), secret, &pending_lf, || {
                Ok(input.pop_front())
            })
            .unwrap();
            assert_eq!(answer.as_deref().map(String::as_str), Some("next"));
            assert!(input.is_empty());
        }
    }
    for next_secret in [false, true] {
        for separator in ["\r", "\r\n", "\n"] {
            let mut input = format!("secret{separator}\r\r\nthird\n")
                .bytes()
                .collect::<VecDeque<_>>();
            let pending_lf = AtomicBool::new(false);
            for (secret, expected) in [
                (true, "secret"),
                (next_secret, ""),
                (false, ""),
                (true, "third"),
            ] {
                let answer = read_line(&Control::new(), secret, &pending_lf, || {
                    Ok(input.pop_front())
                })
                .unwrap()
                .unwrap();
                assert_eq!(answer.as_str(), expected);
            }
            assert!(input.is_empty());
        }
    }
    let overlong = format!("{limit}x\r\n");
    let mut input = overlong.bytes();
    assert!(matches!(
        read_line(&Control::new(), true, &AtomicBool::new(false), || Ok(input.next())),
        Err(Error::Invalid(message)) if message == "Secret prompt input exceeds 64 KiB"
    ));
    let reads = Cell::new(0);
    assert!(matches!(
        read_line(&Control::new(), true, &AtomicBool::new(false), || {
            reads.set(reads.get() + 1);
            Ok(Some(b'x'))
        }),
        Err(Error::Invalid(message)) if message == "Secret prompt input exceeds 64 KiB"
    ));
    assert_eq!(reads.get(), MAX_PROMPT_BYTES + 1);
}

#[test]
fn hidden_input_preserves_scalar_edit_keys_and_does_not_return_escape_sequences() {
    for (input, expected) in [
        ("abé\x7f🙂\x08c\n", Some("abc")),
        ("clear me\x15ok\n", Some("ok")),
        ("first word   \x17done\n", Some("first done")),
        ("a\x1b[Db\n", Some("ab")),
        ("secret\x1b[\r", Some("secret")),
        ("secret\x1b\n", Some("secret")),
        ("secret\x1bO\n", Some("secret")),
        ("a\u{0085}b\n", Some("ab")),
        ("é\x1béok\n", Some("éok")),
        ("\x08\x7f\n", Some("")),
        ("\x04", None),
        ("x\x04\n", Some("x")),
        ("\n", Some("")),
        ("\r", Some("")),
    ] {
        let mut input = input.bytes();
        let answer = read_line(&Control::new(), true, &AtomicBool::new(false), || {
            Ok(input.next())
        })
        .unwrap();
        assert_eq!(answer.as_deref().map(String::as_str), expected);
    }
    let control = Control::new();
    let mut input = b"secret\x03\n".iter().copied();
    assert!(matches!(
        read_line(&control, true, &AtomicBool::new(false), || Ok(input.next())),
        Err(Error::Canceled)
    ));
    assert!(control.is_canceled());
    for invalid in [&[0xff, b'\n'][..], &[0xc3], &[0xc3, 8, b'\n']] {
        let mut input = invalid.iter().copied();
        assert!(matches!(
            read_line(&Control::new(), true, &AtomicBool::new(false), || Ok(input.next())),
            Err(Error::Invalid(message)) if message == "Prompt input is not UTF-8"
        ));
    }
}

#[test]
fn cooked_input_cancellation_fences_both_sides_of_a_read_and_keeps_io_failures() {
    let control = Control::new();
    control.cancel();
    assert!(matches!(
        read_line(&control, false, &AtomicBool::new(false), || panic!(
            "canceled input was read"
        )),
        Err(Error::Canceled)
    ));
    let mut output = Vec::new();
    assert!(matches!(
        read_with_output("Must not appear:", true, &control, &mut output, false),
        Err(Error::Canceled)
    ));
    assert!(output.is_empty());
    let control = Control::new();
    assert!(matches!(
        read_line(&control, false, &AtomicBool::new(false), || {
            control.cancel();
            Ok(Some(b'\n'))
        }),
        Err(Error::Canceled)
    ));
    for kind in [io::ErrorKind::BrokenPipe, io::ErrorKind::Interrupted] {
        assert!(matches!(
            read_line(&Control::new(), false, &AtomicBool::new(false), || Err(Error::from(io::Error::new(kind, "controlled input failure")))),
            Err(Error::Io(error)) if error.kind() == kind
        ));
    }
}
