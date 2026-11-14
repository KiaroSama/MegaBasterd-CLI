#![allow(clippy::unwrap_used)]

use std::{
    io::{self, Cursor, Write},
    sync::{Arc, Mutex},
};

use megabasterd_cli::{
    error::Error,
    terminal::{output::Output, prompts},
};

#[test]
fn selection_eof_is_an_explained_skip_and_invalid_input_can_still_retry() {
    for input in ["", "0\n", "none\n"] {
        let mut output = Vec::new();
        let chosen =
            prompts::select_with_io(3, &mut Cursor::new(input.as_bytes()), &mut output).unwrap();
        assert!(chosen.is_empty());
        let text = String::from_utf8(output).unwrap();
        if input != "none\n" {
            assert!(text.contains("end of input"));
            assert!(text.contains("treating as 'none'"));
        }
        if input == "0\n" {
            assert!(text.contains("Invalid selection"));
        }
        assert!(!text.contains("Traceback") && !text.contains("Unexpected error"));
    }
    for (input, expected) in [("0\n2\n", vec![2]), ("\n", vec![1, 2, 3])] {
        let mut output = Vec::new();
        let chosen =
            prompts::select_with_io(3, &mut Cursor::new(input.as_bytes()), &mut output).unwrap();
        assert_eq!(chosen, expected);
        let text = String::from_utf8(output).unwrap();
        assert!(!text.contains("end of input"));
        if input.starts_with('0') {
            assert!(text.contains("Invalid selection"));
        }
    }
}

#[test]
fn confirmation_retries_unknown_answers_and_distinguishes_enter_from_closed_input() {
    for unknown in ["غ", "بله", "q", "1", "yep", "sure", "ن"] {
        let mut input = Cursor::new(format!("{unknown}\ny\n").into_bytes());
        let mut output = Vec::new();
        assert!(prompts::confirm_with_io("Proceed?", false, &mut input, &mut output).unwrap());
        assert_eq!(input.position(), input.get_ref().len() as u64);
        assert!(String::from_utf8(output).unwrap().contains("y or n"));
    }
    for (input, default, expected) in [
        ("\n", false, false),
        ("\n", true, true),
        ("y\n", false, true),
        ("Yes\n", false, true),
        ("n\n", true, false),
        ("NO\n", true, false),
        ("", false, false),
        ("", true, false),
    ] {
        let mut output = Vec::new();
        assert_eq!(
            prompts::confirm_with_io(
                "Proceed?",
                default,
                &mut Cursor::new(input.as_bytes()),
                &mut output
            )
            .unwrap(),
            expected
        );
    }
}

#[test]
fn destructive_declines_are_explained_but_acceptance_does_not_announce_cancellation() {
    for input in ["n\n", "y\n", ""] {
        let mut output = Vec::new();
        let accepted = prompts::confirmed_with_io(
            "Remove?",
            false,
            &mut Cursor::new(input.as_bytes()),
            &mut output,
        )
        .unwrap();
        assert_eq!(accepted, input == "y\n");
        let text = String::from_utf8(output).unwrap();
        assert_eq!(text.contains("Cancelled; nothing was changed."), !accepted);
    }
}

#[test]
fn prompt_input_is_bounded_utf8_literal_and_never_treats_read_failure_as_confirmation() {
    let mut output = Vec::new();
    let mut invalid = Cursor::new(vec![0xff, b'\n']);
    assert!(matches!(
        prompts::line_with_io("Question", &mut invalid, &mut output),
        Err(Error::Invalid(_))
    ));
    let mut oversized = Cursor::new(vec![b'x'; prompts::MAX_PROMPT_BYTES + 2]);
    assert!(matches!(
        prompts::line_with_io("Question", &mut oversized, &mut output),
        Err(Error::Invalid(_))
    ));
    assert_eq!(oversized.position(), (prompts::MAX_PROMPT_BYTES + 1) as u64);
    let mut output = Vec::new();
    let answer = prompts::line_with_io(
        "Remote\x1b[2J\nlabel",
        &mut Cursor::new("نام  فایل\r\n".as_bytes()),
        &mut output,
    )
    .unwrap();
    assert_eq!(answer.as_deref(), Some("نام  فایل"));
    assert!(!output.contains(&0x1b));
    struct Broken;
    impl std::io::BufRead for Broken {
        fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
            Err(std::io::Error::other("Controlled read failure"))
        }
        fn consume(&mut self, _: usize) {}
    }
    impl std::io::Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("Controlled read failure"))
        }
    }
    assert!(prompts::confirm_with_io("Proceed?", true, &mut Broken, &mut Vec::new()).is_err());
}

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut output = self.0.lock().unwrap();
        if bytes.len() > (8192usize).saturating_sub(output.len()) {
            return Err(io::Error::other("Prompt fixture output bound exceeded"));
        }
        output.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn selection_eof_uses_human_stdout_but_never_contaminates_machine_stdout() {
    for json in [false, true] {
        let stdout = Capture::default();
        let stderr = Capture::default();
        let output = Output::with_writers(json, false, stdout.clone(), stderr.clone());
        assert!(
            output
                .select_files(3, &mut Cursor::new(b"0\n"))
                .unwrap()
                .is_empty()
        );
        let human = if json { &stderr } else { &stdout };
        let diagnostic = String::from_utf8(human.0.lock().unwrap().clone()).unwrap();
        assert!(diagnostic.contains("Invalid selection"));
        assert!(diagnostic.contains("end of input"));
        assert!(diagnostic.contains("treating as 'none'"));
        assert!(!diagnostic.contains("Unexpected") && !diagnostic.contains("Traceback"));
        let unused = if json { &stdout } else { &stderr };
        assert!(unused.0.lock().unwrap().is_empty());
        if json {
            output
                .record(&serde_json::json!({"event":"result","status":"skipped"}))
                .unwrap();
            let bytes = stdout.0.lock().unwrap();
            let text = std::str::from_utf8(&bytes).unwrap();
            assert_eq!(text.lines().count(), 1);
            let record: serde_json::Value = serde_json::from_str(text).unwrap();
            assert_eq!(record["status"], "skipped");
        }
    }
}
