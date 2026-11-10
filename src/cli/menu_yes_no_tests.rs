//! Launcher yes/no options remain distinct from destructive action confirmations.
#![allow(clippy::unwrap_used)]

use super::{Outcome, Wizard, run_with};
use std::{collections::VecDeque, ffi::OsString, path::Path};
use zeroize::Zeroizing;

fn ready(outcome: Outcome) -> Vec<OsString> {
    match outcome {
        Outcome::Ready(arguments) => arguments,
        _ => panic!("Expected a completed wizard"),
    }
}

#[test]
fn launcher_yes_no_defaults_and_nonaffirmative_answers_build_the_exact_source_flags() {
    for (wizard, answer, enabled) in [
        (Wizard::Account, "", true),
        (Wizard::Download, "", false),
        (Wizard::Download, "Y", true),
        (Wizard::Account, "nope", false),
        (Wizard::Account, " n ", false),
        (Wizard::Account, " YES ", true),
        (Wizard::Download, "nope", false),
        (Wizard::Download, "yes", true),
    ] {
        let account = matches!(wizard, Wizard::Account);
        let mut script = if account {
            VecDeque::from(vec![
                ("Account email", "user@example.invalid"),
                ("Label", ""),
                ("Make this the default account?", answer),
                ("Verify login now?", "yes"),
                ("Vault passphrase", ""),
            ])
        } else {
            VecDeque::from(vec![
                ("MEGA link(s)", "https://mega.nz/file/ID#KEY"),
                ("Output directory", ""),
                ("Workers per file", ""),
                ("Parallel files", ""),
                ("Speed limit KB/s", ""),
                ("Link password", ""),
                ("Rename single file", ""),
                ("Proxy URL", ""),
                ("Skip final integrity check?", answer),
            ])
        };
        let outcome = run_with(
            wizard,
            Path::new("output"),
            |question, _| {
                let (expected, answer) = script.pop_front().unwrap();
                assert!(
                    question.starts_with(expected),
                    "Unexpected prompt: {question}"
                );
                if expected == "Make this the default account?" {
                    assert!(question.contains("[yes]"));
                } else if expected == "Skip final integrity check?" {
                    assert!(question.contains("[no]"));
                }
                Ok(Some(Zeroizing::new(answer.to_owned())))
            },
            |message| panic!("A source yes/no answer unexpectedly retried: {message}"),
        )
        .unwrap();
        assert!(script.is_empty());
        let mut expected: Vec<OsString> = if account {
            ["mb", "account", "add", "user@example.invalid"]
                .map(OsString::from)
                .to_vec()
        } else {
            [
                "mb",
                "download",
                "https://mega.nz/file/ID#KEY",
                "-o",
                "output",
                "-w",
                "8",
                "-P",
                "6",
                "-l",
                "0",
            ]
            .map(OsString::from)
            .to_vec()
        };
        if enabled {
            expected.push(if account { "--default" } else { "--no-verify" }.into());
        }
        assert_eq!(ready(outcome), expected);
    }
}

#[test]
fn launcher_yes_no_steps_preserve_back_zero_quit_and_closed_input_before_normalizing() {
    for token in [Some("0"), Some("back"), Some(" EXIT "), None] {
        let mut script = VecDeque::from([
            ("Account email", Some("user@example.invalid")),
            ("Label", Some("old-label")),
            ("Make this the default account?", token),
        ]);
        if matches!(token, Some("0" | "back")) {
            script.extend([
                ("Label", Some("new-label")),
                ("Make this the default account?", Some("nope")),
                ("Verify login now?", Some("yes")),
                ("Vault passphrase", Some("")),
            ]);
        }
        let outcome = run_with(
            Wizard::Account,
            Path::new("output"),
            |question, _| {
                let (expected, answer) = script.pop_front().unwrap();
                assert!(
                    question.starts_with(expected),
                    "Unexpected prompt: {question}"
                );
                Ok(answer.map(|text| Zeroizing::new(text.to_owned())))
            },
            |message| panic!("Navigation unexpectedly became an invalid answer: {message}"),
        )
        .unwrap();
        assert!(script.is_empty());
        if matches!(token, Some("0" | "back")) {
            assert_eq!(
                ready(outcome),
                [
                    "mb",
                    "account",
                    "add",
                    "user@example.invalid",
                    "--label",
                    "new-label"
                ]
                .map(OsString::from)
            );
        } else {
            assert!(matches!(outcome, Outcome::Quit));
        }
    }
}
