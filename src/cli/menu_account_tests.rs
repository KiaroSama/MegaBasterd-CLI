//! Account menu actions supply their command verb and preserve default-account input.
#![allow(clippy::unwrap_used)]

use std::io::Cursor;

use clap::Parser;

use super::{ACCOUNTS, SETTINGS, choose_with, generic_with, split_arguments};
use crate::{
    cli::{
        args::{Account, Cli, Command},
        auto_account_peer_tests::Capture,
    },
    terminal::{output::Output, prompts},
};

#[test]
fn both_account_menus_dispatch_logout_with_email_default_or_all_without_retyping_the_verb() {
    for entries in [ACCOUNTS, SETTINGS] {
        let entry = entries
            .iter()
            .find(|entry| entry.command == ["account", "logout"])
            .unwrap();
        assert!(entry.label.contains("Log out"));
        for (input, selected, all) in [
            (
                "someone@example.invalid\n",
                Some("someone@example.invalid"),
                false,
            ),
            ("\n", None, false),
            ("--all\n", None, true),
        ] {
            let stdout = Capture::default();
            let stderr = Capture::default();
            let output = Output::with_writers(false, false, stdout.clone(), stderr.clone());
            let mut input = Cursor::new(input.as_bytes());
            let mut prompt = Vec::new();
            let mut calls = 0;
            generic_with(
                &output,
                entry,
                |question| prompts::line_with_io(question, &mut input, &mut prompt),
                |arguments| {
                    calls += 1;
                    let parsed = Cli::try_parse_from(arguments).unwrap();
                    match parsed.command.unwrap() {
                        Command::Account(Account::Logout {
                            email_or_label,
                            all: actual_all,
                            ..
                        }) => {
                            assert_eq!(email_or_label.as_deref(), selected);
                            assert_eq!(actual_all, all);
                        }
                        _ => panic!("menu dispatched the wrong account command"),
                    }
                    0
                },
            )
            .unwrap();
            assert_eq!(calls, 1);
            assert!(
                String::from_utf8(prompt)
                    .unwrap()
                    .contains("mb account logout")
            );
            assert!(stdout.0.lock().unwrap().is_empty());
            assert!(
                String::from_utf8(stderr.0.lock().unwrap().clone())
                    .unwrap()
                    .contains("exit code 0")
            );
        }
    }
}

#[test]
fn menu_words_preserve_source_posix_quotes_fragments_and_malformed_fallback_on_every_os() {
    for (text, expected) in [
        ("-o \"my folder\" -w 4", vec!["-o", "my folder", "-w", "4"]),
        ("", vec![]),
        ("a \"unbalanced", vec!["a", "\"unbalanced"]),
        (
            "https://mega.nz/file/ID#KEY #literal",
            vec!["https://mega.nz/file/ID#KEY", "#literal"],
        ),
        (
            r#""C:\Media\two  spaces.bin""#,
            vec![r"C:\Media\two  spaces.bin"],
        ),
        (r#""\$HOME" "\`date\`""#, vec![r"\$HOME", r"\`date\`"]),
        ("one\rtwo", vec!["one", "two"]),
        ("'' \"\" pre\"mid dle\"post", vec!["", "", "premid dlepost"]),
        ("one\\\ntwo", vec!["one\ntwo"]),
        ("trail\\", vec!["trail\\"]),
        ("'فایل  فارسی'", vec!["فایل  فارسی"]),
    ] {
        assert_eq!(split_arguments(text), expected, "input: {text:?}");
    }
}

#[test]
fn account_menu_entries_supply_all_seven_verbs_and_preserve_settings_default() {
    use std::collections::BTreeSet;

    let mut reached = BTreeSet::new();
    for entry in ACCOUNTS
        .iter()
        .filter(|entry| entry.command.first() == Some(&"account"))
    {
        let output = Output::with_writers(false, false, Capture::default(), Capture::default());
        generic_with(
            &output,
            entry,
            |_| Ok(Some("someone@example.invalid".into())),
            |arguments| {
                let words: Vec<_> = arguments
                    .iter()
                    .map(|word| word.to_str().unwrap())
                    .collect();
                assert_eq!(words[1], "account");
                reached.insert(words[2].to_owned());
                0
            },
        )
        .unwrap();
    }
    assert_eq!(
        reached,
        [
            "add",
            "list",
            "logout",
            "remove",
            "default",
            "info",
            "refresh-all"
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );
    assert_eq!(
        SETTINGS[0].command,
        ["config", "show"],
        "restored shortcuts must not change the existing Enter default"
    );
}

#[test]
fn menu_choices_accept_only_decimal_indices_and_retry_without_dispatching_invalid_forms() {
    for (answer, expected) in [
        ("\n", Some(1)),
        ("3\n", Some(3)),
        ("0\n", Some(0)),
        ("exit\n", None),
        (" EXIT \n", None),
        ("٣\n", Some(3)),
    ] {
        let mut input = Cursor::new(answer.as_bytes());
        let stdout = Capture::default();
        let stderr = Capture::default();
        let output = Output::with_writers(false, false, stdout.clone(), stderr.clone());
        assert_eq!(
            choose_with(&output, "Menu", &["a", "b", "c"], true, |question| {
                assert_eq!(question, "Selection [1] {back=0, quit=exit}:");
                prompts::line_with_io(question, &mut input, &mut Vec::new())
            })
            .unwrap(),
            expected
        );
        assert!(stdout.0.lock().unwrap().is_empty());
        assert_eq!(
            std::str::from_utf8(&stderr.0.lock().unwrap()).unwrap(),
            "\nMenu:\n  1. a [1]\n  2. b\n  3. c\n"
        );
    }
    for invalid in ["99", "abc", "+1", "1-1", "1_0", "1,1", "²"] {
        let mut input = Cursor::new(format!("{invalid}\n0\n").into_bytes());
        let stderr = Capture::default();
        let output = Output::with_writers(false, false, Capture::default(), stderr.clone());
        assert_eq!(
            choose_with(&output, "Menu", &["a", "b", "c"], true, |question| {
                prompts::line_with_io(question, &mut input, &mut Vec::new())
            })
            .unwrap(),
            Some(0)
        );
        assert!(
            String::from_utf8(stderr.0.lock().unwrap().clone())
                .unwrap()
                .contains("Invalid selection")
        );
        assert_eq!(input.position(), input.get_ref().len() as u64);
    }
}

#[test]
fn canceled_account_menu_arguments_never_dispatch() {
    let entry = ACCOUNTS
        .iter()
        .find(|entry| entry.command == ["account", "logout"])
        .unwrap();
    for (input, keep_menu) in [
        ("", false),
        ("0\n", true),
        ("back\n", true),
        (" EXIT \n", false),
    ] {
        let mut input = Cursor::new(input.as_bytes());
        let output = Output::with_writers(false, false, Capture::default(), Capture::default());
        assert_eq!(
            generic_with(
                &output,
                entry,
                |question| prompts::line_with_io(question, &mut input, &mut Vec::new()),
                |_| panic!("canceled menu input reached command execution"),
            )
            .unwrap(),
            keep_menu
        );
    }
}
