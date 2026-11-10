//! Source wizard fields and navigation through the production finite-input seam.
#![allow(clippy::unwrap_used)]

use super::{Outcome, Wizard, run_with};
use std::{collections::VecDeque, ffi::OsString, fs, path::Path};
use zeroize::Zeroizing;

fn answers(kind: Wizard, root: &Path, lines: &[&str]) -> (Outcome, Vec<bool>, Vec<String>) {
    let mut lines: VecDeque<_> = lines.iter().map(|line| (*line).to_owned()).collect();
    let mut secrets = Vec::new();
    let mut notices = Vec::new();
    let outcome = run_with(
        kind,
        root,
        |_, secret| {
            secrets.push(secret);
            Ok(lines.pop_front().map(Zeroizing::new))
        },
        |message| {
            notices.push(message.to_owned());
            Ok(())
        },
    )
    .unwrap();
    assert!(lines.is_empty(), "wizard did not consume expected answers");
    (outcome, secrets, notices)
}

fn ready(outcome: Outcome) -> Vec<OsString> {
    match outcome {
        Outcome::Ready(args) => args,
        _ => panic!("expected completed wizard"),
    }
}

#[test]
fn download_wizard_preserves_local_input_lists_and_all_source_options() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/menu-wizard");
    fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    let listing = scratch.path().join("links with  spaces.txt");
    fs::write(&listing, b"synthetic public link list").unwrap();
    let (outcome, secrets, _) = answers(
        Wizard::Download,
        scratch.path(),
        &[
            listing.to_str().unwrap(),
            "",
            "4",
            "2",
            "0",
            "linkpw",
            "file.bin",
            "http://proxy.invalid:3128",
            "y",
        ],
    );
    let args = ready(outcome);
    assert_eq!(
        args,
        [
            "mb",
            "download",
            "-i",
            listing.to_str().unwrap(),
            "-o",
            scratch.path().to_str().unwrap(),
            "-w",
            "4",
            "-P",
            "2",
            "-l",
            "0",
            "-p",
            "linkpw",
            "--rename",
            "file.bin",
            "--proxy",
            "http://proxy.invalid:3128",
            "--no-verify"
        ]
        .map(OsString::from)
    );
    assert_eq!(secrets.iter().filter(|value| **value).count(), 1);
    let (outcome, _, _) = answers(
        Wizard::Download,
        scratch.path(),
        &[
            "https://mega.nz/file/ID#KEY",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
        ],
    );
    let args = ready(outcome);
    assert_eq!(
        args,
        [
            "mb",
            "download",
            "https://mega.nz/file/ID#KEY",
            "-o",
            scratch.path().to_str().unwrap(),
            "-w",
            "8",
            "-P",
            "6",
            "-l",
            "0",
        ]
        .map(OsString::from)
    );
    assert!(
        !args
            .iter()
            .any(|word| word == "-i" || word == "--no-verify")
    );
}

#[test]
fn wizard_required_numeric_back_and_quit_paths_preserve_previous_answers() {
    let root = Path::new("output");
    let (outcome, _, notices) = answers(
        Wizard::Download,
        root,
        &[
            "", "LINK", "0", "LINK2", "", "abc", "-4", "12", "", "0", "", "", "", "n",
        ],
    );
    let args = ready(outcome);
    assert_eq!(args[2], "LINK2");
    assert!(
        args.windows(2)
            .any(|pair| pair == [OsString::from("-w"), OsString::from("12")])
    );
    assert!(
        args.windows(2)
            .any(|pair| pair == [OsString::from("-l"), OsString::from("0")])
    );
    assert_eq!(notices.len(), 3);
    assert!(matches!(
        answers(Wizard::Info, root, &["0"]).0,
        Outcome::Back
    ));
    for exit in ["exit", " EXIT "] {
        assert!(matches!(
            answers(Wizard::Info, root, &[exit]).0,
            Outcome::Quit
        ));
    }
    assert!(matches!(answers(Wizard::Info, root, &[]).0, Outcome::Quit));
}

#[test]
fn speed_limit_back_revisits_parallel_while_zero_remains_an_unlimited_value() {
    let root = Path::new("output");
    let mut script = VecDeque::from([
        ("MEGA link(s)", "LINK"),
        ("Output directory", ""),
        ("Workers per file", "8"),
        ("Parallel files", "2"),
        ("Speed limit KB/s", "back"),
        ("Parallel files", "3"),
        ("Speed limit KB/s", "0"),
        ("Link password", ""),
        ("Rename single file", ""),
        ("Proxy URL", ""),
        ("Skip final integrity check?", "n"),
    ]);
    let outcome = run_with(
        Wizard::Download,
        root,
        |question, _| {
            let (expected, answer) = script.pop_front().unwrap();
            assert!(
                question.starts_with(expected),
                "unexpected prompt: {question}"
            );
            if expected == "Speed limit KB/s" {
                assert!(question.contains("{back=back, quit=exit}"));
            }
            Ok(Some(Zeroizing::new(answer.to_owned())))
        },
        |message| panic!("valid back/zero answers unexpectedly retried: {message}"),
    )
    .unwrap();
    assert!(script.is_empty());
    assert_eq!(
        ready(outcome),
        [
            "mb", "download", "LINK", "-o", "output", "-w", "8", "-P", "3", "-l", "0"
        ]
        .map(OsString::from)
    );
}

#[test]
fn wizard_numeric_answers_normalize_source_decimal_syntax_before_cli_parsing() {
    let (outcome, _, notices) = answers(
        Wizard::Download,
        Path::new("output"),
        &["LINK", "", "²", "+۴", "1_2", "-۰۰", "", "", "", "n"],
    );
    let args = ready(outcome);
    assert_eq!(notices.len(), 1);
    for (option, value) in [("-w", "4"), ("-P", "12"), ("-l", "0")] {
        assert!(
            args.windows(2)
                .any(|pair| pair == [OsString::from(option), OsString::from(value)])
        );
    }
}

#[test]
fn upload_account_info_and_elc_wizards_keep_secret_and_json_argument_boundaries() {
    let root = Path::new("output");
    let (outcome, secrets, _) = answers(
        Wizard::Upload,
        root,
        &[
            "\"one file\" 'two file'",
            "main",
            "Backups",
            "3",
            "2",
            "0",
            "",
            "y",
            "y",
            "vault-pass",
            "--keep-going --rename \"quoted remote name\"",
        ],
    );
    let args = ready(outcome);
    assert_eq!(
        &args[..4],
        ["mb", "upload", "one file", "two file"].map(OsString::from)
    );
    for switch in [
        "--keep-structure",
        "--auto-account",
        "--share",
        "--keep-going",
    ] {
        assert!(args.iter().any(|arg| arg == switch));
    }
    assert!(args.windows(2).any(|pair| pair
        == [
            OsString::from("--vault-passphrase"),
            OsString::from("vault-pass")
        ]));
    assert_eq!(secrets.iter().filter(|value| **value).count(), 1);
    assert_eq!(
        &args[args.len() - 3..],
        ["--keep-going", "--rename", "quoted remote name"].map(OsString::from)
    );
    let (outcome, _, _) = answers(
        Wizard::Upload,
        root,
        &["file", "", "", "", "", "", "", "", "", "", ""],
    );
    assert_eq!(
        ready(outcome),
        [
            "mb",
            "upload",
            "file",
            "-w",
            "8",
            "-P",
            "6",
            "-l",
            "0",
            "--keep-structure"
        ]
        .map(OsString::from)
    );
    let (outcome, _, _) = answers(
        Wizard::Account,
        root,
        &["me@example.invalid", "main", "y", "n", "vault-pass"],
    );
    assert_eq!(
        ready(outcome),
        [
            "mb",
            "account",
            "add",
            "me@example.invalid",
            "--label",
            "main",
            "--default",
            "--vault-passphrase",
            "vault-pass",
            "--no-verify"
        ]
        .map(OsString::from)
    );
    let (outcome, _, _) = answers(Wizard::Info, root, &["LINK", "linkpw"]);
    assert_eq!(
        ready(outcome),
        ["mb", "info", "LINK", "--password", "linkpw"].map(OsString::from)
    );
    let (outcome, _, notices) = answers(Wizard::Elc, root, &["host.invalid", "u", "APIKEY"]);
    let args = ready(outcome);
    assert_eq!(
        &args[..4],
        ["mb", "config", "set", "elc_accounts"].map(OsString::from)
    );
    let payload: serde_json::Value = serde_json::from_str(args[4].to_str().unwrap()).unwrap();
    assert_eq!(
        payload,
        serde_json::json!({"host.invalid":{"user":"u","api_key":"APIKEY"}})
    );
    assert!(!notices.join(" ").contains("APIKEY"));
    let safe = crate::terminal::redaction::log_text(&args[4].to_string_lossy());
    assert!(!safe.contains("APIKEY"));
    assert!(safe.contains("host.invalid"));
}
