//! Own-cloud commands refuse missing credentials before contacting any API peer.
#![allow(clippy::unwrap_used)]

use std::path::Path;

use clap::Parser;

use super::{args::Cli, auto_account_peer_tests::Capture, context::Context, dispatch};
use crate::{
    error::Error,
    protocol::{api::Api, test_peer},
    terminal::output::Output,
};

#[test]
fn parsed_mkdir_and_empty_trash_without_an_account_refuse_before_network_or_success() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/cloud-auth");
    std::fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    let stdout = Capture::default();
    let stderr = Capture::default();
    let (_, calls) = test_peer::with_peer(
        |_| panic!("an unauthenticated cloud command contacted the API"),
        |address| {
            let mut context = Context::test_peer(
                scratch.path(),
                Api::test_peer(address).unwrap(),
                Output::with_writers(false, false, stdout.clone(), stderr.clone()),
            );
            for arguments in [
                vec!["mb", "mkdir", "nope"],
                vec!["mb", "trash", "empty", "--yes"],
                vec!["mb", "share", "nope"],
                vec![
                    "mb",
                    "import",
                    "https://mega.nz/folder/ABCDEFGH#AAAAAAAAAAAAAAAAAAAAAA",
                ],
            ] {
                let command = Cli::try_parse_from(arguments).unwrap().command.unwrap();
                let error = dispatch(&mut context, command).unwrap_err();
                assert!(matches!(&error, Error::Auth(_)));
                assert_eq!(error.exit_code(), 1);
                assert_eq!(
                    error.to_string(),
                    "Authentication failed: No accounts found. Use mb account add first."
                );
                context.report_error(&error);
                for path in [
                    context.paths.accounts(),
                    context.paths.config(),
                    context.paths.queue(),
                    context.paths.sessions(),
                    context.paths.logs.clone(),
                    context.paths.output.clone(),
                ] {
                    assert!(!path.exists(), "unauthenticated command created {path:?}");
                }
            }
            let entries: Vec<_> = std::fs::read_dir(context.paths.accounts().parent().unwrap())
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect();
            assert_eq!(entries, [std::ffi::OsString::from("accounts.json.lock")]);
        },
    );
    assert!(calls.is_empty());
    assert!(stdout.0.lock().unwrap().is_empty());
    let diagnostic = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
    assert_eq!(diagnostic.matches("mb account add").count(), 4);
    for forbidden in [
        "Folder created",
        "Trash emptied",
        "SUCCESS",
        "passphrase",
        "nope",
    ] {
        assert!(!diagnostic.contains(forbidden));
    }
}
