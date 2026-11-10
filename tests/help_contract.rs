//! Human help remains discoverable before runtime configuration or account work.
#![allow(clippy::unwrap_used)]

use clap::{Parser, error::ErrorKind};
use megabasterd_cli::cli::args::Cli;

#[test]
fn source_help_descriptions_commands_and_options_remain_visible_with_successful_help_status() {
    for (command, required) in [
        (vec![], vec!["MegaBasterd CLI"]),
        (vec!["proxy"], vec!["serve", "fetch"]),
        (
            vec!["download"],
            vec!["--parallel", "--password", "--input-file"],
        ),
        (
            vec!["upload"],
            vec!["--share", "--keep-structure", "--auto-account"],
        ),
        (
            vec!["crypter"],
            vec!["encrypt", "decrypt", "make-link", "resolve"],
        ),
        (vec!["share"], vec!["password"]),
        (vec!["info"], vec!["no account or MFA needed"]),
    ] {
        let mut arguments = vec!["mb"];
        arguments.extend(command.iter().copied());
        arguments.push("--help");
        let error = match Cli::try_parse_from(arguments) {
            Err(error) => error,
            Ok(_) => panic!("help incorrectly dispatched a runtime command"),
        };
        assert_eq!(error.kind(), ErrorKind::DisplayHelp, "{command:?}");
        assert_eq!(error.exit_code(), 0, "{command:?}");
        assert!(!error.use_stderr(), "help belongs on stdout");
        let help = error.render().to_string();
        assert!(help.contains("Usage:") && help.contains("--help"));
        assert!(!help.contains('\u{1b}'));
        for text in required {
            assert!(
                help.contains(text),
                "missing {text:?} in {command:?}: {help}"
            );
        }
    }
}
