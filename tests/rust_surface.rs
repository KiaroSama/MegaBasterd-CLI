//! Language-specific replacements for Python import/launcher contracts.
#![allow(clippy::unwrap_used)]
use clap::{CommandFactory, Parser};
use megabasterd_cli::{
    cli::args::Cli,
    crypto::wire,
    error::Error,
    services::hashes::file_md5,
    storage::{accounts::Accounts, paths::Paths, vault::Vault},
    terminal::{progress::format_bytes, redaction},
    transfers::control::{Control, RateLimiter},
};
use std::{fs, path::Path, process::Command};

#[test]
fn native_public_modules_and_typed_operations_resolve_at_compile_time() {
    let _: fn(&str) -> String = redaction::text;
    let _: fn(&[u8]) -> String = wire::b64_url_encode;
    let _: fn(&str) -> megabasterd_cli::error::Result<Vec<u8>> = wire::b64_url_decode;
    let _: fn(&Path) -> megabasterd_cli::error::Result<String> = file_md5;
    let _: fn() -> Control = Control::new;
    assert_eq!(Error::invalid("fixture").exit_code(), 2);
}

#[test]
fn native_checksum_matches_an_independent_multiblock_md5_vector() {
    let scratch = tempfile::tempdir().unwrap();
    let path = scratch.path().join("blob.bin");
    fs::write(&path, b"megabasterd".repeat(5000)).unwrap();
    assert_eq!(file_md5(&path).unwrap(), "67a370eef85749ca323d2c0c58b021dd");
    assert_eq!(fs::metadata(path).unwrap().len(), 55000);
}

#[test]
fn unlimited_native_limiter_accepts_calls_and_preserves_cancellation() {
    let limiter = RateLimiter::new(0.0).unwrap();
    let control = Control::new();
    limiter.acquire(1 << 20, &control).unwrap();
    limiter.acquire(4096, &control).unwrap();
    control.cancel();
    assert!(matches!(limiter.acquire(1, &control), Err(Error::Canceled)));
}

#[test]
fn byte_formatting_and_rate_suffix_keep_their_native_display_contract() {
    assert_eq!(format_bytes(0), "0 B");
    assert_eq!(format!("{}/s", format_bytes(1536)), "1.50 KB/s");
}

#[test]
fn malformed_unicode_numeric_options_return_usage_errors_without_panicking() {
    for value in ["²", "٣", "999999999999999999999999999999999999", "-1"] {
        assert!(Cli::try_parse_from(["mb", "download", "--parallel", value]).is_err());
    }
    assert!(Cli::try_parse_from(["mb", "download", "--parallel", "3"]).is_ok());
}

#[test]
fn native_help_and_alias_startup_work_with_no_interpreter_on_path() {
    for binary in [
        env!("CARGO_BIN_EXE_mb"),
        env!("CARGO_BIN_EXE_mbcli"),
        env!("CARGO_BIN_EXE_megabasterd-cli"),
    ] {
        let result = Command::new(binary)
            .env("PATH", "")
            .arg("--help")
            .output()
            .unwrap();
        assert!(result.status.success());
        assert!(String::from_utf8(result.stdout).unwrap().contains("Usage:"));
        assert!(result.stderr.is_empty());
    }
}

#[test]
fn rust_schema_has_no_exemption_allowlist_or_undocumented_commands() {
    let mut schema = Cli::command();
    schema.build();
    assert!(schema.get_subcommands().count() >= 20);
    assert!(
        schema
            .get_subcommands()
            .all(|command| !command.get_name().is_empty())
    );
    assert!(Cli::try_parse_from(["mb", "definitely_not_a_real_name"]).is_err());
}

#[test]
fn command_logging_masks_links_and_credentials_before_writing() {
    let value = redaction::text(
        "download https://mega.nz/folder/ID#KEY -p \"secret pw\" -o out --token TOKENVALUE --port 8123",
    );
    for secret in ["ID#KEY", "secret pw", "TOKENVALUE"] {
        assert!(!value.contains(secret));
    }
    assert!(value.contains("-o out") && value.contains("--port 8123"));
    assert!(value.contains("<redacted>"));
}

#[test]
fn independent_native_user_namespace_does_not_import_or_mutate_python_stores() {
    let paths = Paths::discover().unwrap();
    assert!(paths.user.ends_with("native-v2"));
    assert!(
        !Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("pyproject.toml")
            .exists()
    );
    assert!(
        !Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("Run.ps1")
            .exists()
    );
}

#[test]
fn bad_current_vault_credentials_never_split_the_passphrase_or_replace_the_account() {
    let scratch = tempfile::tempdir().unwrap();
    let path = scratch.path().join("accounts.json");
    let accounts = Accounts::new(path.clone());
    let correct = Vault::new("native test passphrase");
    accounts
        .add("me@example.invalid", "original", None, true, &correct)
        .unwrap();
    let before = fs::read(&path).unwrap();
    let wrong = Vault::new("wrong native passphrase");
    assert!(
        accounts
            .add("new@example.invalid", "new", None, false, &wrong)
            .is_err()
    );
    assert_eq!(fs::read(&path).unwrap(), before);
    assert!(
        !accounts
            .add("me@example.invalid", "replacement", None, false, &correct)
            .unwrap()
    );
    assert_eq!(
        Accounts::password(&accounts.find(None).unwrap(), &correct)
            .unwrap()
            .as_str(),
        "original"
    );
}
