//! Account-default warnings follow actual selection precedence once per process.
#![allow(clippy::unwrap_used)]

use std::{
    fs,
    io::{self, Write},
    path::Path,
    process::Command,
    sync::{Arc, Mutex},
    time::Duration,
};

use megabasterd_cli::{
    cli::context::Context,
    crypto::wire::b64_url_encode,
    platform::process,
    storage::{
        accounts::{Account, AccountData},
        config_store::ConfigStore,
        files::Store,
        paths::Paths,
    },
    terminal::output::Output,
    transfers::control::Control,
};

const CHILD: &str = "MB_ACCOUNT_WARNING_CHILD";
const WARNING: &str =
    "Account-vault default and config default_account disagree; using the vault default.";

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut output = self.0.lock().unwrap();
        if bytes.len() > (16 * 1024usize).saturating_sub(output.len()) {
            return Err(io::Error::other(
                "Account warning fixture output bound exceeded",
            ));
        }
        output.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn default_conflict_warns_once_after_empty_defaults_and_explicit_overrides_without_leaking_accounts()
 {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/account-warnings");
    if std::env::var_os(CHILD).as_deref() == Some(std::ffi::OsStr::new("1")) {
        let paths = Paths::discover().unwrap();
        assert!(
            paths
                .root
                .canonicalize()
                .unwrap()
                .starts_with(base.canonicalize().unwrap())
        );
        let mut context = Context::start(false, false, Some(false)).unwrap();
        context.require_config().unwrap();
        let stdout = Capture::default();
        let stderr = Capture::default();
        context.output = Output::with_writers(false, false, stdout.clone(), stderr.clone());
        let mut envelope = b"MBV2\x0f\x08\x01".to_vec();
        envelope.extend_from_slice(&[0; 44]);
        let account = |email: &str| Account {
            email: email.into(),
            enc_password: b64_url_encode(&envelope),
            label: None,
            quota_total: None,
            quota_used: None,
            last_used_iso: None,
            notes: None,
        };
        let mut data = AccountData {
            accounts: vec![account("vault@example.com"), account("config@example.com")],
            default_email: None,
        };
        for (vault, configured, explicit, expected) in [
            (None, Some("config@example.com"), None, "config@example.com"),
            (
                Some(""),
                Some("config@example.com"),
                None,
                "config@example.com",
            ),
            (
                Some("vault@example.com"),
                Some(""),
                None,
                "vault@example.com",
            ),
            (Some("vault@example.com"), None, None, "vault@example.com"),
            (
                Some("vault@example.com"),
                Some("VAULT@EXAMPLE.COM"),
                None,
                "vault@example.com",
            ),
            (
                Some("vault@example.com"),
                Some("config@example.com"),
                Some("config@example.com"),
                "config@example.com",
            ),
        ] {
            data.default_email = vault.map(str::to_owned);
            Store::new(paths.accounts())
                .lock()
                .unwrap()
                .save(&data)
                .unwrap();
            context.config.default_account = configured.map(str::to_owned);
            assert_eq!(context.selected_account(explicit).unwrap().email, expected);
            assert!(stderr.0.lock().unwrap().is_empty());
        }
        let before = fs::read(paths.accounts()).unwrap();
        // An empty explicit selection follows the same precedence as no explicit option.
        for explicit in [Some(""), None, None] {
            assert_eq!(
                context.selected_account(explicit).unwrap().email,
                "vault@example.com"
            );
            let text = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
            assert_eq!(text.matches(WARNING).count(), 1);
            for secret in ["vault@example.com", "config@example.com", "MBV2"] {
                assert!(!text.contains(secret));
            }
            assert_eq!(fs::read(paths.accounts()).unwrap(), before);
        }
        assert!(stdout.0.lock().unwrap().is_empty());
        assert!(!paths.logs.exists() && !paths.output.exists());
        assert_eq!(
            fs::read_dir(paths.accounts().parent().unwrap())
                .unwrap()
                .count(),
            2
        );
        context.finish(0);
        return;
    }

    fs::create_dir_all(&base).unwrap();
    let scratch = private_tempfile::tempdir_in(base).unwrap();
    let root = scratch.path().join("runtime with spaces");
    let temporary = scratch.path().join("private temporary");
    let cwd = scratch.path().join("unrelated working directory");
    fs::create_dir(&temporary).unwrap();
    fs::create_dir(&cwd).unwrap();
    ConfigStore::new(root.join("User/native-v2/Config/config.json"))
        .set("max_workers", "4")
        .unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.current_dir(&cwd).env_clear();
    for key in [
        "LLVM_PROFILE_FILE",
        "PATH",
        "SystemRoot",
        "WINDIR",
        "PATHEXT",
        "LD_LIBRARY_PATH",
        "DYLD_LIBRARY_PATH",
    ] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    for key in [
        "HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "TMP",
        "TEMP",
        "TMPDIR",
    ] {
        command.env(key, &temporary);
    }
    command.env(CHILD, "1")
        .env("MEGABASTERD_PROJECT_ROOT", &root)
        .env("MEGABASTERD_USER_DIR", root.join("User"))
        .env("MEGABASTERD_LOG_DIR", root.join("private logs"))
        .env("HOOKMAKER_MAX_TEST_WORKERS", "1")
        .args(["--exact", "default_conflict_warns_once_after_empty_defaults_and_explicit_overrides_without_leaking_accounts", "--test-threads=1"]);
    let result = process::run_command(
        command,
        Duration::from_secs(5),
        16 * 1024,
        16 * 1024,
        &Control::new(),
        None,
    )
    .unwrap();
    assert_eq!(result.status.code(), Some(0));
    let stdout = String::from_utf8(result.stdout).unwrap();
    assert!(
        stdout.contains("1 passed") && stdout.contains("0 failed") && stdout.contains("0 ignored")
    );
    assert!(result.stderr.is_empty());
}

#[path = "common/private_tempfile.rs"]
mod private_tempfile;
