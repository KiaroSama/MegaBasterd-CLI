//! An actual discovered account store stays inside the fixture's user override, never operator data.
#![allow(clippy::unwrap_used)]

use megabasterd_cli::{
    platform::process,
    storage::{accounts::Accounts, paths::Paths, vault::Vault},
    transfers::control::Control,
};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

const CHILD: &str = "MB_ACCOUNT_ISOLATION_CHILD";
const TEST: &str =
    "discovered_account_paths_begin_empty_and_real_credentials_land_only_in_the_isolated_user_tree";

#[test]
fn native_harness_always_receives_an_isolated_user_override_from_the_shared_runner() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let value = std::env::var_os("MEGABASTERD_USER_DIR")
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| {
            panic!("Native tests require the shared runner's isolated user override")
        });
    let user = PathBuf::from(value);
    assert!(user.is_absolute() && user.starts_with(root.join(".ci-work")));
    assert!(!user.starts_with(root.join("User")));
    let paths = Paths::discover().unwrap();
    assert_eq!(paths.user, user.join("native-v2"));
    for path in [
        paths.config(),
        paths.accounts(),
        paths.queue(),
        paths.sessions(),
    ] {
        assert!(path.starts_with(&paths.user));
        assert!(!path.starts_with(root.join("User")));
    }
    let runner = include_str!("../tools/ci.rs");
    assert!(runner.contains("MEGABASTERD_USER_DIR"));
    assert!(runner.contains("runtime space/User"));
}

#[test]
fn discovered_account_paths_begin_empty_and_real_credentials_land_only_in_the_isolated_user_tree() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/account-isolation");
    if std::env::var_os(CHILD).is_some() {
        let paths = Paths::discover().unwrap();
        let expected = PathBuf::from(std::env::var_os("MB_EXPECTED_ISOLATED_USER").unwrap());
        let operator = Path::new(env!("CARGO_MANIFEST_DIR")).join("User");
        assert_eq!(paths.user, expected);
        for path in [
            paths.user.clone(),
            paths.config(),
            paths.accounts(),
            paths.queue(),
            paths.session("fixture@example.invalid"),
        ] {
            assert!(path.starts_with(&expected));
            assert!(!path.starts_with(&operator));
        }
        assert!(!paths.accounts().exists());
        let accounts = Accounts::new(paths.accounts());
        assert!(accounts.list().unwrap().accounts.is_empty());
        let vault = Vault::new("invented isolated vault passphrase");
        assert!(
            accounts
                .add(
                    "fixture@example.invalid",
                    "invented credential",
                    None,
                    true,
                    &vault
                )
                .unwrap()
        );
        assert!(paths.accounts().is_file());
        assert!(
            paths
                .accounts()
                .canonicalize()
                .unwrap()
                .starts_with(expected.canonicalize().unwrap())
        );
        let saved = accounts.find(None).unwrap();
        assert_eq!(
            &*Accounts::password(&saved, &vault).unwrap(),
            "invented credential"
        );
        return;
    }
    fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    let runtime = scratch.path().join("runtime with spaces");
    fs::create_dir(&runtime).unwrap();
    let user = scratch.path().join("isolated user");
    let temporary = scratch.path().join("private temporary");
    fs::create_dir(&temporary).unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.current_dir(scratch.path()).env_clear();
    for key in [
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
    command
        .env(CHILD, "1")
        .env("MEGABASTERD_PROJECT_ROOT", &runtime)
        .env("MEGABASTERD_USER_DIR", &user)
        .env("MB_EXPECTED_ISOLATED_USER", user.join("native-v2"))
        .env("HOOKMAKER_MAX_TEST_WORKERS", "1")
        .args(["--exact", TEST, "--test-threads=1"]);
    let result = process::run_command(
        command,
        Duration::from_secs(10),
        16 * 1024,
        16 * 1024,
        &Control::new(),
        None,
    )
    .unwrap();
    assert_eq!(result.status.code(), Some(0));
    assert!(result.stderr.is_empty());
    let output = String::from_utf8(result.stdout).unwrap();
    assert!(
        output.contains("1 passed") && output.contains("0 failed") && output.contains("0 ignored")
    );
    assert!(user.join("native-v2/Data/accounts.json").is_file());
}
