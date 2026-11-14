//! Actual account removal deletes only the selected credential and cached session.
#![allow(clippy::unwrap_used)]

use std::{
    collections::BTreeMap,
    fs::{self, File},
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use megabasterd_cli::{
    platform::process,
    protocol::auth::Session,
    storage::{
        accounts::Accounts, config_store::ConfigStore, paths::Paths, sessions::Sessions,
        vault::Vault,
    },
    transfers::control::Control,
};

const FIRST: &str = "first@example.invalid";
const SECOND: &str = "second@example.invalid";
const PASS: &str = "synthetic removal vault";

fn snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn collect(root: &Path, directory: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            let metadata = fs::symlink_metadata(&path).unwrap();
            assert!(!metadata.file_type().is_symlink());
            if metadata.is_dir() {
                collect(root, &path, files);
            } else {
                assert!(metadata.is_file() && metadata.len() <= 16 * 1024);
                assert!(
                    files.len() < 32,
                    "account fixture inventory exceeded its bound"
                );
                files.insert(
                    path.strip_prefix(root).unwrap().to_owned(),
                    fs::read(path).unwrap(),
                );
            }
        }
    }
    let mut files = BTreeMap::new();
    collect(root, root, &mut files);
    files
}

#[test]
fn actual_binary_removes_selected_account_cache_then_last_account_without_touching_other_data() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/account-removal");
    fs::create_dir_all(&base).unwrap();
    let scratch = private_tempfile::tempdir_in(base).unwrap();
    let root = scratch.path().join("runtime with spaces");
    let paths = Paths {
        user: root.join("User/native-v2"),
        logs: root.join("private logs"),
        output: root.join("Output"),
        root,
    };
    ConfigStore::new(paths.config())
        .set("log_level", "INFO")
        .unwrap();
    let accounts = Accounts::new(paths.accounts());
    let vault = Vault::new(PASS);
    for (email, label, sid) in [
        (FIRST, "primary", "synthetic-first-sid"),
        (SECOND, "secondary", "synthetic-second-sid"),
    ] {
        assert!(
            accounts
                .add(
                    email,
                    "synthetic password",
                    Some(label.into()),
                    false,
                    &vault
                )
                .unwrap()
        );
        Sessions::new(paths.session(email))
            .remember(
                &Session {
                    sid: sid.into(),
                    master_key: [9; 16],
                    rsa_private_key: None,
                    user_handle: "synthetic-user".into(),
                    email: email.into(),
                },
                &vault,
            )
            .unwrap();
    }
    fs::create_dir(&paths.output).unwrap();
    fs::write(
        paths.output.join("keep.bin"),
        b"previous download must survive",
    )
    .unwrap();
    let temporary = scratch.path().join("private temporary");
    let cwd = scratch.path().join("unrelated working directory");
    fs::create_dir(&temporary).unwrap();
    fs::create_dir(&cwd).unwrap();
    let original = snapshot(&paths.root);
    let second_session = fs::read(paths.session(SECOND)).unwrap();

    for (choice, removed, remaining, answers) in [
        ("PRIMARY", FIRST, Some(SECOND), b"what\ny\n".as_slice()),
        ("SECOND@EXAMPLE.INVALID", SECOND, None, b"y\n".as_slice()),
    ] {
        let before = snapshot(&paths.root);
        let input = temporary.join("answer.txt");
        fs::write(&input, answers).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_mb"));
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
        command
            .env("MEGABASTERD_PROJECT_ROOT", &paths.root)
            .env("MEGABASTERD_USER_DIR", paths.user.parent().unwrap())
            .env("MEGABASTERD_LOG_DIR", &paths.logs)
            .env("HOOKMAKER_MAX_TEST_WORKERS", "1")
            .args(["--no-log-file", "account", "remove", choice]);
        let result = process::run_command(
            command,
            Duration::from_secs(10),
            16 * 1024,
            16 * 1024,
            &Control::new(),
            Some(File::open(input).unwrap()),
        )
        .unwrap();
        assert_eq!(result.status.code(), Some(0));
        assert!(result.stdout.is_empty());
        let diagnostic = String::from_utf8(result.stderr).unwrap();
        assert!(diagnostic.contains("Stored account and local session removed"));
        assert!(!diagnostic.contains("Cancelled"));
        assert_eq!(diagnostic.contains("Enter y or n"), remaining.is_some());
        for secret in [
            PASS,
            "synthetic password",
            "synthetic-first-sid",
            "synthetic-second-sid",
        ] {
            assert!(!diagnostic.contains(secret));
        }
        assert!(!paths.session(removed).exists());
        assert!(!paths.logs.exists());
        let after = snapshot(&paths.root);
        let mut expected = before;
        let relative = paths
            .accounts()
            .strip_prefix(&paths.root)
            .unwrap()
            .to_owned();
        expected.insert(relative, fs::read(paths.accounts()).unwrap());
        let relative = paths
            .session(removed)
            .strip_prefix(&paths.root)
            .unwrap()
            .to_owned();
        assert!(expected.remove(&relative).is_some());
        assert_eq!(
            after, expected,
            "removal changed unrelated files or their bytes"
        );
        let stored = accounts.list().unwrap();
        assert_eq!(stored.default_email.as_deref(), remaining);
        if let Some(email) = remaining {
            assert_eq!(stored.accounts.len(), 1);
            assert_eq!(stored.accounts[0].email, email);
            assert_eq!(stored.accounts[0].label.as_deref(), Some("secondary"));
            assert_eq!(
                &*Accounts::password(&stored.accounts[0], &vault).unwrap(),
                "synthetic password"
            );
            assert_eq!(fs::read(paths.session(email)).unwrap(), second_session);
        } else {
            assert!(stored.accounts.is_empty());
        }
    }
    assert_eq!(
        fs::read(paths.output.join("keep.bin")).unwrap(),
        b"previous download must survive"
    );
    assert_eq!(
        fs::read(paths.config()).unwrap(),
        original[Path::new("User/native-v2/Config/config.json")]
    );
}

#[path = "common/private_tempfile.rs"]
mod private_tempfile;
