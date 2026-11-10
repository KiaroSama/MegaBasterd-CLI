// SPDX-License-Identifier: GPL-3.0-or-later
#![allow(clippy::unwrap_used)]

use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs::{self, File},
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use megabasterd_cli::{
    platform::process,
    protocol::auth::Session,
    storage::{
        accounts::Accounts,
        config_store::ConfigStore,
        files::Store,
        paths::Paths,
        proxies::ProxyStore,
        queue::{JobStatus, JobType, Queue, QueuePayload},
        sessions::Sessions,
        vault::Vault,
    },
    transfers::control::Control,
};

const EMAIL: &str = "prompt-fixture@example.invalid";

struct Fixture {
    _scratch: tempfile::TempDir,
    paths: Paths,
    cwd: PathBuf,
    temporary: PathBuf,
    source: PathBuf,
    destination: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/prompt-cli");
        fs::create_dir_all(&base).unwrap();
        let scratch = tempfile::tempdir_in(base).unwrap();
        let root = scratch.path().join("runtime with spaces");
        let paths = Paths {
            user: root.join("private user/native-v2"),
            logs: root.join("private logs"),
            output: root.join("output"),
            root,
        };
        let config = ConfigStore::new(paths.config());
        config.set("max_workers", "3").unwrap();
        config.set("log_level", "INFO").unwrap();
        let vault = Vault::new("synthetic-fixture-passphrase");
        Accounts::new(paths.accounts())
            .add(EMAIL, "synthetic-account-password", None, true, &vault)
            .unwrap();
        Sessions::new(paths.session(EMAIL))
            .remember(
                &Session {
                    email: EMAIL.into(),
                    sid: "synthetic-fixture-session".into(),
                    master_key: [0x42; 16],
                    rsa_private_key: None,
                    user_handle: "SYNTHETIC01".into(),
                },
                &vault,
            )
            .unwrap();
        ProxyStore::new(paths.proxies())
            .update(|urls| urls.push("http://127.0.0.1:3128/".into()))
            .unwrap();
        let queue = Queue::new(paths.queue());
        let payload = QueuePayload {
            source: "synthetic-queued-source".into(),
            destination: "output with  two spaces".into(),
            password: Some("synthetic-link-password".into()),
            account: None,
            error: None,
        };
        queue.add(JobType::Download, &payload).unwrap();
        let claim = queue.claim_next("fixture-setup").unwrap().unwrap();
        queue.finish(&claim.item, JobStatus::Done, None).unwrap();
        drop(claim);
        queue.add(JobType::Download, &payload).unwrap();
        fs::create_dir_all(&paths.output).unwrap();
        let source = paths.output.join("input with  two spaces.bin");
        let destination = paths.output.join("existing output.bin");
        fs::write(&source, b"unprocessed fixture input").unwrap();
        fs::write(&destination, b"original destination must survive").unwrap();
        let cwd = scratch.path().join("unrelated working directory");
        let temporary = scratch.path().join("private temporary");
        fs::create_dir(&cwd).unwrap();
        fs::create_dir(&temporary).unwrap();
        Self {
            _scratch: scratch,
            paths,
            cwd,
            temporary,
            source,
            destination,
        }
    }

    fn run(&self, args: &[OsString], input: &[u8]) -> process::ProcessOutput {
        self.run_with_stdin(args, Some(input))
    }

    fn run_with_stdin(&self, args: &[OsString], input: Option<&[u8]>) -> process::ProcessOutput {
        let input = input.map(|bytes| {
            let path = self.temporary.join("answer.txt");
            fs::write(&path, bytes).unwrap();
            File::open(path).unwrap()
        });
        let mut command = Command::new(env!("CARGO_BIN_EXE_mb"));
        command.current_dir(&self.cwd).env_clear();
        // Preserve only native loader/Windows prerequisites, never operator app/auth settings.
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
            command.env(key, &self.temporary);
        }
        command
            .env("MEGABASTERD_PROJECT_ROOT", &self.paths.root)
            .env("MEGABASTERD_USER_DIR", self.paths.user.parent().unwrap())
            .env("MEGABASTERD_LOG_DIR", &self.paths.logs)
            .env("HOOKMAKER_MAX_TEST_WORKERS", "1")
            .args([OsStr::new("--no-log-file")])
            .args(args);
        process::run_command(
            command,
            Duration::from_secs(10),
            64 * 1024,
            64 * 1024,
            &Control::new(),
            input,
        )
        .unwrap()
    }
}

fn arguments(words: &[&str]) -> Vec<OsString> {
    words.iter().map(OsString::from).collect()
}

fn snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn collect(root: &Path, directory: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            let metadata = fs::symlink_metadata(&path).unwrap();
            assert!(!metadata.file_type().is_symlink());
            if metadata.is_dir() {
                collect(root, &path, files);
            } else {
                assert!(metadata.is_file());
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
fn actual_binary_destructive_declines_and_closed_input_explain_skip_without_mutation() {
    let fixture = Fixture::new();
    let before = snapshot(&fixture.paths.root);
    let mut cases = vec![
        (arguments(&["account", "remove", EMAIL]), 0),
        (arguments(&["proxy", "clear"]), 0),
        (arguments(&["queue", "clear"]), 0),
        (arguments(&["queue", "reset"]), 0),
        (arguments(&["config", "reset"]), 0),
        (arguments(&["config", "recover", "--reset"]), 0),
        (arguments(&["rm", "not-a-real-node"]), 0),
        (arguments(&["trash", "empty"]), 0),
    ];
    for prefix in [
        vec!["thumbnail"],
        vec!["crypter", "encrypt"],
        vec!["crypter", "decrypt"],
    ] {
        let mut args = arguments(&prefix);
        args.extend([
            fixture.source.as_os_str().to_owned(),
            fixture.destination.as_os_str().to_owned(),
        ]);
        if prefix[0] == "crypter" {
            args.extend(arguments(&["--password", "synthetic-local-password"]));
        }
        cases.push((args, 130));
    }
    for (args, code) in cases {
        let mut inputs = vec![b"n\n".as_slice(), b"".as_slice()];
        if args == arguments(&["queue", "reset"]) {
            inputs.push(b"\n".as_slice());
        }
        for input in inputs {
            let output = fixture.run(&args, input);
            assert_eq!(output.status.code(), Some(code));
            assert!(output.stdout.is_empty());
            let diagnostic = String::from_utf8(output.stderr).unwrap();
            assert!(diagnostic.contains("Cancelled; nothing was changed."));
            for unwanted in ["Authentication failed", "2FA", "Unexpected", "Traceback"] {
                assert!(!diagnostic.contains(unwanted));
            }
            assert_eq!(snapshot(&fixture.paths.root), before);
        }
    }
    assert!(!fixture.paths.logs.exists());
    assert_eq!(
        Accounts::new(fixture.paths.accounts())
            .list()
            .unwrap()
            .accounts
            .len(),
        1
    );
    assert_eq!(Queue::new(fixture.paths.queue()).list().unwrap().len(), 2);
}

#[test]
fn actual_binary_retries_unknown_confirmation_and_acceptance_mutates_only_selected_config() {
    let fixture = Fixture::new();
    let before = snapshot(&fixture.paths.root);
    let output = fixture.run(&arguments(&["config", "reset"]), "غ\nn\n".as_bytes());
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
    let diagnostic = String::from_utf8(output.stderr).unwrap();
    assert!(diagnostic.contains("y or n") && diagnostic.contains("Cancelled"));
    assert_eq!(snapshot(&fixture.paths.root), before);

    let output = fixture.run(&arguments(&["config", "reset"]), b"y\n");
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
    let diagnostic = String::from_utf8(output.stderr).unwrap();
    assert!(!diagnostic.contains("Cancelled"));
    assert!(diagnostic.contains("Configuration reset to defaults."));
    assert_eq!(
        ConfigStore::new(fixture.paths.config())
            .load()
            .unwrap()
            .0
            .max_workers,
        8
    );
    let mut after = snapshot(&fixture.paths.root);
    let mut expected = before;
    let config = fixture
        .paths
        .config()
        .strip_prefix(&fixture.paths.root)
        .unwrap()
        .to_owned();
    assert_ne!(after.remove(&config), expected.remove(&config));
    assert_eq!(after, expected);
}

#[test]
fn actual_binary_corrupt_config_blocks_commands_but_preserves_inspection_and_explicit_recovery() {
    let fixture = Fixture::new();
    ConfigStore::new(fixture.paths.config())
        .set("max_workers", "4")
        .unwrap();
    let valid = fixture.run(&arguments(&["config", "get", "max_workers"]), b"");
    assert_eq!(valid.status.code(), Some(0));
    assert!(String::from_utf8(valid.stdout).unwrap().contains('4'));
    let malformed = b"{\"connect_proxy_password\":\"sentinel-not-a-real-secret\",,, BROKEN";
    Store::new(fixture.paths.config())
        .lock()
        .unwrap()
        .write_bytes(malformed)
        .unwrap();
    assert!(matches!(
        ConfigStore::new(fixture.paths.config()).load(),
        Err(megabasterd_cli::error::Error::Corrupt(_))
    ));
    let before = snapshot(&fixture.paths.root);
    // No valid link or credentials are needed: policy refusal precedes those checks.
    for args in [
        arguments(&["ls"]),
        arguments(&["rm", "not-a-real-node"]),
        arguments(&["account", "remove", EMAIL]),
        arguments(&["proxy", "clear"]),
        arguments(&["queue", "clear"]),
        arguments(&["queue", "reset"]),
        arguments(&[
            "queue",
            "add-download",
            "https://mega.nz/file/ABCD1234#KEYMATERIAL",
        ]),
        vec![
            "split".into(),
            fixture.source.clone().into_os_string(),
            "1".into(),
        ],
    ] {
        let output = fixture.run(&args, b"y\n");
        assert_eq!(output.status.code(), Some(1), "{args:?}");
        assert!(output.stdout.is_empty());
        let diagnostic = String::from_utf8(output.stderr).unwrap();
        assert!(diagnostic.to_lowercase().contains("config"));
        assert!(!diagnostic.contains("sentinel-not-a-real-secret"));
        assert!(!diagnostic.contains("Traceback"));
        assert!(!diagnostic.contains("Cancelled"));
        assert_eq!(snapshot(&fixture.paths.root), before);
    }
    for (args, expected) in [
        (arguments(&["config", "path"]), 0),
        (arguments(&["config", "show"]), 0),
        (arguments(&["config", "get", "max_workers"]), 0),
        (arguments(&["config", "recover"]), 1),
    ] {
        let output = fixture.run(&args, b"");
        assert_eq!(output.status.code(), Some(expected));
        for stream in [&output.stdout, &output.stderr] {
            let text = std::str::from_utf8(stream).unwrap();
            assert!(!text.contains("sentinel-not-a-real-secret"));
            assert!(!text.contains("Traceback"));
        }
        assert_eq!(snapshot(&fixture.paths.root), before);
    }
    let output = fixture.run(&arguments(&["config", "recover", "--reset"]), b"y\n");
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        ConfigStore::new(fixture.paths.config())
            .load()
            .unwrap()
            .0
            .max_workers,
        8
    );
    let mut after = snapshot(&fixture.paths.root);
    let mut expected = before;
    let config = fixture
        .paths
        .config()
        .strip_prefix(&fixture.paths.root)
        .unwrap()
        .to_owned();
    assert_ne!(after.remove(&config), expected.remove(&config));
    let backups: Vec<_> = after
        .keys()
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("config.json.corrupt-")
        })
        .cloned()
        .collect();
    assert_eq!(backups.len(), 1);
    assert_eq!(after.remove(&backups[0]).unwrap(), malformed);
    assert_eq!(expected.remove(&backups[0]).unwrap(), malformed);
    assert_eq!(after, expected);
    let output = fixture.run(&arguments(&["config", "get", "max_workers"]), b"");
    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8(output.stdout).unwrap().contains('8'));
}

#[test]
fn actual_binary_config_get_and_path_keep_plain_stdout_and_redact_secrets() {
    let fixture = Fixture::new();
    for (key, value, expected) in [
        ("max_workers", "10", "10\n"),
        ("default_account", "null-value", "null-value\n"),
        ("default_account", "NONE", "None\n"),
        ("verify_integrity", "no", "False\n"),
        ("verify_integrity", "yes", "True\n"),
        ("connect_proxy_password", "hunter2", "<redacted>\n"),
    ] {
        let changed = fixture.run(&arguments(&["config", "set", key, value]), b"");
        assert_eq!(changed.status.code(), Some(0));
        assert!(changed.stdout.is_empty());
        assert!(
            !std::str::from_utf8(&changed.stderr)
                .unwrap()
                .contains("hunter2")
        );
        let output = fixture.run(&arguments(&["config", "get", key]), b"");
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(
            std::str::from_utf8(&output.stdout)
                .unwrap()
                .replace("\r\n", "\n"),
            expected
        );
        assert!(output.stderr.is_empty());
    }
    let output = fixture.run(&arguments(&["config", "path"]), b"");
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        std::str::from_utf8(&output.stdout)
            .unwrap()
            .trim_end_matches(['\r', '\n']),
        fixture.paths.config().to_str().unwrap()
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn actual_binary_split_and_merge_replace_only_after_confirmation_and_keep_inputs() {
    let fixture = Fixture::new();
    let bytes: Vec<_> = (0..1024 * 1024 + 17).map(|i| (i % 251) as u8).collect();
    fs::write(&fixture.source, &bytes).unwrap();
    let parts = fixture.paths.output.join("parts with spaces");
    let split = vec![
        "split".into(),
        fixture.source.clone().into_os_string(),
        "1".into(),
        "-o".into(),
        parts.clone().into_os_string(),
    ];
    assert_eq!(fixture.run(&split, b"").status.code(), Some(0));
    let name = fixture.source.file_name().unwrap().to_string_lossy();
    let first = parts.join(format!("{name}.part1-2"));
    let second = parts.join(format!("{name}.part2-2"));
    let checksum = parts.join(format!("{name}.sha1"));
    assert_eq!(fs::read(&first).unwrap(), bytes[..1024 * 1024]);
    assert_eq!(fs::read(&second).unwrap(), bytes[1024 * 1024..]);
    fs::write(&second, b"old incomplete part").unwrap();
    let before = snapshot(&fixture.paths.root);
    for input in [b"n\n".as_slice(), b"".as_slice(), b"\n".as_slice()] {
        let output = fixture.run(&split, input);
        assert_eq!(output.status.code(), Some(130));
        assert!(output.stdout.is_empty());
        assert!(
            std::str::from_utf8(&output.stderr)
                .unwrap()
                .contains("Cancelled")
        );
        assert_eq!(snapshot(&fixture.paths.root), before);
    }
    let accepted = fixture.run(&split, b"y\n");
    assert_eq!(accepted.status.code(), Some(0));
    assert!(accepted.stdout.is_empty());
    assert_eq!(fs::read(&first).unwrap(), bytes[..1024 * 1024]);
    assert_eq!(fs::read(&second).unwrap(), bytes[1024 * 1024..]);
    let checksum_bytes = fs::read(&checksum).unwrap();
    let merge = vec![
        "merge".into(),
        second.clone().into_os_string(),
        "-o".into(),
        fixture.destination.clone().into_os_string(),
    ];
    let before = snapshot(&fixture.paths.root);
    for input in [b"n\n".as_slice(), b"".as_slice(), b"\n".as_slice()] {
        let output = fixture.run(&merge, input);
        assert_eq!(output.status.code(), Some(130));
        assert!(output.stdout.is_empty());
        assert!(
            std::str::from_utf8(&output.stderr)
                .unwrap()
                .contains("Cancelled")
        );
        assert_eq!(snapshot(&fixture.paths.root), before);
    }
    let accepted = fixture.run(&merge, b"y\n");
    assert_eq!(accepted.status.code(), Some(0));
    assert!(accepted.stdout.is_empty());
    assert_eq!(fs::read(&fixture.destination).unwrap(), bytes);
    assert_eq!(fs::read(&fixture.source).unwrap(), bytes);
    assert_eq!(fs::read(&checksum).unwrap(), checksum_bytes);
    assert!(first.exists() && second.exists());
    for directory in [&parts, &fixture.paths.output] {
        assert!(fs::read_dir(directory).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")
        }));
    }
    let mut after = snapshot(&fixture.paths.root);
    let mut expected = before;
    let destination = fixture
        .destination
        .strip_prefix(&fixture.paths.root)
        .unwrap();
    assert_ne!(after.remove(destination), expected.remove(destination));
    // A new persistent destination claim is expected; all other user-store bytes stay unchanged.
    let mut claim = destination.as_os_str().to_os_string();
    claim.push(".mbclaim");
    after.remove(Path::new(&claim));
    expected.remove(Path::new(&claim));
    assert_eq!(after, expected);
}

#[test]
fn actual_binary_headless_account_secrets_name_the_required_flags_without_touching_saved_data() {
    let fixture = Fixture::new();
    let before = snapshot(&fixture.paths.root);
    let cases = [
        (arguments(&["account", "info"]), "--vault-passphrase", false),
        (
            arguments(&["account", "refresh-all"]),
            "--vault-passphrase",
            false,
        ),
        (
            arguments(&["account", "add", "new@example.invalid", "--no-verify"]),
            "--password",
            false,
        ),
        (
            vec![
                "upload".into(),
                fixture.source.clone().into_os_string(),
                "--json".into(),
            ],
            "--vault-passphrase",
            true,
        ),
    ];
    for (args, flag, json) in cases {
        // None is a genuine null handle; Some(empty) is a redirected regular file at EOF.
        for input in [None, Some(b"".as_slice())] {
            let output = fixture.run_with_stdin(&args, input);
            assert_eq!(output.status.code(), Some(1));
            let diagnostic = String::from_utf8(output.stderr).unwrap();
            assert!(diagnostic.contains(flag), "{diagnostic}");
            for forbidden in [
                "Traceback",
                "panicked",
                "synthetic-fixture-passphrase",
                "synthetic-account-password",
            ] {
                assert!(!diagnostic.contains(forbidden));
            }
            if json {
                let record: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(record["error_code"], "auth_failed");
                assert!(record["error"].as_str().unwrap().contains(flag));
            } else {
                assert!(output.stdout.is_empty());
            }
            assert_eq!(snapshot(&fixture.paths.root), before);
        }
    }
    assert!(!fixture.paths.logs.exists());
}

#[test]
fn actual_binary_account_add_allows_fresh_storage_but_refuses_a_different_vault_passphrase() {
    let fixture = Fixture::new();
    let accounts = Accounts::new(fixture.paths.accounts());
    accounts.remove(EMAIL).unwrap();
    let empty = snapshot(&fixture.paths.root);
    for command in ["info", "refresh-all"] {
        let output = fixture.run_with_stdin(&arguments(&["account", command]), None);
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        let message = String::from_utf8(output.stderr).unwrap();
        assert!(message.contains("No accounts found"));
        assert!(!message.contains("Vault passphrase:") && !message.contains("Traceback"));
        assert_eq!(snapshot(&fixture.paths.root), empty);
    }
    for email in ["first@example.invalid", "second@example.invalid"] {
        let output = fixture.run_with_stdin(
            &arguments(&[
                "account",
                "add",
                email,
                "--password",
                "synthetic-new-password",
                "--no-verify",
                "--vault-passphrase",
                "synthetic-fixture-passphrase",
            ]),
            None,
        );
        assert_eq!(output.status.code(), Some(0));
        assert!(output.stdout.is_empty());
        let message = String::from_utf8(output.stderr).unwrap();
        assert!(message.contains("Account saved"));
        assert!(!message.contains("synthetic-new-password"));
        let account = accounts.find(Some(email)).unwrap();
        assert_eq!(
            &*Accounts::password(&account, &Vault::new("synthetic-fixture-passphrase")).unwrap(),
            "synthetic-new-password"
        );
    }
    // Session inspection intentionally creates its persistent sidecar, even when no cache exists.
    assert!(
        !Sessions::new(fixture.paths.session("first@example.invalid"))
            .has_cached()
            .unwrap()
    );
    let before = snapshot(&fixture.paths.root);
    for args in [
        arguments(&[
            "account",
            "add",
            "third@example.invalid",
            "--password",
            "replacement",
            "--no-verify",
            "--vault-passphrase",
            "synthetic-wrong-passphrase",
        ]),
        arguments(&[
            "account",
            "info",
            "--vault-passphrase",
            "synthetic-wrong-passphrase",
        ]),
    ] {
        let output = fixture.run_with_stdin(&args, None);
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        let message = String::from_utf8(output.stderr).unwrap();
        assert!(message.to_lowercase().contains("passphrase"));
        for secret in [
            "synthetic-wrong-passphrase",
            "replacement",
            "Traceback",
            "panicked",
        ] {
            assert!(!message.contains(secret));
        }
        assert_eq!(snapshot(&fixture.paths.root), before);
    }
    assert_eq!(accounts.list().unwrap().accounts.len(), 2);
}

#[test]
fn actual_binary_declined_recovery_preserves_corrupt_configuration_and_its_detection_copy() {
    let fixture = Fixture::new();
    Store::new(fixture.paths.config())
        .lock()
        .unwrap()
        .write_bytes(b"not valid JSON")
        .unwrap();
    assert!(ConfigStore::new(fixture.paths.config()).load().is_err());
    let before = snapshot(&fixture.paths.root);
    let copies: Vec<_> = before
        .iter()
        .filter(|(path, _)| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("config.json.corrupt-")
        })
        .collect();
    assert_eq!(copies.len(), 1);
    assert_eq!(copies[0].1, b"not valid JSON");
    let output = fixture.run(&arguments(&["config", "recover", "--reset"]), b"n\n");
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("Cancelled; nothing was changed.")
    );
    assert_eq!(snapshot(&fixture.paths.root), before);
}
