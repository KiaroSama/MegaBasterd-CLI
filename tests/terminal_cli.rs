#![allow(clippy::unwrap_used)]

use megabasterd_cli::{platform::process, transfers::control::Control};
use std::{fs, path::Path, process::Command, time::Duration};

#[cfg(windows)]
#[path = "common/windows_log_acl.rs"]
mod windows_log_acl;

fn run(root: &Path, args: &[&str]) -> process::ProcessOutput {
    run_with_logging(root, args, false)
}

fn run_with_logging(root: &Path, args: &[&str], logging: bool) -> process::ProcessOutput {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mb"));
    command.current_dir(root).env_clear();
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
        command.env(key, root);
    }
    command
        .env("MEGABASTERD_PROJECT_ROOT", root)
        .env("MEGABASTERD_USER_DIR", root.join("user"))
        .env(
            "MEGABASTERD_LOG_DIR",
            root.join("logs-user@example.com-SENTINEL-PW-4471"),
        )
        .env("HOOKMAKER_MAX_TEST_WORKERS", "1")
        .env("NO_COLOR", "1")
        .arg(if logging {
            "--log-file"
        } else {
            "--no-log-file"
        })
        .args(args);
    process::run_command(
        command,
        Duration::from_secs(5),
        32 * 1024,
        16 * 1024,
        &Control::new(),
        None,
    )
    .unwrap()
}

#[test]
fn unsafe_native_log_directory_disables_only_file_logging_without_disclosing_the_refused_path() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/terminal-cli");
    fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    let root = scratch.path();
    let logs = root.join("logs-user@example.com-SENTINEL-PW-4471");
    drop(megabasterd_cli::platform::secure_files::PrivateDirectory::ensure(&logs).unwrap());
    let sentinel = logs.join("keep.txt");
    fs::write(&sentinel, b"preserve existing directory contents\n").unwrap();
    let config = root.join("user/native-v2/Config/config.json");
    megabasterd_cli::storage::files::Store::new(&config)
        .lock()
        .unwrap()
        .save(&serde_json::json!({}))
        .unwrap();
    let before_config = fs::read(&config).unwrap();
    #[cfg(unix)]
    struct RestorePermissions(std::path::PathBuf);
    #[cfg(unix)]
    impl Drop for RestorePermissions {
        fn drop(&mut self) {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
        }
    }
    #[cfg(unix)]
    let _restore = {
        use std::os::unix::fs::PermissionsExt;
        let restore = RestorePermissions(logs.clone());
        fs::set_permissions(&logs, fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            fs::metadata(&logs).unwrap().permissions().mode() & 0o7777,
            0o777
        );
        restore
    };
    #[cfg(windows)]
    let unsafe_acl = {
        windows_log_acl::snapshot(&logs).assert_owner_only();
        windows_log_acl::grant_local_service_read(&logs, false)
    };
    let control = run(root, &["config", "path"]);
    assert_eq!(control.status.code(), Some(0));
    assert_eq!(
        String::from_utf8(control.stdout.clone()).unwrap(),
        format!("{}\n", config.display())
    );
    assert!(control.stderr.is_empty());
    let result = run_with_logging(root, &["config", "path"], true);
    assert_eq!(result.status.code(), Some(0));
    assert_eq!(result.stdout, control.stdout);
    let stdout = String::from_utf8(result.stdout).unwrap();
    let stderr = String::from_utf8(result.stderr).unwrap();
    assert_eq!(
        stderr,
        "[WARNING] Private file logging could not be initialized; only console diagnostics are available.\n"
    );
    for artifact in [&stdout, &stderr] {
        for sensitive in ["SENTINEL-PW-4471", "user@example.com"] {
            assert!(!artifact.contains(sensitive));
        }
    }
    assert_eq!(fs::read(&config).unwrap(), before_config);
    assert_eq!(
        fs::read(&sentinel).unwrap(),
        b"preserve existing directory contents\n"
    );
    let entries: Vec<_> = fs::read_dir(&logs)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(entries, [std::ffi::OsString::from("keep.txt")]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&logs).unwrap().permissions().mode() & 0o7777,
            0o777
        );
    }
    #[cfg(windows)]
    assert_eq!(windows_log_acl::snapshot(&logs), unsafe_acl);
}

#[test]
fn failed_private_logging_initialization_warns_even_in_quiet_mode_without_changing_stdout() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/terminal-cli");
    fs::create_dir_all(&base).unwrap();
    for quiet in [false, true] {
        let scratch = tempfile::tempdir_in(&base).unwrap();
        let blocked = scratch
            .path()
            .join("logs-user@example.com-SENTINEL-PW-4471");
        fs::write(&blocked, b"preserve non-directory logging target").unwrap();
        let config = scratch.path().join("user/native-v2/Config/config.json");
        megabasterd_cli::storage::files::Store::new(&config)
            .lock()
            .unwrap()
            .save(&serde_json::json!({"extra1":1,"extra2":2,"extra3":3,"extra4":4,"extra5":5}))
            .unwrap();
        let before_config = fs::read(&config).unwrap();
        let arguments: &[&str] = if quiet {
            &["--quiet", "config", "path"]
        } else {
            &["config", "path"]
        };
        let control = run(scratch.path(), arguments);
        assert_eq!(control.status.code(), Some(0));
        let diagnostics = if quiet {
            String::new()
        } else {
            "[WARNING] Config contains an unknown setting; it was ignored\n".repeat(5)
        };
        assert_eq!(String::from_utf8(control.stderr).unwrap(), diagnostics);
        let result = run_with_logging(scratch.path(), arguments, true);
        assert_eq!(result.status.code(), Some(0));
        assert_eq!(result.stdout, control.stdout);
        let stderr = String::from_utf8(result.stderr).unwrap();
        assert_eq!(
            stderr,
            format!(
                "[WARNING] Private file logging could not be initialized; only console diagnostics are available.\n{diagnostics}"
            )
        );
        assert_eq!(stderr.matches("Private file logging").count(), 1);
        assert!(!stderr.contains("SENTINEL-PW-4471") && !stderr.contains("user@example.com"));
        assert_eq!(fs::read(&config).unwrap(), before_config);
        assert_eq!(
            fs::read(&blocked).unwrap(),
            b"preserve non-directory logging target"
        );
        assert_eq!(fs::read_dir(scratch.path()).unwrap().count(), 2);
    }
}

#[test]
fn initial_logging_refusal_keeps_argument_secrets_out_of_both_output_streams_and_artifacts() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/terminal-cli");
    fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    let blocked = scratch
        .path()
        .join("logs-user@example.com-SENTINEL-PW-4471");
    fs::write(&blocked, b"preserve non-directory logging target").unwrap();
    let config = scratch.path().join("user/native-v2/Config/config.json");
    megabasterd_cli::storage::files::Store::new(&config)
        .lock()
        .unwrap()
        .save(&serde_json::json!({}))
        .unwrap();
    let before_config = fs::read(&config).unwrap();
    let arguments = [
        "download",
        "https://mega.nz/file/ABCDEFGH#SENTINELKEY9911",
        "--password",
        "SENTINEL-PW-8842",
        "--parallel",
        "0",
        "--json",
    ];
    let control = run(scratch.path(), &arguments);
    assert_eq!(control.status.code(), Some(2));
    let diagnostic = "[ERROR] Invalid input: Parallel downloads must be between 1 and 32\n";
    assert_eq!(control.stderr, diagnostic.as_bytes());
    let result = run_with_logging(scratch.path(), &arguments, true);
    assert_eq!(result.status.code(), Some(2));
    assert_eq!(result.stdout, control.stdout);
    let stdout = String::from_utf8(result.stdout).unwrap();
    assert_eq!(stdout.lines().count(), 1);
    let record: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(record["event"], "result");
    assert_eq!(record["status"], "failed");
    assert_eq!(record["error_code"], "invalid_input");
    assert_eq!(
        record["error"],
        "Invalid input: Parallel downloads must be between 1 and 32"
    );
    let stderr = String::from_utf8(result.stderr).unwrap();
    assert_eq!(
        stderr,
        format!(
            "[WARNING] Private file logging could not be initialized; only console diagnostics are available.\n{diagnostic}"
        )
    );
    for secret in [
        "SENTINEL-PW-8842",
        "SENTINELKEY9911",
        "SENTINEL-PW-4471",
        "user@example.com",
    ] {
        assert!(!stdout.contains(secret) && !stderr.contains(secret));
    }
    assert_eq!(fs::read(&config).unwrap(), before_config);
    assert_eq!(
        fs::read(&blocked).unwrap(),
        b"preserve non-directory logging target"
    );
    assert_eq!(fs::read_dir(scratch.path()).unwrap().count(), 2);
}

#[test]
fn configured_invalid_proxy_probe_reports_literal_rows_without_leaking_query_credentials() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/terminal-cli");
    fs::create_dir_all(&base).unwrap();
    for (url, displayed) in [
        (
            "http://127.0.0.1:1/?token=SENTINEL_TOKEN",
            "http://127.0.0.1:1/?token=<redacted>",
        ),
        ("http://127.0.0.1[/bold]x:1", "http://127.0.0.1[/bold]x:1"),
    ] {
        let scratch = tempfile::tempdir_in(&base).unwrap();
        let root = scratch.path();
        let set = run(root, &["config", "set", "smart_proxy_url", url]);
        assert_eq!(set.status.code(), Some(0));
        assert!(set.stdout.is_empty());
        assert_eq!(
            String::from_utf8(set.stderr).unwrap(),
            "[INFO] Configuration setting saved.\n"
        );
        let config = root.join("user/native-v2/Config/config.json");
        let saved_config = fs::read(&config).unwrap();
        let document: serde_json::Value = serde_json::from_slice(&saved_config).unwrap();
        assert_eq!(document["data"]["smart_proxy_url"], url);
        let pool = root.join("user/native-v2/Data/proxies.json");
        assert!(!pool.exists());
        let result = run_with_logging(root, &["proxy", "test"], true);
        assert_eq!(result.status.code(), Some(1));
        let stdout = String::from_utf8(result.stdout).unwrap();
        let stderr = String::from_utf8(result.stderr).unwrap();
        assert_eq!(
            stdout,
            format!(
                "URL | Reachable | Latency / reason\n{displayed} | no | InvalidInput: endpoint has no supported host and port\n"
            )
        );
        assert_eq!(
            stderr,
            "[INFO] 0/1 reachable.\n[ERROR] Protocol error: No configured proxy endpoint is reachable\n"
        );
        let logs = root.join("logs-user@example.com-SENTINEL-PW-4471");
        let entries: Vec<_> = fs::read_dir(&logs)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].extension().unwrap(), "log");
        let text = fs::read_to_string(&entries[0]).unwrap();
        let run_id = entries[0].file_stem().unwrap().to_str().unwrap();
        let context = format!("run={run_id} cmd=proxy ");
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines.len(), 5);
        assert!(lines.iter().all(|line| line.contains(&context)));
        assert!(lines[0].contains("[INFO] [RUNTIME]") && lines[0].contains("Started"));
        assert!(lines[1].contains("[INFO] [CLI]") && lines[1].contains("Command started"));
        assert!(lines[2].contains("[INFO] [OUTPUT]") && lines[2].contains("0/1 reachable."));
        assert!(lines[3].contains("[ERROR] [OUTPUT]") && lines[3].contains("No configured proxy"));
        assert!(lines[4].contains("Finished") && lines[4].contains("\"exit_code\":1"));
        for artifact in [&stdout, &stderr, &text] {
            assert!(!artifact.contains("SENTINEL_TOKEN"));
            assert!(!artifact.contains('\x1b'));
            assert!(!artifact.contains("panicked") && !artifact.contains("Traceback"));
        }
        assert_eq!(fs::read(&config).unwrap(), saved_config);
        assert!(!pool.exists());
    }
}

#[test]
fn stored_configuration_markup_is_literal_through_the_actual_binary() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/terminal-cli");
    fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    for value in ["[bold red]PWNED[/bold red]", "agent[/bold]x"] {
        let set = run(scratch.path(), &["config", "set", "user_agent", value]);
        assert_eq!(set.status.code(), Some(0));
        let show = run(scratch.path(), &["config", "show"]);
        assert_eq!(show.status.code(), Some(0));
        let stdout = String::from_utf8(show.stdout).unwrap();
        let stderr = String::from_utf8(show.stderr).unwrap();
        assert!(stdout.contains(value));
        assert!(!stdout.contains('\x1b'));
        assert!(!stderr.contains("panicked") && !stderr.contains("Traceback"));
    }
}

#[test]
fn syntactically_invalid_proxy_markup_is_refused_without_bricking_a_valid_listing() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/terminal-cli");
    fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    for invalid in [
        "http://[bold red]PWNED[/bold red].example:8080",
        "http://evil[/bold].example:8080",
    ] {
        let add = run(scratch.path(), &["proxy", "add", invalid]);
        assert_eq!(
            add.status.code(),
            Some(2),
            "strict URL validation must not be weakened for a markup fixture"
        );
    }
    let add = run(
        scratch.path(),
        &["proxy", "add", "http://good.example:8080"],
    );
    assert_eq!(add.status.code(), Some(0));
    let list = run(scratch.path(), &["proxy", "list"]);
    assert_eq!(list.status.code(), Some(0));
    let text = String::from_utf8(list.stdout).unwrap();
    assert!(text.contains("good.example:8080"));
    assert!(!text.contains("PWNED") && !text.contains("evil[/bold]"));

    let proxy_path = scratch.path().join("user/native-v2/Data/proxies.json");
    let saved_proxies = fs::read(&proxy_path).unwrap();
    for configured in [
        "http://[bold]PWNED[/bold].example:8080",
        "http://evil[/bold].example:8080",
    ] {
        let set = run(
            scratch.path(),
            &["config", "set", "smart_proxy_url", configured],
        );
        assert_eq!(set.status.code(), Some(0));
        assert!(set.stdout.is_empty());
        assert_eq!(
            String::from_utf8(set.stderr).unwrap(),
            "[INFO] Configuration setting saved.\n"
        );
        let config_path = scratch.path().join("user/native-v2/Config/config.json");
        let saved_config = fs::read(&config_path).unwrap();
        let persisted = concat!(
            "URL | Successes | Failures | Status | Source\n",
            "http://good.example:8080 | 0 | 0 | OK | persisted\n",
        );
        for (arguments, expected) in [
            (
                &["proxy", "list"][..],
                format!("{persisted}{configured} | 0 | 0 | OK | config\n"),
            ),
            (
                &["proxy", "list", "--no-config-urls"][..],
                persisted.to_owned(),
            ),
        ] {
            let list = run(scratch.path(), arguments);
            assert_eq!(list.status.code(), Some(0));
            let rendered = String::from_utf8(list.stdout).unwrap();
            assert_eq!(rendered, expected);
            assert!(list.stderr.is_empty());
            assert!(!rendered.contains('\x1b'));
            assert_eq!(fs::read(&proxy_path).unwrap(), saved_proxies);
            assert_eq!(fs::read(&config_path).unwrap(), saved_config);
        }
    }
}
