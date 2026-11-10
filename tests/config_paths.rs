//! Effective native defaults and overrides stay anchored outside the caller's working directory.
#![allow(clippy::unwrap_used)]

use std::{fs, path::Path, process::Command, time::Duration};

use megabasterd_cli::{
    cli::context::Context,
    platform::process::{self, ProcessOutput},
    storage::{config_store::ConfigStore, files::Store, paths::Paths},
    transfers::control::Control,
};
use serde_json::json;

const CHILD: &str = "MB_CONFIG_PATH_CHILD";
const TEST: &str =
    "effective_default_paths_and_user_overrides_reach_the_actual_configuration_commands";

fn command(
    executable: &Path,
    cwd: &Path,
    temporary: &Path,
    root: &Path,
    user: Option<&Path>,
) -> Command {
    let mut command = Command::new(executable);
    command.current_dir(cwd).env_clear();
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
        command.env(key, temporary);
    }
    command
        .env("MEGABASTERD_PROJECT_ROOT", root)
        .env("HOOKMAKER_MAX_TEST_WORKERS", "1");
    if let Some(user) = user {
        command.env("MEGABASTERD_USER_DIR", user);
    }
    command
}

fn run(command: Command) -> ProcessOutput {
    let result = process::run_command(
        command,
        Duration::from_secs(5),
        32 * 1024,
        16 * 1024,
        &Control::new(),
        None,
    )
    .unwrap();
    assert_eq!(
        result.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    result
}

#[test]
fn effective_default_paths_and_user_overrides_reach_the_actual_configuration_commands() {
    if std::env::var_os(CHILD).as_deref() == Some(std::ffi::OsStr::new("1")) {
        let paths = Paths::discover().unwrap();
        let expected_root = std::path::PathBuf::from(std::env::var_os("MB_EXPECTED_ROOT").unwrap());
        let expected_user = std::path::PathBuf::from(std::env::var_os("MB_EXPECTED_USER").unwrap());
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/config-paths");
        assert!(
            expected_root
                .canonicalize()
                .unwrap()
                .starts_with(base.canonicalize().unwrap())
        );
        assert_eq!(paths.root, expected_root);
        assert_eq!(paths.user, expected_user);
        assert_eq!(paths.output, expected_root.join("Output"));
        assert_eq!(paths.logs, expected_user.join("Logs"));
        assert_eq!(paths.config(), expected_user.join("Config/config.json"));
        assert_eq!(paths.accounts(), expected_user.join("Data/accounts.json"));
        assert_eq!(paths.queue(), expected_user.join("Data/queue.json"));
        let (settings, warnings) = ConfigStore::new(paths.config()).load().unwrap();
        assert!(settings.download_path.is_empty() && warnings.is_empty());
        assert_eq!(
            settings.max_workers, 8,
            "Prior-layout settings must not be loaded"
        );
        assert_eq!(
            paths.download(&settings.download_path),
            expected_root.join("Output")
        );
        let context = Context::start(false, false, Some(false)).unwrap();
        context.require_config().unwrap();
        assert_eq!(
            context.paths.download(&context.config.download_path),
            expected_root.join("Output")
        );
        drop(context);
        assert!(!paths.config().exists() && !paths.output.exists() && !paths.logs.exists());
        return;
    }

    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/config-paths");
    fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    let cwd = scratch.path().join("unrelated working directory");
    let temporary = scratch.path().join("private temporary");
    fs::create_dir(&cwd).unwrap();
    fs::create_dir(&temporary).unwrap();
    for mode in ["default", "absolute", "relative"] {
        let expected_root = if mode == "relative" {
            cwd.join("relative runtime")
        } else {
            scratch.path().join(format!("{mode} runtime"))
        };
        fs::create_dir(&expected_root).unwrap();
        let root = if mode == "relative" {
            Path::new("relative runtime")
        } else {
            &expected_root
        };
        let absolute_user = scratch.path().join("custom user");
        let user = match mode {
            "absolute" => Some(absolute_user.as_path()),
            "relative" => Some(Path::new("relative user")),
            _ => None,
        };
        let expected_user = match mode {
            "absolute" => absolute_user.join("native-v2"),
            "relative" => cwd.join("relative user/native-v2"),
            _ => expected_root.join("User/native-v2"),
        };
        let previous_base = expected_user.parent().unwrap();
        let previous_files: Vec<_> = [
            (
                "Config/config.json",
                r#"{"max_workers":63,"download_path":"previous downloads"}"#,
            ),
            (
                "Data/accounts.json",
                r#"{"accounts":["synthetic previous account"]}"#,
            ),
            ("Data/queue.json", r#"{"jobs":["synthetic previous job"]}"#),
            (
                "Data/sessions/previous.json",
                r#"{"session":"synthetic previous session"}"#,
            ),
            (
                "Logs/previous.log",
                "Previous operational log must remain unchanged\n",
            ),
        ]
        .into_iter()
        .map(|(relative, text)| {
            let path = previous_base.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, text.as_bytes()).unwrap();
            (path, text.as_bytes())
        })
        .collect();
        let mut child = command(
            &std::env::current_exe().unwrap(),
            &cwd,
            &temporary,
            root,
            user,
        );
        child
            .env(CHILD, "1")
            .env("MB_EXPECTED_ROOT", &expected_root)
            .env("MB_EXPECTED_USER", &expected_user)
            .args(["--exact", TEST, "--test-threads=1"]);
        let child = run(child);
        let child_text = String::from_utf8(child.stdout).unwrap();
        assert!(
            child_text.contains("1 passed")
                && child_text.contains("0 failed")
                && child_text.contains("0 ignored")
        );
        assert!(child.stderr.is_empty());
        let binary = |args: &[&str]| {
            let mut child = command(
                Path::new(env!("CARGO_BIN_EXE_mb")),
                &cwd,
                &temporary,
                root,
                user,
            );
            child.arg("--no-log-file").args(args);
            run(child)
        };
        let path = binary(&["config", "path"]);
        assert_eq!(
            String::from_utf8(path.stdout)
                .unwrap()
                .trim_end_matches(['\r', '\n']),
            expected_user.join("Config/config.json").to_str().unwrap()
        );
        assert!(path.stderr.is_empty());
        if mode == "default" {
            let output = expected_root.join("Output");
            let get = binary(&["config", "get", "download_path"]);
            assert_eq!(
                String::from_utf8(get.stdout)
                    .unwrap()
                    .trim_end_matches(['\r', '\n']),
                output.to_str().unwrap()
            );
            assert!(get.stderr.is_empty());
            let show = binary(&["config", "show"]);
            let text = String::from_utf8(show.stdout).unwrap();
            let expected = format!(
                "download_path | {}",
                serde_json::to_string(output.to_str().unwrap()).unwrap()
            );
            assert!(text.lines().any(|line| line == expected));
            assert!(show.stderr.is_empty());
            let config = expected_user.join("Config/config.json");
            let malformed = b"{malformed-private-sentinel";
            Store::new(&config)
                .lock()
                .unwrap()
                .write_bytes(malformed)
                .unwrap();
            let corrupt = binary(&["config", "get", "download_path"]);
            assert_eq!(
                String::from_utf8(corrupt.stdout)
                    .unwrap()
                    .trim_end_matches(['\r', '\n']),
                output.to_str().unwrap()
            );
            let warning = String::from_utf8(corrupt.stderr).unwrap();
            assert!(warning.contains("[WARNING]") && !warning.contains("private-sentinel"));
            assert_eq!(fs::read(&config).unwrap(), malformed);
            Store::new(&config)
                .lock()
                .unwrap()
                .save(&json!({"download_path":"relative downloads"}))
                .unwrap();
            let before = fs::read(&config).unwrap();
            let custom = binary(&["config", "get", "download_path"]);
            assert_eq!(
                String::from_utf8(custom.stdout)
                    .unwrap()
                    .trim_end_matches(['\r', '\n']),
                "relative downloads"
            );
            assert!(custom.stderr.is_empty());
            assert_eq!(fs::read(&config).unwrap(), before);
        }
        assert!(!expected_root.join("Output").exists());
        assert!(!expected_user.join("Logs").exists());
        for (path, bytes) in previous_files {
            assert_eq!(fs::read(path).unwrap(), bytes);
        }
    }
}
