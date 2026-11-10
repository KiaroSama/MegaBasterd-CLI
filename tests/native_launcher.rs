#![cfg(windows)]
#![allow(clippy::unwrap_used)]

use megabasterd_cli::{platform::process, transfers::control::Control};
use std::{fs, path::Path, process::Command, time::Duration};

fn run(script: &Path, cwd: &Path, temporary: &Path, arguments: &[&str]) -> process::ProcessOutput {
    let root = script.parent().unwrap();
    let mut command = Command::new("pwsh");
    command.current_dir(cwd).env_clear();
    for key in ["PATH", "SystemRoot", "WINDIR", "PATHEXT"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    for key in [
        "HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "TEMP",
        "TMP",
        "TMPDIR",
    ] {
        command.env(key, temporary);
    }
    command
        .env("MEGABASTERD_USER_DIR", root.join("User"))
        .env("MEGABASTERD_LOG_DIR", root.join("private logs"))
        .env("NO_COLOR", "1")
        .env("HOOKMAKER_MAX_TEST_WORKERS", "1")
        .args(["-NoProfile", "-NonInteractive", "-File"])
        .arg(script)
        .args(arguments);
    process::run_command(
        command,
        Duration::from_secs(8),
        16 * 1024,
        16 * 1024,
        &Control::new(),
        None,
    )
    .unwrap()
}

#[test]
fn candidate_launcher_forwards_arguments_from_an_unrelated_cwd_and_preserves_native_exit_codes() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/native-launcher");
    fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    let root = scratch.path().join("release with spaces");
    let cwd = scratch.path().join("unrelated working directory");
    let temporary = scratch.path().join("temporary");
    for directory in [&root, &cwd, &temporary] {
        fs::create_dir(directory).unwrap();
    }
    let script = root.join("Run.ps1");
    let launcher = include_bytes!("../tools/launcher/Run.Native.ps1");
    fs::write(&script, launcher).unwrap();
    fs::copy(env!("CARGO_BIN_EXE_mb"), root.join("mb.exe")).unwrap();
    let parent = root.join("native error preference.ps1");
    fs::write(
        &parent,
        concat!(
            "param([string] $Launcher, [Parameter(ValueFromRemainingArguments = $true)][string[]] $CliArgs)\n",
            "$PSNativeCommandUseErrorActionPreference = $true\n",
            "& $Launcher @CliArgs\n",
            "$Code = $LASTEXITCODE\n",
            "if (-not $PSNativeCommandUseErrorActionPreference) { exit 99 }\n",
            "exit $Code\n",
        ),
    )
    .unwrap();
    for (entry, arguments, expected, stdout, stderr) in [
        (
            &script,
            vec!["--no-log-file", "config", "get", "max_workers"],
            0,
            "8\n",
            "",
        ),
        (
            &script,
            vec!["--no-log-file", "config", "get", "unknown-fixture-key"],
            2,
            "",
            "[ERROR] Invalid input: Unknown configuration setting\n",
        ),
        (
            &parent,
            vec![
                script.to_str().unwrap(),
                "--no-log-file",
                "config",
                "get",
                "unknown-fixture-key",
            ],
            2,
            "",
            "[ERROR] Invalid input: Unknown configuration setting\n",
        ),
        (
            &parent,
            vec![
                script.to_str().unwrap(),
                "--no-log-file",
                "config",
                "set",
                "max_workers",
                "3",
            ],
            0,
            "",
            "[INFO] Configuration setting saved.\n",
        ),
    ] {
        let result = run(entry, &cwd, &temporary, &arguments);
        assert_eq!(result.status.code(), Some(expected));
        assert_eq!(
            String::from_utf8(result.stdout)
                .unwrap()
                .replace("\r\n", "\n"),
            stdout
        );
        assert_eq!(
            String::from_utf8(result.stderr)
                .unwrap()
                .replace("\r\n", "\n"),
            stderr
        );
    }
    let first_part = root.join("missing peer.bin.part1-2");
    let absent_part = root.join("missing peer.bin.part2-2");
    let destination = root.join("must not be published.bin");
    fs::write(&first_part, b"original first part").unwrap();
    let result = run(
        &parent,
        &cwd,
        &temporary,
        &[
            script.to_str().unwrap(),
            "--no-log-file",
            "merge",
            first_part.to_str().unwrap(),
            "-o",
            destination.to_str().unwrap(),
        ],
    );
    assert_eq!(result.status.code(), Some(1));
    assert!(result.stdout.is_empty());
    let stderr = String::from_utf8(result.stderr).unwrap();
    assert!(stderr.starts_with("[ERROR] I/O operation failed: "));
    for forbidden in [
        "Native CLI could not be started",
        "NativeCommandExitException",
    ] {
        assert!(!stderr.contains(forbidden));
    }
    assert_eq!(fs::read(&first_part).unwrap(), b"original first part");
    assert!(!absent_part.exists() && !destination.exists());
    let config = root.join("User/native-v2/Config/config.json");
    let saved = fs::read(&config).unwrap();
    let document: serde_json::Value = serde_json::from_slice(&saved).unwrap();
    assert_eq!(document["data"]["max_workers"], 3);
    let logs = root.join("private logs");
    assert!(!logs.exists());
    for inline in [false, true] {
        let marker = if inline {
            "LAUNCHER_TOKEN_INLINE_FORM_SHOULD_NOT_LEAK"
        } else {
            "LAUNCHER_TOKEN_SPLIT_FORM_SHOULD_NOT_LEAK"
        };
        let inline_option = format!("--token={marker}");
        let mut arguments = vec![
            script.to_str().unwrap(),
            "--log-file",
            "stream",
            "https://mega.nz/file/ID#KEY",
            "--port",
            "8123",
        ];
        if inline {
            arguments.push(&inline_option);
        } else {
            arguments.extend(["--token", marker]);
        }
        let before = if logs.exists() {
            fs::read_dir(&logs)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let mut written = None;
        for help in [false, true] {
            if help {
                arguments.push("--help");
            }
            let result = run(&parent, &cwd, &temporary, &arguments);
            assert_eq!(result.status.code(), Some(if help { 0 } else { 2 }));
            let stdout = String::from_utf8(result.stdout)
                .unwrap()
                .replace("\r\n", "\n");
            let stderr = String::from_utf8(result.stderr)
                .unwrap()
                .replace("\r\n", "\n");
            if help {
                assert!(
                    stdout.contains("Usage:")
                        && stdout.contains("--port")
                        && stdout.contains("--token")
                );
                assert!(stderr.is_empty());
            } else {
                assert!(stdout.is_empty());
                assert_eq!(
                    stderr,
                    "[ERROR] Invalid input: MEGA link key has 2 bytes; expected 32 bytes\n"
                );
            }
            let entries = fs::read_dir(&logs)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect::<Vec<_>>();
            assert_eq!(entries.len(), before.len() + 1);
            let new = entries
                .iter()
                .filter(|path| {
                    !before
                        .iter()
                        .any(|name| path.file_name() == Some(name.as_os_str()))
                })
                .collect::<Vec<_>>();
            assert_eq!(new.len(), 1);
            assert_eq!(new[0].extension().unwrap(), "log");
            let text = fs::read_to_string(new[0]).unwrap();
            if let Some(previous) = &written {
                assert_eq!(&text, previous, "help must not append or create a log");
            } else {
                written = Some(text.clone());
            }
            assert_eq!(text.lines().count(), 4);
            for retained in [
                "cmd=stream",
                "Started",
                "Command started",
                "expected 32 bytes",
                "Finished",
                "\"exit_code\":2",
            ] {
                assert!(text.contains(retained));
            }
            for artifact in [&stdout, &stderr, &text] {
                for secret in [
                    marker,
                    "ID#KEY",
                    "Native CLI could not be started",
                    "NativeCommandExitException",
                ] {
                    assert!(!artifact.contains(secret));
                }
            }
            assert!(!stdout.contains('\x1b') && !stderr.contains('\x1b'));
            assert_eq!(fs::read(&config).unwrap(), saved);
        }
    }
    let preserved_logs = fs::read_dir(&logs)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            let bytes = fs::read(&path).unwrap();
            (path, bytes)
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    for inline in [false, true] {
        let marker = "LAUNCHER_TOKEN_SPLIT_FORM_SHOULD_NOT_LEAK";
        let inline_option = format!("--token={marker}");
        let mut arguments = vec![
            script.to_str().unwrap(),
            "--log-file",
            "stream",
            "FAKE_NOURL",
        ];
        if inline {
            arguments.push(&inline_option);
        } else {
            arguments.extend(["--token", marker]);
        }
        arguments.push("--definitely-not-a-real-flag");
        let result = run(&parent, &cwd, &temporary, &arguments);
        assert_eq!(result.status.code(), Some(2));
        assert!(result.stdout.is_empty());
        let stderr = String::from_utf8(result.stderr).unwrap();
        assert!(stderr.starts_with("[ERROR] Invalid input: error: unexpected argument"));
        assert!(stderr.contains("--definitely-not-a-real-flag") && stderr.contains("Usage:"));
        for forbidden in [
            marker,
            "Native CLI could not be started",
            "NativeCommandExitException",
            "\x1b",
        ] {
            assert!(!stderr.contains(forbidden));
        }
        let current = fs::read_dir(&logs)
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                let bytes = fs::read(&path).unwrap();
                (path, bytes)
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            current, preserved_logs,
            "parse errors must not open a logger"
        );
        assert_eq!(fs::read(&config).unwrap(), saved);
    }
    assert!(!cwd.join("User").exists() && !cwd.join("Logs").exists());
    assert_eq!(fs::read_dir(&cwd).unwrap().count(), 0);
    assert!(!root.join("Logs").exists() && !root.join("Output").exists());
    assert_eq!(fs::read(&script).unwrap().as_slice(), launcher.as_slice());
    fs::remove_file(root.join("mb.exe")).unwrap();
    let result = run(&script, &cwd, &temporary, &[]);
    assert_eq!(result.status.code(), Some(1));
    assert!(result.stdout.is_empty());
    assert!(
        String::from_utf8(result.stderr)
            .unwrap()
            .contains("Native mb.exe is missing")
    );
}
