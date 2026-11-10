#![allow(clippy::unwrap_used)]

use std::{fs, path::Path, process::Command, sync::Arc, time::Duration};

use megabasterd_cli::{
    platform::process,
    terminal::{logging::Logger, output::Output},
    transfers::control::Control,
};
use serde_json::{Value, json};

fn scratch() -> tempfile::TempDir {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/logging-context");
    fs::create_dir_all(&base).unwrap();
    tempfile::tempdir_in(base).unwrap()
}

fn run(root: &Path, args: &[&str]) -> process::ProcessOutput {
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
        .env("MEGABASTERD_LOG_DIR", root.join("private logs with spaces"))
        .env("HOOKMAKER_MAX_TEST_WORKERS", "1")
        .env("NO_COLOR", "1")
        .arg("--log-file")
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
fn actual_commands_keep_unique_fixed_context_from_startup_through_error_and_finish() {
    let scratch = scratch();
    let root = scratch.path();
    let logs = root.join("private logs with spaces");
    let hostile = "HOSTILEARGV-user@example.com-https://mega.nz/file/abc#SECRETKEY";
    let upload = root.join("source with spaces.bin");
    fs::write(&upload, b"x").unwrap();
    let mut names: Vec<std::ffi::OsString> = Vec::new();
    for (label, args, diagnostic, machine) in [
        (
            "download",
            vec![
                "download",
                hostile,
                "--parallel",
                "0",
                "--json",
                "--password",
                "SENTINELPW-CONTEXT",
                "--proxy",
                "http://user:SENTINELPROXY@proxy.example:8080",
            ],
            "Parallel downloads must be between 1 and 32",
            true,
        ),
        (
            "config",
            vec!["config", "get", hostile],
            "Unknown configuration setting",
            false,
        ),
        (
            "download",
            vec![
                "download",
                "https://mega.nz/file/ABC#SECRET",
                "--password",
                "secret",
                "--vault-passphrase",
                "vault-secret",
                "--elc-api-key",
                "key",
                "--parallel",
                "0",
                "--json",
            ],
            "Parallel downloads must be between 1 and 32",
            true,
        ),
        (
            "download",
            vec![
                "download",
                "https://mega.nz/file/ABC#SECRET",
                "-p",
                "linkpw",
                "--vault-passphrase",
                "vp",
                "--mfa-code",
                "123456",
                "--elc-api-key",
                "apikey",
                "--parallel",
                "0",
                "--json",
            ],
            "Parallel downloads must be between 1 and 32",
            true,
        ),
        (
            "upload",
            vec![
                "upload",
                upload.to_str().unwrap(),
                "--share-password",
                "share-secret",
                "--vault-passphrase",
                "vault-secret",
                "--parallel",
                "0",
                "--json",
            ],
            "Upload workers must be 1..64 and parallel files 1..32",
            true,
        ),
        (
            "stream",
            vec![
                "stream",
                "https://mega.nz/file/ID#KEY",
                "--port",
                "8800",
                "--token",
                "s3cret-token",
            ],
            "MEGA link key has 2 bytes; expected 32 bytes",
            false,
        ),
        (
            "stream",
            vec![
                "stream",
                "https://mega.nz/file/ID#KEY",
                "--port",
                "8800",
                "--token=s3cret-token",
            ],
            "MEGA link key has 2 bytes; expected 32 bytes",
            false,
        ),
    ] {
        let result = run(root, &args);
        assert_eq!(result.status.code(), Some(2));
        let stderr = String::from_utf8(result.stderr).unwrap();
        assert_eq!(stderr, format!("[ERROR] Invalid input: {diagnostic}\n"));
        let stdout = String::from_utf8(result.stdout).unwrap();
        if machine {
            assert_eq!(stdout.lines().count(), 1);
            let record: Value = serde_json::from_str(&stdout).unwrap();
            assert_eq!(record["event"], "result");
            assert_eq!(record["status"], "failed");
            assert_eq!(record["error_code"], "invalid_input");
            assert_eq!(record["error"], format!("Invalid input: {diagnostic}"));
            assert!(!stdout.contains("run=") && !stdout.contains("cmd="));
        } else {
            assert!(stdout.is_empty());
        }
        let current: Vec<_> = fs::read_dir(&logs)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(current.len(), names.len() + 1);
        let new: Vec<_> = current
            .iter()
            .filter(|name| !names.contains(*name))
            .collect();
        assert_eq!(new.len(), 1);
        let name = new[0];
        let run_id = Path::new(name).file_stem().unwrap().to_str().unwrap();
        assert!(run_id.starts_with("mb_") && run_id.contains("_UTC"));
        assert_eq!(Path::new(name).extension().unwrap(), "log");
        let text = fs::read_to_string(logs.join(name)).unwrap();
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines.len(), 4);
        let context = format!("run={run_id} cmd={label} ");
        assert!(lines.iter().all(|line| line.contains(&context)));
        assert!(lines[0].contains(&format!("[INFO] [RUNTIME] {context}Started ")));
        assert!(lines[1].contains(&format!("[INFO] [CLI] {context}Command started ")));
        assert!(lines[2].contains(&format!(
            "[ERROR] [OUTPUT] {context}Invalid input: {diagnostic}"
        )));
        assert!(lines[3].contains(&format!("[INFO] [RUNTIME] {context}Finished ")));
        assert!(lines[3].contains("\"exit_code\":2"));
        for raw in [
            "HOSTILEARGV",
            "user@example.com",
            "SECRETKEY",
            "SENTINELPW-CONTEXT",
            "SENTINELPROXY",
        ] {
            assert!(!text.contains(raw));
        }
        if label == "stream" {
            for artifact in [&text, &stderr, &stdout] {
                for secret in ["s3cret-token", "https://mega.nz/file/ID#KEY", "ID#KEY"] {
                    assert!(!artifact.contains(secret));
                }
            }
        }
        if args.contains(&"linkpw") {
            for artifact in [&text, &stderr, &stdout] {
                for secret in ["linkpw", "vp", "apikey", "https://mega.nz/file/ABC#SECRET"] {
                    assert!(!artifact.contains(secret));
                }
            }
        }
        if args.contains(&"vault-secret") || args.contains(&"linkpw") {
            for raw in [
                "https://mega.nz/file/ABC#SECRET",
                "#SECRET",
                "share-secret",
                "vault-secret",
            ] {
                assert!(!text.contains(raw));
            }
            for (line, prefix) in lines.iter().zip([
                format!("[INFO] [RUNTIME] {context}Started "),
                format!("[INFO] [CLI] {context}Command started "),
                format!("[ERROR] [OUTPUT] {context}Invalid input: {diagnostic} "),
                format!("[INFO] [RUNTIME] {context}Finished "),
            ]) {
                let record = line.split_once(" UTC] ").unwrap().1;
                let mut fields: Value =
                    serde_json::from_str(record.strip_prefix(&prefix).unwrap()).unwrap();
                assert!(fields.is_object());
                if args.contains(&"linkpw") {
                    if let Some(elapsed) = fields.as_object_mut().unwrap().remove("elapsed_seconds")
                    {
                        assert!(elapsed.is_number());
                    }
                    assert!(!fields.to_string().contains("123456"));
                    assert!(!stderr.contains("123456") && !stdout.contains("123456"));
                }
                for raw in ["\"secret\"", "\"key\""] {
                    assert!(!fields.to_string().contains(raw));
                }
            }
        }
        names.push(name.clone());
    }
    assert_ne!(names[0], names[1]);
    assert_eq!(fs::read(upload).unwrap(), b"x");
}

#[test]
fn parser_failure_never_discloses_stream_tokens_or_initializes_private_storage() {
    let scratch = scratch();
    let root = scratch.path();
    for inline in [false, true] {
        let marker = "LAUNCHER_TOKEN_SPLIT_FORM_SHOULD_NOT_LEAK";
        let inline_option = format!("--token={marker}");
        let mut arguments = vec!["stream", "FAKE_NOURL"];
        if inline {
            arguments.push(&inline_option);
        } else {
            arguments.extend(["--token", marker]);
        }
        arguments.push("--definitely-not-a-real-flag");
        let result = run(root, &arguments);
        assert_eq!(result.status.code(), Some(2));
        assert!(result.stdout.is_empty());
        let stderr = String::from_utf8(result.stderr).unwrap();
        assert!(stderr.starts_with("[ERROR] Invalid input: error: unexpected argument"));
        assert!(stderr.contains("--definitely-not-a-real-flag") && stderr.contains("Usage:"));
        for forbidden in [marker, "panicked", "Traceback", "\x1b"] {
            assert!(!stderr.contains(forbidden));
        }
        assert!(!root.join("private logs with spaces").exists());
        assert!(!root.join("user").exists());
        assert!(!root.join("Output").exists());
        assert_eq!(fs::read_dir(root).unwrap().count(), 0);
    }
}

#[test]
fn actual_command_status_is_independent_of_stderr_on_success_and_operational_failure() {
    let scratch = scratch();
    let root = scratch.path();
    let first_part = root.join("missing peer.bin.part1-2");
    let destination = root.join("must not be published.bin");
    fs::write(&first_part, b"original first part").unwrap();
    let logs = root.join("private logs with spaces");
    let mut names = Vec::new();
    for (arguments, command, expected) in [
        (
            vec![
                "merge",
                first_part.to_str().unwrap(),
                "-o",
                destination.to_str().unwrap(),
            ],
            "merge",
            1,
        ),
        (vec!["config", "set", "max_workers", "3"], "config", 0),
    ] {
        let result = run(root, &arguments);
        assert_eq!(result.status.code(), Some(expected));
        assert!(result.stdout.is_empty());
        let stderr = String::from_utf8(result.stderr).unwrap();
        if expected == 0 {
            assert_eq!(stderr, "[INFO] Configuration setting saved.\n");
        } else {
            assert!(stderr.starts_with("[ERROR] I/O operation failed: "));
        }
        assert!(!stderr.contains("panicked") && !stderr.contains("Traceback"));
        let current = fs::read_dir(&logs)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(current.len(), names.len() + 1);
        let new = current
            .iter()
            .filter(|name| !names.contains(*name))
            .collect::<Vec<_>>();
        assert_eq!(new.len(), 1);
        let name = new[0];
        let run_id = Path::new(name).file_stem().unwrap().to_str().unwrap();
        let text = fs::read_to_string(logs.join(name)).unwrap();
        let lines = text.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 4);
        let context = format!("run={run_id} cmd={command} ");
        assert!(lines.iter().all(|line| line.contains(&context)));
        assert!(lines[0].contains("Started") && lines[1].contains("Command started"));
        let (level, message) = stderr.trim_end().split_once("] ").unwrap();
        assert!(lines[2].contains(&format!("{level}] [OUTPUT] {context}{message} ")));
        assert!(lines[3].contains("Finished"));
        assert!(lines[3].contains(&format!("\"exit_code\":{expected}")));
        names.push(name.clone());
        assert_eq!(fs::read(&first_part).unwrap(), b"original first part");
        assert!(!root.join("missing peer.bin.part2-2").exists());
        assert!(!destination.exists());
    }
    let config: Value =
        serde_json::from_slice(&fs::read(root.join("user/native-v2/Config/config.json")).unwrap())
            .unwrap();
    assert_eq!(config["data"]["max_workers"], 3);
}

#[test]
fn json_positionals_keep_secrets_out_of_real_command_logs_on_success_and_rejection() {
    let scratch = scratch();
    let root = scratch.path();
    let logs = root.join("private logs with spaces");
    let config = root.join("user/native-v2/Config/config.json");
    let payload = r#"{"host.example":{"user":"u","api_key":"SUPERSECRET"}}"#;
    let mut names = Vec::new();
    let mut saved = None;
    for (arguments, diagnostic, expected_exit, records) in [
        (
            vec!["config", "set", "elc_accounts", payload],
            "[INFO] Configuration setting saved.\n",
            0,
            4,
        ),
        (vec!["config", "get", "elc_accounts"], "", 0, 3),
        (
            vec![
                "config",
                "set",
                "elc_accounts",
                r#"{"a":{"b":[{"password":"pw1","note":"keep"}]}}"#,
            ],
            "[ERROR] Invalid input: Invalid value for config setting elc_accounts\n",
            2,
            4,
        ),
        (
            vec!["config", "set", "elc_accounts", r#"{"api_key": "oops"#],
            "[ERROR] Invalid input: Expected a valid number or JSON object\n",
            2,
            4,
        ),
    ] {
        let result = run(root, &arguments);
        assert_eq!(result.status.code(), Some(expected_exit));
        let stdout = String::from_utf8(result.stdout).unwrap();
        let stderr = String::from_utf8(result.stderr).unwrap();
        assert_eq!(stderr, diagnostic);
        if arguments[1] == "get" {
            assert_eq!(
                serde_json::from_str::<Value>(&stdout).unwrap(),
                json!({"host.example":{"user":"u","api_key":"<redacted>"}})
            );
            assert_eq!(stdout.lines().count(), 1);
        } else {
            assert!(stdout.is_empty());
        }
        let current: Vec<_> = fs::read_dir(&logs)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(current.len(), names.len() + 1);
        let new: Vec<_> = current
            .iter()
            .filter(|name| !names.contains(*name))
            .collect();
        assert_eq!(new.len(), 1);
        let name = new[0];
        assert_eq!(Path::new(name).extension().unwrap(), "log");
        let run_id = Path::new(name).file_stem().unwrap().to_str().unwrap();
        let context = format!("run={run_id} cmd=config ");
        let text = fs::read_to_string(logs.join(name)).unwrap();
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines.len(), records);
        assert!(lines.iter().all(|line| line.contains(&context)));
        assert!(lines[0].contains(&format!("[INFO] [RUNTIME] {context}Started ")));
        assert!(lines[1].contains(&format!("[INFO] [CLI] {context}Command started ")));
        let finish = lines.last().unwrap();
        assert!(finish.contains(&format!("[INFO] [RUNTIME] {context}Finished ")));
        assert!(finish.contains(&format!("\"exit_code\":{expected_exit}")));
        if records == 4 {
            let message = diagnostic.trim().split_once("] ").unwrap().1;
            assert!(lines[2].contains(message));
        }
        for artifact in [&stdout, &stderr, &text] {
            for secret in ["SUPERSECRET", "pw1", "oops"] {
                assert!(!artifact.contains(secret));
            }
        }
        names.push(name.clone());
        let bytes = fs::read(&config).unwrap();
        if let Some(original) = &saved {
            assert_eq!(&bytes, original);
        } else {
            let document: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(
                document["data"]["elc_accounts"],
                json!({"host.example":{"user":"u","api_key":"SUPERSECRET"}})
            );
            saved = Some(bytes);
        }
    }
}

#[test]
fn plain_text_positionals_keep_private_values_out_of_actual_config_output_and_logs() {
    let scratch = scratch();
    let root = scratch.path();
    let logs = root.join("private logs with spaces");
    let config = root.join("user/native-v2/Config/config.json");
    let payload = "password: hunter2";
    let mut names = Vec::new();
    let mut saved = None;
    for (arguments, expected_stdout, diagnostic, records) in [
        (
            vec!["config", "set", "user_agent", payload],
            "",
            "[INFO] Configuration setting saved.\n",
            4,
        ),
        (
            vec!["config", "get", "user_agent"],
            "password: <redacted>\n",
            "",
            3,
        ),
    ] {
        let result = run(root, &arguments);
        assert_eq!(result.status.code(), Some(0));
        let stdout = String::from_utf8(result.stdout).unwrap();
        let stderr = String::from_utf8(result.stderr).unwrap();
        assert_eq!(stdout, expected_stdout);
        assert_eq!(stderr, diagnostic);
        let current: Vec<_> = fs::read_dir(&logs)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(current.len(), names.len() + 1);
        let new: Vec<_> = current
            .iter()
            .filter(|name| !names.contains(*name))
            .collect();
        assert_eq!(new.len(), 1);
        let name = new[0];
        assert_eq!(Path::new(name).extension().unwrap(), "log");
        let run_id = Path::new(name).file_stem().unwrap().to_str().unwrap();
        let context = format!("run={run_id} cmd=config ");
        let text = fs::read_to_string(logs.join(name)).unwrap();
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines.len(), records);
        assert!(lines.iter().all(|line| line.contains(&context)));
        assert!(lines[0].contains(&format!("[INFO] [RUNTIME] {context}Started ")));
        assert!(lines[1].contains(&format!("[INFO] [CLI] {context}Command started ")));
        let finish = lines.last().unwrap();
        assert!(finish.contains(&format!("[INFO] [RUNTIME] {context}Finished ")));
        assert!(finish.contains("\"exit_code\":0"));
        if records == 4 {
            assert!(lines[2].contains("Configuration setting saved."));
        }
        for artifact in [&stdout, &stderr, &text] {
            assert!(!artifact.contains("hunter2"));
        }
        names.push(name.clone());
        let bytes = fs::read(&config).unwrap();
        if let Some(original) = &saved {
            assert_eq!(&bytes, original);
        } else {
            let document: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(document["data"]["user_agent"], payload);
            saved = Some(bytes);
        }
    }
}

#[test]
fn public_logger_constructors_keep_unknown_command_context_and_redaction_on_every_record() {
    let scratch = scratch();
    let logs = scratch.path().join("private logs with spaces");
    let mut names: Vec<std::ffi::OsString> = Vec::new();
    for configured in [false, true] {
        let logger = Arc::new(if configured {
            Logger::configured(&logs, 0, 0).unwrap()
        } else {
            Logger::start(&logs).unwrap()
        });
        let name = logger.name().to_owned();
        let run_id = Path::new(&name).file_stem().unwrap().to_str().unwrap();
        let output = Output::with_writers(true, true, Vec::new(), Vec::new());
        output.attach_logger(logger.clone()).unwrap();
        output
            .diagnostic("INFO", "Downloaded from https://mega.nz/file/abc#SECRETKEY")
            .unwrap();
        logger
            .write(
                "WARNING",
                "CONTEXT",
                "Refreshing account user@example.com; password: SENTINELPW-CONTEXT",
                &json!({"api_key": "SENTINELAPI-CONTEXT", "count": 7}),
            )
            .unwrap();
        logger.finish(0).unwrap();
        let text = fs::read_to_string(logs.join(&name)).unwrap();
        assert_eq!(text.lines().count(), 4);
        let context = format!("run={run_id} cmd=unknown ");
        assert!(text.lines().all(|line| line.contains(&context)));
        assert!(text.contains(&format!("[INFO] [OUTPUT] {context}Downloaded from ")));
        assert!(text.contains(&format!("[WARNING] [CONTEXT] {context}Refreshing account ")));
        assert!(text.contains("<redacted-url>") && text.contains("<redacted-email>"));
        assert!(text.contains("\"count\":7") && text.contains("\"exit_code\":0"));
        for secret in [
            "https://mega.nz",
            "SECRETKEY",
            "user@example.com",
            "SENTINELPW-CONTEXT",
            "SENTINELAPI-CONTEXT",
        ] {
            assert!(!text.contains(secret));
        }
        let before = fs::read(logs.join(&name)).unwrap();
        assert!(
            logger
                .write("INFO", "CONTEXT", "must stay closed", &json!({}))
                .is_err()
        );
        assert_eq!(fs::read(logs.join(&name)).unwrap(), before);
        drop(output);
        drop(logger);
        names.push(name);
    }
    assert_ne!(names[0], names[1]);
}
