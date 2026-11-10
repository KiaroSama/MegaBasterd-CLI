#![allow(clippy::unwrap_used)]

use megabasterd_cli::{
    services::hooks::{after_batch, after_file, command_args},
    terminal::{logging::Logger, output::Output},
    transfers::control::Control,
};
use std::{ffi::OsString, path::Path};

#[test]
fn transferred_path_is_one_literal_argument_and_configured_arguments_are_preserved() {
    let path = OsString::from("directory with spaces/file;$(untrusted).bin");
    let (program, arguments) = command_args("notify --flag", &[path.clone()]).unwrap();
    assert_eq!(program, OsString::from("notify"));
    assert_eq!(arguments, vec![OsString::from("--flag"), path]);
    assert!(command_args("", &[]).is_err());
    assert!(command_args("notify\0bad", &[]).is_err());
    assert!(command_args("notify 'unterminated", &[]).is_err());
}

#[cfg(windows)]
#[test]
fn windows_hook_parsing_preserves_source_backslashes_and_quotes() {
    let (program, arguments) =
        command_args(r#"C:\Tools\notify.exe --path "C:\My Files""#, &[]).unwrap();
    assert_eq!(program, OsString::from(r"C:\Tools\notify.exe"));
    assert_eq!(
        arguments.last().unwrap(),
        &OsString::from(r#""C:\My Files""#)
    );
}

#[cfg(unix)]
#[test]
fn unix_hooks_use_posix_quoting_without_running_a_shell() {
    let (program, arguments) = command_args("/usr/bin/notify --msg 'hello world'", &[]).unwrap();
    assert_eq!(program, OsString::from("/usr/bin/notify"));
    assert_eq!(
        arguments,
        vec![OsString::from("--msg"), OsString::from("hello world")]
    );
}

#[test]
fn download_workers_receive_explicit_command_configuration_without_thread_local_lookup() {
    let executable = |source: &str| {
        assert!(
            !source.contains("/*") && !source.contains("*/"),
            "Block comments require a reviewed structural-contract update"
        );
        source
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let hooks = executable(include_str!("../src/services/hooks.rs"));
    let download = executable(include_str!("../src/cli/download.rs"));
    let helper = hooks
        .split_once("pub fn after_file(")
        .unwrap()
        .1
        .split_once("pub fn after_batch(")
        .unwrap()
        .0;
    for parameter in [
        "command: Option<&str>",
        "path: &Path",
        "control: &Control",
        "output: &Output",
    ] {
        assert!(helper.contains(parameter), "missing explicit {parameter}");
    }
    assert!(helper.contains(
        "Some(command) => execute(command, &[path.as_os_str().to_owned()], control, output)"
    ));
    for source in [&hooks, &download] {
        assert!(!source.contains("get_current_context"));
        assert!(!source.contains("thread_local!"));
    }
    let configured = "hooks::after_file(context.config.run_command.as_deref(), &path, &context.control, &context.output)";
    assert_eq!(download.matches("hooks::after_file(").count(), 1);
    let workers = download
        .split_once("std::thread::scope(")
        .unwrap()
        .1
        .split_once("for worker in workers {")
        .unwrap()
        .0;
    let spawn = workers.find("workers.push(scope.spawn(|| {").unwrap();
    let success = workers.find("Ok(path) => {").unwrap();
    let handoff = workers.find(configured).unwrap();
    let failure = workers.find("Err(error) => {").unwrap();
    assert!(spawn < success && success < handoff && handoff < failure);
}

#[test]
fn command_diagnostics_keep_the_executable_and_count_without_arguments_or_paths() {
    use std::{
        io::{self, Write},
        sync::{Arc, Mutex},
    };

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);
    impl Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let mut output = self.0.lock().unwrap();
            if bytes.len() > (16 * 1024usize).saturating_sub(output.len()) {
                return Err(io::Error::other(
                    "Command diagnostic fixture exceeded its bound",
                ));
            }
            output.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/hook-diagnostics");
    std::fs::create_dir_all(&root).unwrap();
    let scratch = tempfile::tempdir_in(root).unwrap();
    for quiet in [false, true] {
        let logs = scratch
            .path()
            .join(if quiet { "quiet logs" } else { "visible logs" });
        let logger = Arc::new(Logger::start(&logs).unwrap());
        let log_name = logger.name().to_owned();
        let machine = Capture::default();
        let human = Capture::default();
        let output = Output::with_writers(true, quiet, machine.clone(), human.clone());
        output.set_diagnostic_level("INFO").unwrap();
        output.attach_logger(logger.clone()).unwrap();
        let control = Control::new();
        control.cancel();
        let command = "private-parent/tool --token SUPERSECRET";
        assert_eq!(
            after_file(
                Some(command),
                Path::new("private-path/sentinel.bin"),
                &control,
                &output
            )
            .unwrap_err()
            .exit_code(),
            130
        );
        assert_eq!(
            after_batch(Some(command), "upload", 1, 0, &control, &output)
                .unwrap_err()
                .exit_code(),
            130
        );
        logger.finish(130).unwrap();
        drop(output);
        drop(logger);
        let log = std::fs::read_to_string(logs.join(log_name)).unwrap();
        let human = String::from_utf8(human.0.lock().unwrap().clone()).unwrap();
        let expected = "Running configured command: tool (2 configured args)";
        assert_eq!(log.matches(expected).count(), 2);
        assert_eq!(human.matches(expected).count(), if quiet { 0 } else { 2 });
        assert!(machine.0.lock().unwrap().is_empty());
        for surface in [&log, &human] {
            for secret in [
                "SUPERSECRET",
                "--token",
                "private-parent",
                "private-path",
                "sentinel.bin",
            ] {
                assert!(!surface.contains(secret));
            }
        }
    }
}

const CHILD: &str = "batch_command_child_records_literal_arguments_once";

#[test]
fn batch_command_child_records_literal_arguments_once() {
    use std::io::Write;

    let arguments: Vec<_> = std::env::args_os().collect();
    if !arguments
        .windows(2)
        .any(|pair| pair[0] == "--exact" && pair[1] == CHILD)
    {
        return;
    }
    assert_eq!(arguments.len(), 10);
    assert_eq!(arguments[3], "--nocapture");
    assert_eq!(arguments[4], "--test-threads=1");
    let marker = Path::new(&arguments[5]);
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/hook-contract");
    assert!(
        marker
            .parent()
            .unwrap()
            .canonicalize()
            .unwrap()
            .starts_with(base.canonicalize().unwrap())
    );
    assert_eq!(marker.file_name().unwrap(), "batch-marker.json");
    assert_eq!(arguments[6], "marker;$(literal)");
    assert_eq!(arguments[7], "upload");
    assert_eq!(arguments[8], "4");
    assert_eq!(arguments[9], "2");
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(marker)
        .unwrap();
    serde_json::to_writer(
        &mut output,
        &serde_json::json!({
            "configured":arguments[6].to_str().unwrap(),"kind":arguments[7].to_str().unwrap(),
            "succeeded":arguments[8].to_str().unwrap(),"failed":arguments[9].to_str().unwrap()
        }),
    )
    .unwrap();
    output.flush().unwrap();
    output.sync_all().unwrap();
}

#[test]
fn batch_outcomes_are_three_literal_arguments_to_one_owned_native_command() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/hook-contract");
    std::fs::create_dir_all(&root).unwrap();
    let scratch = tempfile::tempdir_in(&root).unwrap();
    let cwd = std::env::current_dir().unwrap().canonicalize().unwrap();
    let executable = std::env::current_exe().unwrap().canonicalize().unwrap();
    let relative = executable.strip_prefix(&cwd).unwrap().to_str().unwrap();
    let marker = scratch
        .path()
        .canonicalize()
        .unwrap()
        .join("batch-marker.json");
    let relative_marker = marker.strip_prefix(&cwd).unwrap().to_str().unwrap();
    assert!(!relative.contains(char::is_whitespace));
    assert!(!relative_marker.contains(char::is_whitespace));
    let command = format!(
        "{relative} --exact {CHILD} --nocapture --test-threads=1 {relative_marker} marker;$(literal)"
    );
    let output = Output::with_writers(false, false, Vec::new(), Vec::new());
    after_batch(Some(&command), "upload", 4, 2, &Control::new(), &output).unwrap();
    let record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&marker).unwrap()).unwrap();
    assert_eq!(
        record,
        serde_json::json!({"configured":"marker;$(literal)","kind":"upload","succeeded":"4","failed":"2"})
    );
    assert_eq!(std::fs::read_dir(scratch.path()).unwrap().count(), 1);
}

#[test]
fn empty_batches_and_unconfigured_commands_do_nothing_even_after_cancellation() {
    let control = Control::new();
    control.cancel();
    let output = Output::with_writers(false, false, Vec::new(), Vec::new());
    after_batch(Some("unfinished '"), "upload", 0, 0, &control, &output).unwrap();
    for command in [None, Some("")] {
        after_batch(command, "download", 1, 0, &control, &output).unwrap();
        after_file(
            command,
            Path::new("file with spaces.bin"),
            &control,
            &output,
        )
        .unwrap();
    }
    assert_eq!(
        after_file(
            Some("definitely-unavailable-program"),
            Path::new("file.bin"),
            &control,
            &output,
        )
        .unwrap_err()
        .exit_code(),
        130
    );
}
