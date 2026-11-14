#![allow(clippy::unwrap_used)]

use std::cell::Cell;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use super::*;
use crate::terminal::output::Output;

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);
impl Capture {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}
impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut output = self.0.lock().unwrap();
        if bytes.len() > 8192usize.saturating_sub(output.len()) {
            return Err(io::Error::other("Watch fixture output exceeded its bound"));
        }
        output.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn scratch() -> crate::test_support::TempDir {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/watch");
    std::fs::create_dir_all(&base).unwrap();
    crate::test_support::tempdir_in(base).unwrap()
}
fn options() -> WatchOptions {
    WatchOptions {
        destination: "output".into(),
        run: false,
        auth: args::VaultOptions {
            vault_passphrase: None,
            mfa_code: None,
        },
    }
}
fn context(root: &Path) -> (Context, Capture, Capture) {
    let mut context = Context::test_context(root);
    let stdout = Capture::default();
    let stderr = Capture::default();
    context.output = Output::with_writers(false, false, stdout.clone(), stderr.clone());
    (context, stdout, stderr)
}
#[test]
fn context_and_output_share_one_sanitized_warning_after_the_file_sink_is_disabled() {
    let scratch = scratch();
    let (mut context, stdout, stderr) = context(scratch.path());
    let logger = Arc::new(
        crate::terminal::logging::Logger::configured(&context.paths.logs, 512, 2).unwrap(),
    );
    let blocked = context
        .paths
        .logs
        .join(format!("{}.1", logger.name().to_string_lossy()));
    std::fs::create_dir(&blocked).unwrap();
    context.output.attach_logger(logger.clone()).unwrap();
    context.logger = Some(logger);
    context.diagnostic(
        "WARNING",
        "CONTEXT",
        &"x".repeat(600),
        &serde_json::json!({}),
    );
    context.output.message("WARNING", "still alive").unwrap();
    context.diagnostic(
        "ERROR",
        "CONTEXT",
        "context still alive",
        &serde_json::json!({}),
    );
    context.finish(1);
    let text = stderr.text();
    assert_eq!(text.matches("Private runtime log write failed.").count(), 1);
    assert!(text.contains("still alive") && text.contains("context still alive"));
    assert!(!text.contains("could not be finalized"));
    assert!(stdout.text().is_empty());
    assert!(blocked.is_dir());
}

fn backend_output(success: bool, stdout: &[u8]) -> Result<process::ProcessOutput> {
    #[cfg(unix)]
    use std::os::unix::process::ExitStatusExt;
    #[cfg(windows)]
    use std::os::windows::process::ExitStatusExt;

    #[cfg(windows)]
    let status = std::process::ExitStatus::from_raw(u32::from(!success));
    #[cfg(unix)]
    let status = std::process::ExitStatus::from_raw(i32::from(!success) << 8);
    Ok(process::ProcessOutput {
        status,
        stdout: stdout.to_vec(),
        stderr: Vec::new(),
    })
}

fn clipboard_fixture(
    commands: &[(&str, &[&str])],
    replies: Vec<Result<process::ProcessOutput>>,
    expected: &[&str],
) -> Result<String> {
    let mut replies = replies.into_iter();
    let mut attempts = Vec::new();
    let result = clipboard_with(commands, |program, args| {
        attempts.push((program.to_path_buf(), args.to_vec()));
        replies
            .next()
            .unwrap_or_else(|| panic!("Unplanned clipboard process attempt"))
    });
    assert!(replies.next().is_none(), "Clipboard fixture replies unused");
    assert_eq!(attempts.len(), expected.len());
    for ((program, args), expected) in attempts.iter().zip(expected) {
        assert_eq!(program, Path::new(expected));
        let expected_args: &[&str] = match *expected {
            "preferred-clipboard" | "fallback-clipboard" => &[],
            "wl-paste" => &["-n"],
            "xclip" => &["-selection", "clipboard", "-o"],
            "pbpaste" => &[],
            _ => panic!("Unexpected clipboard program"),
        };
        assert_eq!(
            args,
            &expected_args
                .iter()
                .map(|arg| OsString::from(*arg))
                .collect::<Vec<_>>()
        );
    }
    result
}

#[test]
fn missing_preferred_clipboard_backend_uses_the_next_configured_command() {
    for (commands, expected) in [
        (
            TEST_CLIPBOARD,
            &["preferred-clipboard", "fallback-clipboard"][..],
        ),
        (LINUX_CLIPBOARD, &["wl-paste", "xclip"][..]),
    ] {
        let text = clipboard_fixture(
            commands,
            vec![
                Err(Error::MissingTool("Requested external executable".into())),
                backend_output(true, b"https://mega.nz/file/x#y"),
            ],
            expected,
        )
        .unwrap();
        assert_eq!(text, "https://mega.nz/file/x#y");
        assert!(text.contains("mega.nz"));
    }
}

#[test]
fn failing_preferred_clipboard_backend_uses_the_next_configured_command() {
    for (commands, expected) in [
        (
            TEST_CLIPBOARD,
            &["preferred-clipboard", "fallback-clipboard"][..],
        ),
        (LINUX_CLIPBOARD, &["wl-paste", "xclip"][..]),
    ] {
        for failure in [
            Err(Error::protocol("Clipboard backend unavailable")),
            backend_output(false, b"failed backend output must not escape"),
        ] {
            assert_eq!(
                clipboard_fixture(
                    commands,
                    vec![failure, backend_output(true, b"fallback text")],
                    expected,
                )
                .unwrap(),
                "fallback text"
            );
        }
    }
}

#[test]
fn successful_preferred_clipboard_backend_returns_without_trying_another_command() {
    for (commands, expected) in [
        (TEST_CLIPBOARD, "preferred-clipboard"),
        (LINUX_CLIPBOARD, "wl-paste"),
        (MACOS_CLIPBOARD, "pbpaste"),
    ] {
        for text in ["from-pyperclip", "", "  first\nsecond\n", "متن"] {
            assert_eq!(
                clipboard_fixture(
                    commands,
                    vec![backend_output(true, text.as_bytes())],
                    &[expected]
                )
                .unwrap(),
                text
            );
        }
    }
}

#[test]
fn clipboard_cancel_invalid_utf8_and_exhaustion_keep_their_existing_error_boundaries() {
    for (commands, expected) in [
        (TEST_CLIPBOARD, "preferred-clipboard"),
        (LINUX_CLIPBOARD, "wl-paste"),
        (MACOS_CLIPBOARD, "pbpaste"),
    ] {
        assert!(matches!(
            clipboard_fixture(commands, vec![Err(Error::Canceled)], &[expected]),
            Err(Error::Canceled)
        ));
        assert!(matches!(
            clipboard_fixture(commands, vec![backend_output(true, &[0xff])], &[expected]),
            Err(Error::Protocol(message)) if message == "Clipboard backend returned non-UTF-8 text"
        ));
    }
    for (commands, expected) in [
        (
            TEST_CLIPBOARD,
            &["preferred-clipboard", "fallback-clipboard"][..],
        ),
        (LINUX_CLIPBOARD, &["wl-paste", "xclip"][..]),
        (MACOS_CLIPBOARD, &["pbpaste"][..]),
    ] {
        let replies = expected
            .iter()
            .map(|_| backend_output(false, b"ignored"))
            .collect();
        assert!(matches!(
            clipboard_fixture(commands, replies, expected),
            Err(Error::MissingTool(message)) if message ==
                "No usable clipboard backend; install/configure the platform clipboard utility yourself"
        ));
    }
}

const LINK: &str = "https://mega.nz/file/abc123#SuperSecretKeyMaterial";

#[test]
fn clipboard_enqueue_shows_only_redacted_link_but_persists_the_exact_source() {
    let scratch = scratch();
    let (mut context, stdout, stderr) = context(scratch.path());
    let queue = Queue::new(context.paths.queue());
    let mut reads = ["", LINK].into_iter();
    drive(
        &mut context,
        &queue,
        &options(),
        |_| reads.next().map(str::to_owned).ok_or(Error::Canceled),
        |_| Ok(()),
        |queue, payload| queue.add(JobType::Download, payload),
    )
    .unwrap();
    let items = queue.list().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(queue.payload(&items[0]).unwrap().source, LINK);
    assert!(stdout.text().is_empty());
    let text = stderr.text();
    assert!(!text.contains("SuperSecretKeyMaterial"));
    assert!(text.contains("#<key>") && text.contains("Watch stopped."));
}

#[test]
fn transient_enqueue_lock_contention_keeps_polling_and_does_not_store_the_failed_link() {
    let scratch = scratch();
    let (mut context, _, stderr) = context(scratch.path());
    let queue = Queue::new(context.paths.queue());
    let mut reads = ["", LINK, "https://mega.nz/file/second#k2"].into_iter();
    let mut calls = Vec::new();
    drive(
        &mut context,
        &queue,
        &options(),
        |_| reads.next().map(str::to_owned).ok_or(Error::Canceled),
        |_| Ok(()),
        |queue, payload| {
            calls.push(payload.source.clone());
            if calls.len() == 1 {
                Err(Error::Busy("synthetic contention".into()))
            } else {
                queue.add(JobType::Download, payload)
            }
        },
    )
    .unwrap();
    assert_eq!(calls, [LINK, "https://mega.nz/file/second#k2"]);
    let items = queue.list().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(
        queue.payload(&items[0]).unwrap().source,
        "https://mega.nz/file/second#k2"
    );
    assert!(stderr.text().contains("Queue is busy") && stderr.text().contains("Watch stopped."));
}

#[test]
fn corrupt_queue_at_start_or_enqueue_fails_cleanly_and_preserves_the_original_bytes() {
    for during_enqueue in [false, true] {
        let scratch = scratch();
        let (mut context, stdout, stderr) = context(scratch.path());
        let path = context.paths.queue();
        let queue = Queue::new(&path);
        let reads_count = Cell::new(0);
        let mut reads = ["", LINK].into_iter();
        if !during_enqueue {
            let directory =
                crate::platform::secure_files::PrivateDirectory::ensure(path.parent().unwrap())
                    .unwrap();
            let mut file = directory
                .open_private(path.file_name().unwrap(), true)
                .unwrap();
            file.write_all(b"{not json").unwrap();
            file.sync_all().unwrap();
        }
        let result = drive(
            &mut context,
            &queue,
            &options(),
            |_| {
                reads_count.set(reads_count.get() + 1);
                reads.next().map(str::to_owned).ok_or(Error::Canceled)
            },
            |_| Ok(()),
            |_, _| {
                Err(Error::Corrupt(
                    "The transfer queue file is corrupt and was preserved.".into(),
                ))
            },
        );
        let error = result.unwrap_err();
        assert_eq!(error.exit_code(), 1);
        assert_eq!(error.code(), "storage_corrupt");
        assert!(stdout.text().is_empty());
        assert!(!stderr.text().contains("Queued "));
        if during_enqueue {
            assert_eq!(reads_count.get(), 2);
        } else {
            assert_eq!(
                reads_count.get(),
                0,
                "corruption must fail before clipboard access"
            );
            assert_eq!(std::fs::read(path).unwrap(), b"{not json");
        }
    }
}

#[test]
fn invalid_interval_refuses_before_queue_or_clipboard_access() {
    let scratch = scratch();
    let (mut context, stdout, stderr) = context(scratch.path());
    for interval in [0.0, -1.0, -0.5, f64::NAN, f64::INFINITY] {
        let error = dispatch(&mut context, interval, None, false, options().auth).unwrap_err();
        assert_eq!(error.exit_code(), 2);
        assert!(error.to_string().to_ascii_lowercase().contains("interval"));
    }
    assert!(!context.paths.queue().exists());
    assert!(stdout.text().is_empty() && stderr.text().is_empty());
}
