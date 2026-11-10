//! Real file-command failures must not become successful automation exits.
#![allow(clippy::unwrap_used)]

use megabasterd_cli::{platform::process, transfers::control::Control};
use std::{ffi::OsString, fs, path::Path, process::Command, time::Duration};

fn run(root: &Path, arguments: &[OsString], input: Option<&[u8]>) -> process::ProcessOutput {
    let answers = input.map(|bytes| {
        let path = root.join("answers.txt");
        fs::write(&path, bytes).unwrap();
        fs::File::open(path).unwrap()
    });
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
        .env("MEGABASTERD_LOG_DIR", root.join("logs"))
        .env("HOOKMAKER_MAX_TEST_WORKERS", "1")
        .env("NO_COLOR", "1")
        .args(["--no-log-file", "--quiet"])
        .args(arguments);
    process::run_command(
        command,
        Duration::from_secs(5),
        16 * 1024,
        16 * 1024,
        &Control::new(),
        answers,
    )
    .unwrap()
}

fn refusal(result: process::ProcessOutput, code: i32, diagnostic: &str) {
    assert_eq!(result.status.code(), Some(code));
    assert!(result.stdout.is_empty());
    let stderr = String::from_utf8(result.stderr).unwrap();
    assert!(stderr.contains(diagnostic), "unexpected refusal: {stderr}");
    assert!(!stderr.contains("panicked") && !stderr.contains("Traceback"));
}

#[test]
fn actual_file_commands_reject_alias_missing_part_bad_name_empty_input_and_unsupported_thumbnail() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/file-ops-cli");
    fs::create_dir_all(&base).unwrap();
    let scratch = private_tempfile::tempdir_in(base).unwrap();
    let root = scratch.path();
    let source = root.join("payload with spaces.bin");
    let bytes: Vec<_> = (0..2 * 1024 * 1024 + 5)
        .map(|index| (index % 251) as u8)
        .collect();
    fs::write(&source, &bytes).unwrap();
    let split = run(
        root,
        &["split".into(), source.clone().into_os_string(), "1".into()],
        None,
    );
    assert_eq!(split.status.code(), Some(0));
    assert!(split.stdout.is_empty() && split.stderr.is_empty());
    let parts = (1..=3)
        .map(|index| root.join(format!("payload with spaces.bin.part{index}-3")))
        .collect::<Vec<_>>();
    for (index, part) in parts.iter().enumerate() {
        let start = index * 1024 * 1024;
        let end = bytes.len().min(start + 1024 * 1024);
        assert_eq!(fs::read(part).unwrap(), bytes[start..end]);
    }
    let checksum = root.join("payload with spaces.bin.sha1");
    let checksum_bytes = fs::read(&checksum).unwrap();
    refusal(
        run(
            root,
            &[
                "merge".into(),
                parts[0].clone().into_os_string(),
                "-o".into(),
                parts[0].clone().into_os_string(),
            ],
            Some(b"y\n"),
        ),
        2,
        "output is the same file as an input",
    );
    for (index, part) in parts.iter().enumerate() {
        let start = index * 1024 * 1024;
        assert_eq!(
            fs::read(part).unwrap(),
            bytes[start..bytes.len().min(start + 1024 * 1024)]
        );
    }
    fs::remove_file(&parts[2]).unwrap();
    let merged = root.join("must not be published.bin");
    refusal(
        run(
            root,
            &[
                "merge".into(),
                parts[0].clone().into_os_string(),
                "-o".into(),
                merged.clone().into_os_string(),
            ],
            None,
        ),
        1,
        "I/O operation failed",
    );
    assert!(!merged.exists());
    let stray = root.join("not-a-part.bin");
    fs::write(&stray, b"x").unwrap();
    refusal(
        run(
            root,
            &["merge".into(), stray.clone().into_os_string()],
            None,
        ),
        2,
        "Filename must match *.partN-total",
    );
    assert_eq!(fs::read(stray).unwrap(), b"x");
    let empty = root.join("empty.bin");
    fs::write(&empty, b"").unwrap();
    refusal(
        run(
            root,
            &["split".into(), empty.clone().into_os_string(), "1".into()],
            None,
        ),
        2,
        "Cannot split an empty file",
    );
    assert_eq!(fs::metadata(empty).unwrap().len(), 0);
    let text = root.join("not-an-image.txt");
    let thumbnail = root.join("thumb.jpg");
    fs::write(&text, b"definitely not a JPEG").unwrap();
    refusal(
        run(
            root,
            &[
                "thumbnail".into(),
                text.clone().into_os_string(),
                thumbnail.clone().into_os_string(),
            ],
            None,
        ),
        2,
        "Unsupported thumbnail media type",
    );
    assert!(!thumbnail.exists());
    assert_eq!(fs::read(text).unwrap(), b"definitely not a JPEG");
    assert_eq!(fs::read(&source).unwrap(), bytes);
    assert_eq!(fs::read(&parts[0]).unwrap(), bytes[..1024 * 1024]);
    assert_eq!(
        fs::read(&parts[1]).unwrap(),
        bytes[1024 * 1024..2 * 1024 * 1024]
    );
    assert!(!parts[2].exists());
    assert_eq!(fs::read(checksum).unwrap(), checksum_bytes);
    assert!(!root.join("logs").exists());
    assert!(fs::read_dir(root).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")
    }));
}

#[path = "common/private_tempfile.rs"]
mod private_tempfile;
