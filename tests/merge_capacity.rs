// SPDX-License-Identifier: GPL-3.0-or-later
//! Descriptor limits are changed only in owned children, never in the test process.
#![cfg(unix)]
#![allow(clippy::unwrap_used)]

use std::{fs, os::unix::process::CommandExt, path::Path, process::Command, time::Duration};

use megabasterd_cli::{platform::process, transfers::control::Control};
use sha1::{Digest, Sha1};

fn limits() -> libc::rlimit {
    let mut limits = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: the output has the native layout and remains live through the call.
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limits) },
        0
    );
    limits
}

#[test]
fn merge_retains_pinned_inputs_with_a_low_soft_limit_and_refuses_an_insufficient_hard_limit() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let base = root.join(".ci-work/merge-capacity");
    fs::create_dir_all(&base).unwrap();
    let scratch = private_tempfile::tempdir_in(base).unwrap();
    let before = limits();
    assert!(
        before.rlim_max >= 256,
        "native merge fixture requires hard limit >=256"
    );
    for (count, hard, allowed) in [(96, 64, false), (96, 256, true), (1, 64, true)] {
        let expected: Vec<u8> = (0..count).map(|index| index as u8).collect();
        let directory = scratch.path().join(format!("parts-{count}-hard-{hard}"));
        fs::create_dir(&directory).unwrap();
        for (index, byte) in expected.iter().enumerate() {
            fs::write(
                directory.join(format!("input.bin.part{}-{count}", index + 1)),
                [*byte],
            )
            .unwrap();
        }
        let checksum = format!("{}\n", hex::encode(Sha1::digest(&expected)));
        fs::write(directory.join("input.bin.sha1"), &checksum).unwrap();
        let output = directory.join("merged.bin");
        let mut command = Command::new(env!("CARGO_BIN_EXE_mb"));
        command.current_dir(&directory).env_clear();
        for key in ["PATH", "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        for key in ["HOME", "TMP", "TEMP", "TMPDIR"] {
            command.env(key, scratch.path());
        }
        command
            .env("MEGABASTERD_PROJECT_ROOT", &directory)
            .env("MEGABASTERD_USER_DIR", scratch.path().join("private user"))
            .env("NO_COLOR", "1")
            .env("HOOKMAKER_MAX_TEST_WORKERS", "1")
            .args(["--no-log-file", "merge"])
            .arg(directory.join(format!("input.bin.part1-{count}")))
            .arg("-o")
            .arg(&output)
            .arg("--delete-parts");
        let child_limits = libc::rlimit {
            rlim_cur: 64,
            rlim_max: hard,
        };
        // SAFETY: this child-only hook calls one async-signal-safe syscall with captured scalars.
        unsafe {
            command.pre_exec(move || {
                if libc::setrlimit(libc::RLIMIT_NOFILE, &child_limits) == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
        let result = process::run_command(
            command,
            Duration::from_secs(8),
            16 * 1024,
            16 * 1024,
            &Control::new(),
            None,
        )
        .unwrap();
        assert_eq!(result.status.code(), Some(if allowed { 0 } else { 1 }));
        let text = String::from_utf8(result.stderr).unwrap();
        assert!(!text.contains("panicked") && !text.contains("Traceback"));
        assert!(result.stdout.is_empty());
        if allowed {
            assert_eq!(fs::read(&output).unwrap(), expected);
            let names: Vec<_> = fs::read_dir(&directory)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect();
            assert_eq!(names.len(), 2);
            assert!(names.contains(&"merged.bin".into()));
            assert!(names.contains(&"merged.bin.mbclaim".into()));
        } else {
            assert!(text.contains("open-file limit") && text.contains("larger parts"));
            assert!(!output.exists());
            assert_eq!(
                fs::read_to_string(directory.join("input.bin.sha1")).unwrap(),
                checksum
            );
            assert_eq!(fs::read_dir(&directory).unwrap().count(), count + 1);
            for (index, byte) in expected.iter().enumerate() {
                assert_eq!(
                    fs::read(directory.join(format!("input.bin.part{}-{count}", index + 1)))
                        .unwrap(),
                    [*byte]
                );
            }
        }
        let after = limits();
        assert_eq!(
            (after.rlim_cur, after.rlim_max),
            (before.rlim_cur, before.rlim_max)
        );
    }
}

#[path = "common/private_tempfile.rs"]
mod private_tempfile;
