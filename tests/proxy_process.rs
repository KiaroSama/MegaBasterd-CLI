//! Independent CLI processes always reload the current private proxy document.
#![allow(clippy::unwrap_used)]

use std::{
    ffi::{OsStr, OsString},
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use megabasterd_cli::{
    platform::process,
    storage::{paths::Paths, proxies::ProxyStore},
    transfers::control::Control,
};

struct Fixture {
    _scratch: private_tempfile::TempDir,
    paths: Paths,
    temporary: PathBuf,
    cwd: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/proxy-process");
        fs::create_dir_all(&base).unwrap();
        let scratch = private_tempfile::tempdir_in(base).unwrap();
        let root = scratch.path().join("runtime with spaces");
        let paths = Paths {
            user: root.join("private user/native-v2"),
            logs: root.join("private logs"),
            output: root.join("output"),
            root,
        };
        let temporary = scratch.path().join("child temporary");
        let cwd = scratch.path().join("unrelated working directory");
        fs::create_dir_all(&temporary).unwrap();
        fs::create_dir(&cwd).unwrap();
        Self {
            _scratch: scratch,
            paths,
            temporary,
            cwd,
        }
    }

    fn run(&self, args: &[&OsStr]) {
        let mut command = Command::new(env!("CARGO_BIN_EXE_mb"));
        command.current_dir(&self.cwd).env_clear();
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
            command.env(key, &self.temporary);
        }
        command
            .env("MEGABASTERD_PROJECT_ROOT", &self.paths.root)
            .env("MEGABASTERD_USER_DIR", self.paths.user.parent().unwrap())
            .env("MEGABASTERD_LOG_DIR", &self.paths.logs)
            .env("HOOKMAKER_MAX_TEST_WORKERS", "1")
            .args(["--no-log-file", "proxy"])
            .args(args);
        let result = process::run_command(
            command,
            Duration::from_secs(5),
            16 * 1024,
            16 * 1024,
            &Control::new(),
            None,
        )
        .unwrap();
        assert!(
            result.status.success(),
            "proxy CLI failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(result.stdout.is_empty());
        let diagnostic = String::from_utf8(result.stderr).unwrap();
        assert!(!diagnostic.contains("Traceback") && !diagnostic.contains("panicked"));
        assert!(!self.paths.logs.exists());
    }

    fn store(&self) -> ProxyStore {
        ProxyStore::new(self.paths.proxies())
    }

    fn no_stage(&self) {
        assert_eq!(
            fs::read_dir(self.paths.proxies().parent().unwrap())
                .unwrap()
                .count(),
            2
        );
        assert!(self.paths.proxies().with_extension("json.lock").is_file());
    }
}

#[test]
fn independent_add_and_remove_commands_keep_every_unrelated_entry() {
    let fixture = Fixture::new();
    let words = |values: &[&str]| values.iter().map(OsString::from).collect::<Vec<_>>();
    let run = |values: &[&str]| {
        let args = words(values);
        fixture.run(&args.iter().map(OsString::as_os_str).collect::<Vec<_>>());
    };
    run(&["add", "http://keep.invalid:1", "http://drop.invalid:2"]);
    // Constructed before both child commands: list must still reload the latest commit.
    let stale_instance = fixture.store();
    run(&["add", "http://fresh.invalid:3"]);
    run(&["remove", "http://drop.invalid:2"]);
    assert_eq!(
        stale_instance.list().unwrap(),
        ["http://keep.invalid:1", "http://fresh.invalid:3"]
    );
    assert_eq!(
        fixture.store().list().unwrap(),
        ["http://keep.invalid:1", "http://fresh.invalid:3"]
    );
    fixture.no_stage();
}

#[test]
fn independent_import_and_add_commands_preserve_all_entries_from_a_spaced_input_path() {
    let fixture = Fixture::new();
    let listing = fixture.cwd.join("proxy input with  two spaces.txt");
    let bytes = b"http://i1.invalid:1\nhttp://i2.invalid:2\n";
    fs::write(&listing, bytes).unwrap();
    fixture.run(&[OsStr::new("import"), listing.as_os_str()]);
    fixture.run(&[OsStr::new("add"), OsStr::new("http://direct.invalid:9")]);
    assert_eq!(
        fixture.store().list().unwrap(),
        [
            "http://i1.invalid:1",
            "http://i2.invalid:2",
            "http://direct.invalid:9"
        ]
    );
    assert_eq!(fs::read(listing).unwrap(), bytes);
    fixture.no_stage();
}

#[path = "common/private_tempfile.rs"]
mod private_tempfile;
