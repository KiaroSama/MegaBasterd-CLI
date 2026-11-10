#![allow(clippy::unwrap_used)]

use megabasterd_cli::{platform::process, transfers::control::Control};
use std::{fs, path::Path, process::Command, time::Duration};

fn run(binary: &Path, cwd: &Path, home: &Path, arguments: &[&str]) -> process::ProcessOutput {
    let mut command = Command::new(binary);
    command.current_dir(cwd).env_clear();
    #[cfg(windows)]
    for key in ["SystemRoot", "WINDIR", "PATHEXT"] {
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
        command.env(key, home);
    }
    command
        .env("PATH", home.join("empty executable search path"))
        .env("NO_COLOR", "1")
        .env("HOOKMAKER_MAX_TEST_WORKERS", "1")
        .args(arguments);
    process::run_command(
        command,
        Duration::from_secs(5),
        64 * 1024,
        16 * 1024,
        &Control::new(),
        None,
    )
    .unwrap()
}

#[test]
fn relocated_native_aliases_need_no_python_cargo_source_cwd_or_project_root_override() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/distribution");
    fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    let release = scratch.path().join("native release with spaces");
    let cwd = scratch.path().join("unrelated caller with spaces");
    let home = scratch.path().join("isolated runtime");
    for path in [&release, &cwd, &home] {
        fs::create_dir(path).unwrap();
    }
    fs::create_dir(home.join("empty executable search path")).unwrap();
    for (name, original) in [
        ("mb", env!("CARGO_BIN_EXE_mb")),
        ("mbcli", env!("CARGO_BIN_EXE_mbcli")),
        ("megabasterd-cli", env!("CARGO_BIN_EXE_megabasterd-cli")),
    ] {
        let suffix = if cfg!(windows) { ".exe" } else { "" };
        let binary = release.join(format!("{name}{suffix}"));
        fs::copy(original, &binary).unwrap();
        let version = run(&binary, &cwd, &home, &["--version"]);
        assert_eq!(version.status.code(), Some(0));
        assert_eq!(
            String::from_utf8(version.stdout).unwrap(),
            format!("mb {}\n", env!("CARGO_PKG_VERSION"))
        );
        assert!(version.stderr.is_empty());
        let help = run(&binary, &cwd, &home, &["--help"]);
        assert_eq!(help.status.code(), Some(0));
        assert!(help.stderr.is_empty());
        let help = String::from_utf8(help.stdout).unwrap();
        assert!(help.contains("Usage:") && help.contains("--help") && help.contains("download"));
        assert!(!help.contains('\x1b'));
        let empty = run(&binary, &cwd, &home, &[]);
        assert_eq!(empty.status.code(), Some(2));
        assert!(empty.stdout.is_empty());
        assert_eq!(
            String::from_utf8(empty.stderr).unwrap(),
            "[ERROR] No command provided. Use mb --help in noninteractive mode.\n"
        );
        let setting = run(
            &binary,
            &cwd,
            &home,
            &["--no-log-file", "config", "get", "max_workers"],
        );
        assert_eq!(setting.status.code(), Some(0));
        assert_eq!(setting.stdout, b"8\n");
        assert!(setting.stderr.is_empty());
        let path = run(&binary, &cwd, &home, &["--no-log-file", "config", "path"]);
        assert_eq!(path.status.code(), Some(0));
        assert!(path.stderr.is_empty());
        let rendered = String::from_utf8(path.stdout).unwrap();
        let actual = Path::new(rendered.trim_end());
        assert!(actual.ends_with("User/native-v2/Config/config.json"));
        assert_eq!(
            fs::canonicalize(actual.ancestors().nth(4).unwrap()).unwrap(),
            fs::canonicalize(&release).unwrap()
        );
    }
    assert!(fs::read_dir(&cwd).unwrap().next().is_none());
    assert!(!release.join("src").exists() && !release.join("Cargo.toml").exists());
    assert!(!release.join("Logs").exists());
}

#[test]
fn packaged_launcher_delegates_without_raw_transcripts_or_late_file_scrubbing() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let launchers = fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| extension.eq_ignore_ascii_case("ps1"))
        })
        .collect::<Vec<_>>();
    assert_eq!(launchers, [root.join("Run.ps1")]);
    assert!(launchers[0].is_file());
    let launcher = include_str!("../tools/launcher/Run.Native.ps1");
    let lower = launcher.to_ascii_lowercase();
    for forbidden in [
        "start-transcript",
        "stop-transcript",
        "protect-transcriptfile",
        "get-content -literalpath $path -raw",
    ] {
        assert!(
            !lower.contains(forbidden),
            "unsafe launcher primitive: {forbidden}"
        );
    }
    let invoke = launcher.find("& $Binary @CliArgs").unwrap();
    assert!(
        launcher
            .find("$PSNativeCommandUseErrorActionPreference = $false")
            .unwrap()
            < invoke
    );
    assert!(!launcher.contains("$global:PSNativeCommandUseErrorActionPreference"));
    assert!(launcher.contains("$Code = $LASTEXITCODE"));
    assert!(launcher.contains("exit $Code"));
    let package = include_str!("../tools/package/runtime.py");
    assert!(package.contains("entries[\"Run.ps1\"] = project / \"tools/launcher/Run.Native.ps1\""));
}

#[test]
fn distribution_inputs_keep_the_real_gpl_grant_historical_mit_and_unicode_notices() {
    let license = include_str!("../LICENSE").replace("\r\n", "\n");
    assert!(license.starts_with("GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007"));
    assert!(
        license.contains("Corresponding Source") && license.contains("Conveying Non-Source Forms")
    );
    let attribution = include_str!("../ATTRIBUTION.md");
    assert!(
        attribution.contains("GPL-3.0-or-later")
            && attribution.contains("matching Corresponding Source")
    );
    assert!(
        attribution.contains("Their notice is preserved")
            && attribution.contains("MIT-historical.txt")
    );
    let historical = include_str!("../licenses/MIT-historical.txt").replace("\r\n", "\n");
    assert!(historical.starts_with("MIT License\n"));
    assert!(historical.contains("Copyright (c) 2026 Kiaro Sama"));
    assert!(
        historical
            .contains("The above copyright notice and this permission notice shall be included")
    );
    let unicode = include_str!("../licenses/Unicode-3.0.txt").replace("\r\n", "\n");
    assert!(unicode.starts_with("UNICODE LICENSE V3\n"));
    assert!(unicode.contains("Copyright") && unicode.contains("Unicode, Inc."));
    assert!(unicode.contains("this copyright and permission notice appear"));
}
