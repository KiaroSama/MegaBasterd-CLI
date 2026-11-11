//! Rust-only CI driver. Each receipt is derived from actual libtest discovery and execution.
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::{BufRead, Read, Write};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_owned()
}

fn output(command: &mut Command) -> Result<Output> {
    let result = command.output()?;
    if !result.status.success() {
        eprint!(
            "{}{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        return Err(format!(
            "Command failed: {:?}: {}",
            command.get_program(),
            result.status
        )
        .into());
    }
    Ok(result)
}

/// Keep libtest's progress visible while retaining its exact output for the receipt.
fn test_output(command: &mut Command) -> Result<Output> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().ok_or("Missing test stdout")?;
    let mut stderr = child.stderr.take().ok_or("Missing test stderr")?;
    std::thread::scope(|scope| {
        let diagnostics = scope.spawn(move || -> std::io::Result<Vec<u8>> {
            let mut bytes = Vec::new();
            stderr.read_to_end(&mut bytes)?;
            Ok(bytes)
        });
        let mut captured = Vec::new();
        for line in std::io::BufReader::new(stdout).split(b'\n') {
            let line = line?;
            std::io::stdout().write_all(&line)?;
            std::io::stdout().write_all(b"\n")?;
            captured.extend_from_slice(&line);
            captured.push(b'\n');
        }
        Ok(Output {
            status: child.wait()?,
            stdout: captured,
            stderr: diagnostics
                .join()
                .map_err(|_| "Test stderr reader panicked")??,
        })
    })
}

fn cargo() -> Command {
    let mut command = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
    command.current_dir(root());
    command
}

fn private_test_process(command: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: only the child's creation mask changes; umask is async-signal-safe.
        unsafe {
            command.pre_exec(|| {
                libc::umask(0o077);
                Ok(())
            });
        }
    }
    #[cfg(not(unix))]
    let _ = command;
}

fn source_policy(directory: &Path) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            source_policy(&path)?;
        } else if matches!(
            path.extension().and_then(|x| x.to_str()),
            Some("py" | "ps1" | "cs" | "c" | "cpp" | "js" | "ts" | "sh")
        ) {
            return Err(format!("Non-Rust source remains: {}", path.display()).into());
        }
    }
    Ok(())
}

fn ledger() -> Result<Value> {
    let ledger: Value = serde_json::from_slice(&fs::read(
        root().join("tests/fixtures/contract_coverage.json"),
    )?)?;
    let modules = ledger["modules"]
        .as_array()
        .ok_or("Missing parity modules")?;
    if modules.len() != 164 {
        return Err("Baseline module count changed".into());
    }
    let mut identities = BTreeSet::new();
    let mut baseline = BTreeSet::new();
    for module in modules {
        for row in module["tests"].as_array().ok_or("Missing parity cases")? {
            let id = row["source_id"].as_str().ok_or("Missing case identity")?;
            if !identities.insert(id.to_owned()) {
                return Err(format!("Duplicate case: {id}").into());
            }
            baseline.insert(format!(
                "{id} {}",
                row["source_ast_sha256"]
                    .as_str()
                    .ok_or("Missing original assertion digest")?
            ));
            if row["status"] != "written_unexecuted"
                || row["targets"].as_array().is_none_or(Vec::is_empty)
            {
                return Err(format!("Unported baseline case: {id}").into());
            }
            for target in row["targets"].as_array().unwrap() {
                let path = target["path"].as_str().ok_or("Missing target path")?;
                if !(path.starts_with("src/") || path.starts_with("tests/"))
                    || path.contains("..")
                    || !path.ends_with(".rs")
                {
                    return Err("Invalid parity target path".into());
                }
                let content = fs::read_to_string(root().join(path))?.replace("\r\n", "\n");
                let digest = hex::encode(Sha256::digest(content.as_bytes()));
                if target["source_sha256"] != digest {
                    return Err(format!("Review parity mapping after changing {path}").into());
                }
                let name = target["test"].as_str().ok_or("Missing target name")?;
                if !content.contains(&format!("fn {name}(")) {
                    return Err(format!("Missing mapped test {path}::{name}").into());
                }
            }
        }
    }
    if identities.len() != 1416 {
        return Err("The 1,416 baseline cases must all remain accounted for".into());
    }
    let baseline = baseline
        .into_iter()
        .map(|line| line + "\n")
        .collect::<String>();
    // Frozen source IDs and ASTs from c4559ec: count preservation cannot hide substituted cases.
    if hex::encode(Sha256::digest(baseline.as_bytes()))
        != "c8c5794583b6e47deed64135b361ef141c7b67f432150974ccbc88cac3edaefd"
    {
        return Err("Original baseline identities or assertions were altered".into());
    }
    Ok(ledger)
}

fn verify() -> Result<()> {
    let revision = output(
        Command::new("git")
            .current_dir(root())
            .args(["rev-parse", "HEAD"]),
    )?;
    let revision = String::from_utf8(revision.stdout)?.trim().to_owned();
    let dirty = output(Command::new("git").current_dir(root()).args([
        "status",
        "--porcelain",
        "--untracked-files=no",
    ]))?;
    let clean = dirty.stdout.is_empty();
    if std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true")
        && (!clean || std::env::var("GITHUB_SHA").as_deref() != Ok(revision.as_str()))
    {
        return Err("CI must test the exact checked-out commit with a clean tracked tree".into());
    }
    for directory in ["src", "tests", "xtask", "tools"] {
        source_policy(&root().join(directory))?;
    }
    let ledger = ledger()?;
    let built = output(
        cargo()
            .args([
                "test",
                "--locked",
                "--workspace",
                "--all-targets",
                "--no-run",
                "--message-format=json-render-diagnostics",
            ])
            .stderr(Stdio::inherit()),
    )?;
    let mut harnesses = BTreeMap::new();
    for line in String::from_utf8(built.stdout)?.lines() {
        let Ok(message) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if message["reason"] != "compiler-artifact" || message["profile"]["test"] != true {
            continue;
        }
        if let (Some(executable), Some(source)) = (
            message["executable"].as_str(),
            message["target"]["src_path"].as_str(),
        ) {
            harnesses.insert(
                executable.to_owned(),
                Path::new(source)
                    .strip_prefix(root())?
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
    }
    if harnesses.len() < 100 {
        return Err("Native harness inventory unexpectedly shrank".into());
    }
    let work = root().join(".ci-work");
    fs::create_dir_all(work.join("runtime space/User"))?;
    fs::create_dir_all(work.join("results"))?;
    let mut passed = BTreeMap::<String, BTreeSet<String>>::new();
    let mut failures = Vec::new();
    let mut count = 0;
    for (index, (binary, source)) in harnesses.iter().enumerate() {
        let mut command = Command::new(binary);
        private_test_process(&mut command);
        command
            .current_dir(root())
            .env("MEGABASTERD_USER_DIR", work.join("runtime space/User"))
            .env("MEGABASTERD_LOG_DIR", work.join("runtime space/Logs"))
            .env("HOOKMAKER_MAX_TEST_WORKERS", "2")
            .env("NO_COLOR", "1");
        let media = work
            .join("media/bin")
            .join(format!("ffmpeg{}", std::env::consts::EXE_SUFFIX));
        if media.is_file() {
            command.env("MEGABASTERD_FFMPEG", media);
        }
        let listed = output(command.args(["--list", "--format=terse"]))?;
        let discovered: BTreeSet<_> = String::from_utf8(listed.stdout)?
            .lines()
            .filter_map(|x| x.strip_suffix(": test"))
            .map(str::to_owned)
            .collect();
        // Remove discovery arguments before execution.
        let mut run = Command::new(binary);
        private_test_process(&mut run);
        run.current_dir(root())
            .envs(command.get_envs().filter_map(|(k, v)| v.map(|v| (k, v))))
            .args(["--test-threads=2", "--color=never"]);
        println!("Running {source}: {} discovered tests", discovered.len());
        let result = test_output(&mut run)?;
        let text = String::from_utf8(result.stdout)?;
        let diagnostics = String::from_utf8_lossy(&result.stderr);
        fs::write(
            work.join(format!("results/{index}.txt")),
            format!("{source}\n{text}{diagnostics}"),
        )?;
        let actual: BTreeSet<_> = text
            .lines()
            .filter_map(|line| line.strip_prefix("test ")?.strip_suffix(" ... ok"))
            .map(str::to_owned)
            .collect();
        if !result.status.success() || actual != discovered {
            eprintln!("{source}: {}\n{text}{diagnostics}", result.status);
            failures.push(source.as_str());
            continue;
        }
        println!("{source}: {} passed", actual.len());
        count += actual.len();
        if !actual.is_empty() {
            passed.insert(source.clone(), actual);
        }
    }
    if !failures.is_empty() {
        return Err(format!(
            "Native tests failed or were ignored in: {}",
            failures.join(", ")
        )
        .into());
    }
    let platform = std::env::consts::OS;
    let mut cases = Vec::new();
    for module in ledger["modules"].as_array().unwrap() {
        for row in module["tests"].as_array().unwrap() {
            let mut applicable = 0;
            for target in row["targets"].as_array().unwrap() {
                if !target["required_platforms"]
                    .as_array()
                    .ok_or("Missing platform scope")?
                    .iter()
                    .any(|p| p == platform)
                {
                    continue;
                }
                applicable += 1;
                let path = target["path"].as_str().unwrap();
                let suite = if path.starts_with("src/") {
                    "src/lib.rs"
                } else {
                    path
                };
                let name = target["harness_test"]
                    .as_str()
                    .ok_or("Missing harness test")?;
                if !passed.get(suite).is_some_and(|names| names.contains(name)) {
                    return Err(format!(
                        "Parity case {} requires unexecuted {suite}::{name}",
                        row["source_id"]
                    )
                    .into());
                }
            }
            cases.push(json!({"source_id":row["source_id"],"status":if applicable>0 {"passed"} else {"other_platform"}}));
        }
    }
    let git = output(
        Command::new("git")
            .current_dir(root())
            .args(["rev-parse", "HEAD"]),
    )?;
    if String::from_utf8(git.stdout.clone())?.trim() != revision {
        return Err("Checkout changed while tests executed".into());
    }
    if std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true") {
        let dirty = output(Command::new("git").current_dir(root()).args([
            "status",
            "--porcelain",
            "--untracked-files=no",
        ]))?;
        if !dirty.stdout.is_empty() {
            return Err("Tracked sources changed during CI tests".into());
        }
    }
    let receipt = json!({"schema_version":1,"commit":String::from_utf8(git.stdout)?.trim(),"os":platform,"architecture":std::env::consts::ARCH,
        "working_tree_clean":clean,"native_tests":count,"baseline_cases":cases.len(),"cases":cases});
    let escape = |value: &str| {
        value
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
    };
    let skipped = cases
        .iter()
        .filter(|case| case["status"] == "other_platform")
        .count();
    let mut junit = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuite name=\"Migrated source contracts ({platform})\" tests=\"1416\" failures=\"0\" skipped=\"{skipped}\">\n"
    );
    for case in &cases {
        let identity = case["source_id"].as_str().ok_or("Missing receipt case")?;
        junit.push_str(&format!("<testcase name=\"{}\">", escape(identity)));
        if case["status"] == "other_platform" {
            junit.push_str("<skipped message=\"Not applicable on this runner\"/>");
        }
        junit.push_str("</testcase>\n");
    }
    junit.push_str("</testsuite>\n");
    fs::write(work.join("source-contracts.xml"), junit)?;
    fs::write(
        work.join("receipt.json"),
        serde_json::to_vec_pretty(&receipt)?,
    )?;
    println!("{count} native tests passed; all 1,416 baseline cases accounted for ({platform})");
    Ok(())
}

fn package() -> Result<()> {
    let target = std::env::var("CARGO_BUILD_TARGET").ok();
    let mut directory = root().join("target");
    if let Some(target) = &target {
        directory.push(target);
    }
    directory.push("release");
    let destination = root().join("dist");
    fs::create_dir_all(&destination)?;
    for name in ["mb", "mbcli", "megabasterd-cli"] {
        let name = format!("{name}{}", std::env::consts::EXE_SUFFIX);
        fs::copy(directory.join(&name), destination.join(name))?;
    }
    for name in ["LICENSE", "ATTRIBUTION.md", "README.md"] {
        fs::copy(root().join(name), destination.join(name))?;
    }
    let metadata = output(cargo().args(["metadata", "--locked", "--format-version=1"]))?;
    let metadata: Value = serde_json::from_slice(&metadata.stdout)?;
    let notices = destination.join("third-party");
    fs::create_dir_all(&notices)?;
    let mut index = Vec::new();
    for package in metadata["packages"]
        .as_array()
        .ok_or("Missing dependency packages")?
    {
        if package["source"].is_null() {
            continue;
        }
        let name = format!(
            "{}-{}",
            package["name"].as_str().ok_or("Missing package name")?,
            package["version"]
                .as_str()
                .ok_or("Missing package version")?
        );
        let directory = Path::new(
            package["manifest_path"]
                .as_str()
                .ok_or("Missing dependency manifest")?,
        )
        .parent()
        .ok_or("Missing dependency root")?;
        let mut files = Vec::new();
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            let filename = path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .to_ascii_lowercase();
            if [
                "license",
                "licence",
                "copying",
                "notice",
                "copyright",
                "authors",
                "unlicense",
            ]
            .iter()
            .any(|prefix| filename.starts_with(prefix))
            {
                notice_files(directory, &path, &notices.join(&name), &mut files)?;
            }
        }
        if let Some(license_file) = package["license_file"].as_str() {
            let path = directory.join(license_file);
            if path.is_file() {
                notice_files(directory, &path, &notices.join(&name), &mut files)?;
            }
        }
        files.sort_by_key(|value| value["path"].as_str().unwrap_or_default().to_owned());
        files.dedup();
        if files.is_empty() {
            let supplements = root().join("licenses/third-party").join(&name);
            if supplements.is_dir() {
                notice_files(&supplements, &supplements, &notices.join(&name), &mut files)?;
            }
        }
        if files.is_empty() {
            return Err(format!("Dependency {name} has no packaged license text").into());
        }
        index.push(json!({"package":name,"license":package["license"],"source":package["source"],"files":files}));
    }
    fs::write(
        notices.join("index.json"),
        serde_json::to_vec_pretty(&index)?,
    )?;
    fs::copy(
        root().join("licenses/third-party/provenance.json"),
        notices.join("supplemental-provenance.json"),
    )?;
    let source = output(cargo().args([
        "package",
        "--locked",
        "--allow-dirty",
        "--no-verify",
        "-p",
        "megabasterd-cli",
    ]))?;
    print!("{}", String::from_utf8_lossy(&source.stderr));
    fs::copy(
        root().join("target/package/megabasterd-cli-2.0.0.crate"),
        destination.join("megabasterd-cli-2.0.0.crate"),
    )?;
    let signed = std::env::var("MBCLI_SIGN_RELEASE").as_deref() == Ok("1");
    let signing_script = root().join(".github/scripts/Sign-Release.ps1");
    if signed {
        output(
            Command::new("pwsh")
                .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-File"])
                .arg(&signing_script)
                .args(["-Stage", "Binaries", "-Directory"])
                .arg(&destination),
        )?;
    }
    let mut hashes = String::new();
    let mut files = Vec::new();
    distribution_files(&destination, &mut files)?;
    files.sort();
    for path in files {
        if path.is_file() && path.file_name().unwrap() != "SHA256SUMS" {
            hashes.push_str(&format!(
                "{}  {}\n",
                hex::encode(Sha256::digest(fs::read(&path)?)),
                path.strip_prefix(&destination)?
                    .to_string_lossy()
                    .replace('\\', "/")
            ));
        }
    }
    fs::write(destination.join("SHA256SUMS"), hashes)?;
    // Actions' outer ZIP normalizes Unix permissions. A tar payload retains the
    // executable modes of the actual native aliases across artifact download.
    let target = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "x86_64-unknown-linux-gnu",
        ("windows", "x86_64") => "x86_64-pc-windows-msvc",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        ("macos", "aarch64") => "aarch64-apple-darwin",
        _ => return Err("Unsupported native distribution target".into()),
    };
    let archives = root().join(".ci-work/distribution");
    fs::create_dir_all(&archives)?;
    let name = format!("megabasterd-cli-2.0.0-{target}.tar.gz");
    let archive = archives.join(&name);
    output(
        Command::new("tar")
            .arg("-czf")
            .arg(&archive)
            .arg("-C")
            .arg(&destination)
            .arg("."),
    )?;
    fs::write(
        archives.join(format!("{name}.sha256")),
        format!(
            "{}  {name}\n",
            hex::encode(Sha256::digest(fs::read(archive)?))
        ),
    )?;
    if signed {
        output(
            Command::new("pwsh")
                .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-File"])
                .arg(signing_script)
                .args(["-Stage", "Archives", "-Directory"])
                .arg(&archives),
        )?;
    }
    Ok(())
}

fn distribution_files(directory: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_symlink() {
            return Err("Linked distribution file".into());
        }
        if path.is_dir() {
            distribution_files(&path, files)?;
        } else if path.is_file() {
            files.push(path);
        }
    }
    Ok(())
}

fn notice_files(
    base: &Path,
    source: &Path,
    destination: &Path,
    files: &mut Vec<Value>,
) -> Result<()> {
    if source.is_symlink() {
        return Err("Linked dependency notice".into());
    }
    if source.is_dir() {
        for entry in fs::read_dir(source)? {
            notice_files(base, &entry?.path(), destination, files)?;
        }
    } else if source.is_file() {
        let relative = source.strip_prefix(base)?;
        let target = destination.join(relative);
        fs::create_dir_all(target.parent().unwrap())?;
        let content = fs::read(source)?;
        fs::write(target, &content)?;
        files.push(json!({"path":relative.to_string_lossy().replace('\\', "/"),"sha256":hex::encode(Sha256::digest(&content))}));
    }
    Ok(())
}

fn media() -> Result<()> {
    let work = root().join(".ci-work/media");
    let bin = work.join("bin");
    fs::create_dir_all(&bin)?;
    let executable = bin.join(format!("ffmpeg{}", std::env::consts::EXE_SUFFIX));
    if !executable.is_file() {
        let (url, hash, name) = if cfg!(windows) {
            (
                "https://www.gyan.dev/ffmpeg/builds/packages/ffmpeg-9.0.2-essentials_build.zip",
                "60f467265b1e312373dbcd92200c2618a74850f98d3d078e94296bb3fa2047ba",
                "media.zip",
            )
        } else {
            (
                "https://ffmpeg.org/releases/ffmpeg-9.0.2.tar.xz",
                "8c3850283eb25fa026482078a04051e0be17347b09ef81a0849bec15a96e002e",
                "media.tar.xz",
            )
        };
        let archive = work.join(name);
        output(
            Command::new("curl")
                .args(["--fail", "--location", "--max-time", "180", "--output"])
                .arg(&archive)
                .arg(url),
        )?;
        if hex::encode(Sha256::digest(fs::read(&archive)?)) != hash {
            return Err("Media prerequisite checksum mismatch".into());
        }
        output(
            Command::new("tar")
                .arg("-xf")
                .arg(&archive)
                .arg("-C")
                .arg(&work),
        )?;
        if cfg!(windows) {
            let source = work.join("ffmpeg-9.0.2-essentials_build/bin");
            for name in ["ffmpeg.exe", "ffprobe.exe"] {
                fs::copy(source.join(name), bin.join(name))?;
            }
        } else {
            let configure = work.join("ffmpeg-9.0.2/configure");
            output(Command::new("sh").current_dir(&bin).arg(configure).args([
                "--disable-autodetect",
                "--disable-everything",
                "--disable-network",
                "--disable-doc",
                "--disable-debug",
                "--disable-ffplay",
                "--disable-avdevice",
                "--disable-x86asm",
                "--disable-shared",
                "--enable-static",
                "--enable-decoder=h264,vp8",
                "--enable-parser=h264,vp8",
                "--enable-demuxer=mov,matroska",
                "--enable-encoder=mjpeg",
                "--enable-muxer=image2pipe",
                "--enable-protocol=fd,pipe",
                "--enable-filter=scale",
            ]))?;
            output(
                Command::new("make")
                    .current_dir(&bin)
                    .args(["-j2", "ffmpeg", "ffprobe"]),
            )?;
        }
    }
    for name in ["ffmpeg", "ffprobe"] {
        let binary = bin.join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
        let version = output(Command::new(&binary).arg("-version"))?;
        if !String::from_utf8(version.stdout)?.starts_with(&format!("{name} version 9.0.2")) {
            return Err("Media version differs".into());
        }
        let protocols = output(Command::new(binary).args(["-hide_banner", "-protocols"]))?;
        if !String::from_utf8(protocols.stdout)?
            .lines()
            .any(|line| line.trim() == "fd")
        {
            return Err("Seekable media input unavailable".into());
        }
    }
    if let Some(path) = std::env::var_os("GITHUB_ENV") {
        writeln!(
            fs::OpenOptions::new().append(true).open(path)?,
            "MEGABASTERD_FFMPEG={}",
            executable.display()
        )?;
    }
    println!("Verified FFmpeg/ffprobe 9.0.2: {}", executable.display());
    Ok(())
}

fn main() -> Result<()> {
    match std::env::args().nth(1).as_deref() {
        Some("verify") => verify(),
        Some("package") => package(),
        Some("media") => media(),
        _ => Err("Usage: cargo xtask <verify|package|media>".into()),
    }
}
