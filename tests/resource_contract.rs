//! Representative transfer preparation and local-file costs, not network throughput.
#![allow(clippy::unwrap_used)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

use megabasterd_cli::{
    platform::{process, secure_files::OutputDirectory},
    services::splitter::{merge_parts, split_file},
    terminal::logging::Logger,
    transfers::{control::Control, upload::source_hash},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha1::Sha1;
use sha2::{Digest, Sha256};

const CASE: &str =
    "representative_source_hash_and_local_files_record_real_bounded_resource_samples";
const MODE: &str = "MB_RESOURCE_CHILD";
const SOURCE: &str = "MB_RESOURCE_SOURCE";
const OUTPUT: &str = "MB_RESOURCE_OUTPUT";
const SIZES: [usize; 2] = [1024 * 1024 + 17, 16 * 1024 * 1024 + 17];
const METRICS: [&str; 5] = [
    "hash_ns",
    "split_ns",
    "merge_ns",
    "wall_ns",
    "peak_rss_bytes",
];

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Sample {
    schema_version: u32,
    engine: String,
    bytes: u64,
    sha256: String,
    sha1: String,
    hash_ns: u64,
    split_ns: u64,
    merge_ns: u64,
    peak_rss_bytes: u64,
    runtime: String,
}

#[test]
fn resource_samples_reject_duplicate_missing_unknown_and_noninteger_fields() {
    let valid = r#"{"schema_version":1,"engine":"python-source","bytes":17,"sha256":"abc","sha1":"def","hash_ns":1,"split_ns":2,"merge_ns":3,"peak_rss_bytes":4,"runtime":"CPython 3.14.0"}"#;
    assert!(serde_json::from_str::<Sample>(valid).is_ok());
    for invalid in [
        valid.replacen("\"hash_ns\":1", "\"hash_ns\":1,\"hash_ns\":2", 1),
        valid.replacen("\"hash_ns\":1,", "", 1),
        valid.replacen("\"hash_ns\":1", "\"hash_ns\":1,\"other\":2", 1),
        valid.replacen("\"hash_ns\":1", "\"hash_ns\":1.5", 1),
        valid.replacen("\"hash_ns\":1", "\"hash_ns\":-1", 1),
        valid.replacen("\"hash_ns\":1", "\"hash_ns\":true", 1),
        valid.replacen("\"hash_ns\":1", "\"hash_ns\":\"1\"", 1),
    ] {
        assert!(serde_json::from_str::<Sample>(&invalid).is_err());
    }
}

fn digest(path: &Path) -> (String, String) {
    let mut file = File::open(path).unwrap();
    let mut sha256 = Sha256::new();
    let mut sha1 = Sha1::new();
    let mut buffer = vec![0; 1024 * 1024];
    loop {
        let count = file.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        sha256.update(&buffer[..count]);
        sha1.update(&buffer[..count]);
    }
    (hex::encode(sha256.finalize()), hex::encode(sha1.finalize()))
}

fn owned(path: PathBuf, base: &Path) -> PathBuf {
    let path = std::path::absolute(path).unwrap();
    let base = std::path::absolute(base).unwrap();
    let mut current = base.clone();
    for component in path.strip_prefix(&base).unwrap().components() {
        assert!(matches!(component, std::path::Component::Normal(_)));
        current.push(component);
        let metadata = fs::symlink_metadata(&current).unwrap();
        assert!(!metadata.file_type().is_symlink());
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            assert_eq!(metadata.file_attributes() & 0x400, 0);
        }
    }
    assert!(
        path.canonicalize()
            .unwrap()
            .starts_with(base.canonicalize().unwrap())
    );
    path
}

#[cfg(unix)]
fn peak_rss() -> u64 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: getrusage writes this correctly sized output and retains no pointer.
    assert_eq!(
        unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) },
        0
    );
    // SAFETY: the successful call initialized the complete rusage structure.
    let peak = u64::try_from(unsafe { usage.assume_init() }.ru_maxrss).unwrap();
    peak.checked_mul(if cfg!(target_os = "macos") { 1 } else { 1024 })
        .unwrap()
}

#[cfg(windows)]
fn peak_rss() -> u64 {
    #[repr(C)]
    struct Counters {
        cb: u32,
        faults: u32,
        peak: usize,
        working: usize,
        remaining: [usize; 6],
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> *mut std::ffi::c_void;
        fn K32GetProcessMemoryInfo(
            process: *mut std::ffi::c_void,
            counters: *mut Counters,
            size: u32,
        ) -> i32;
    }
    let mut counters = Counters {
        cb: std::mem::size_of::<Counters>() as u32,
        faults: 0,
        peak: 0,
        working: 0,
        remaining: [0; 6],
    };
    let size = counters.cb;
    // SAFETY: pseudo-handle needs no close; the correctly sized output stays live for the call.
    assert_ne!(
        unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), &mut counters, size) },
        0
    );
    counters.peak as u64
}

fn native(source: &Path, directory: &Path) -> Value {
    assert!(SIZES.contains(&(fs::metadata(source).unwrap().len() as usize)));
    assert_eq!(fs::read_dir(directory).unwrap().count(), 0);
    let anchor = OutputDirectory::open(source.parent().unwrap()).unwrap();
    let mut input = anchor.open_read(source.file_name().unwrap()).unwrap();
    let start = Instant::now();
    let identity = source_hash(&mut input, &Control::new()).unwrap();
    let hash_ns = start.elapsed().as_nanos() as u64;
    let start = Instant::now();
    let split = split_file(source, 4, Some(directory), false, None).unwrap();
    let split_ns = start.elapsed().as_nanos() as u64;
    let start = Instant::now();
    merge_parts(
        split.parts.last().unwrap(),
        Some(&directory.join("merged.bin")),
        true,
        false,
        false,
        None,
    )
    .unwrap();
    let merge_ns = start.elapsed().as_nanos() as u64;
    json!({"schema_version":1,"engine":"rust-native","bytes":split.total_bytes,
        "sha256":identity.rsplit_once(':').unwrap().1,"sha1":split.sha1,
        "hash_ns":hash_ns,"split_ns":split_ns,"merge_ns":merge_ns,
        "peak_rss_bytes":peak_rss(),"runtime":format!("Rust native test harness; debug_assertions={}",cfg!(debug_assertions))})
}

fn run(
    mut command: Command,
    scratch: &Path,
    native: bool,
    source: &Path,
    directory: &Path,
) -> (process::ProcessOutput, u64) {
    command.current_dir(scratch).env_clear();
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
        "TEMP",
        "TMP",
        "TMPDIR",
    ] {
        command.env(key, scratch);
    }
    command
        .env("NO_COLOR", "1")
        .env("HOOKMAKER_MAX_TEST_WORKERS", "1");
    if native {
        command
            .env(MODE, "native")
            .env(SOURCE, source)
            .env(OUTPUT, directory);
    }
    let start = Instant::now();
    let result = process::run_command(
        command,
        Duration::from_secs(30),
        16 * 1024,
        16 * 1024,
        &Control::new(),
        None,
    )
    .unwrap();
    (result, start.elapsed().as_nanos() as u64)
}

fn sample(
    engine: &str,
    directory: &Path,
    size: usize,
    expected: &(String, String),
    wall: u64,
) -> Value {
    let path = directory.join("sample.json");
    assert!(fs::metadata(&path).unwrap().len() <= 4096);
    let result: Sample = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert_eq!(result.schema_version, 1);
    assert_eq!(result.engine, engine);
    assert_eq!(result.bytes, size as u64);
    assert_eq!(result.sha256, expected.0);
    assert_eq!(result.sha1, expected.1);
    let runtime = result.runtime.as_str();
    if engine == "rust-native" {
        assert_eq!(
            runtime,
            format!(
                "Rust native test harness; debug_assertions={}",
                cfg!(debug_assertions)
            )
        );
    } else {
        let version = runtime.strip_prefix("CPython ").unwrap();
        assert!(!version.is_empty() && version.len() <= 30);
        assert!(
            version
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.')
        );
    }
    for elapsed in [result.hash_ns, result.split_ns, result.merge_ns] {
        assert!((1..30_000_000_000).contains(&elapsed));
    }
    assert!((1..512 * 1024 * 1024).contains(&result.peak_rss_bytes));
    assert!(wall > 0);
    assert_eq!(digest(&directory.join("merged.bin")), *expected);
    let count = size.div_ceil(4 * 1024 * 1024);
    let mut names = BTreeSet::from([
        "sample.json".to_owned(),
        "merged.bin".to_owned(),
        "input.bin.sha1".to_owned(),
    ]);
    for index in 1..=count {
        let name = format!("input.bin.part{index}-{count}");
        assert_eq!(
            fs::metadata(directory.join(&name)).unwrap().len(),
            (size - (index - 1) * 4 * 1024 * 1024).min(4 * 1024 * 1024) as u64
        );
        names.insert(name);
    }
    assert_eq!(
        fs::read_to_string(directory.join("input.bin.sha1")).unwrap(),
        format!("{}\n", expected.1)
    );
    if engine == "rust-native" {
        let claims: Vec<_> = names
            .iter()
            .filter(|name| *name != "sample.json")
            .map(|name| format!("{name}.mbclaim"))
            .collect();
        names.extend(claims);
    }
    let actual: BTreeSet<_> = fs::read_dir(directory)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            assert!(entry.file_type().unwrap().is_file());
            entry.file_name().into_string().unwrap()
        })
        .collect();
    assert_eq!(actual, names);
    let mut result = serde_json::to_value(result).unwrap();
    result["wall_ns"] = wall.into();
    result
}

fn summarize(samples: &[Value]) -> Value {
    let mut summary = serde_json::Map::new();
    for metric in METRICS {
        let mut values: Vec<_> = samples
            .iter()
            .map(|sample| sample[metric].as_u64().unwrap())
            .collect();
        assert_eq!(values.len(), 3);
        values.sort_unstable();
        summary.insert(
            metric.into(),
            json!({"min":values[0],"median":values[1],"max":values[2]}),
        );
    }
    summary.into()
}

#[test]
fn representative_source_hash_and_local_files_record_real_bounded_resource_samples() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let base = root.join(".ci-work/resource-contract");
    if std::env::var_os(MODE).is_some() {
        assert_eq!(std::env::var(MODE).unwrap(), "native");
        let source = owned(std::env::var_os(SOURCE).unwrap().into(), &base);
        let directory = owned(std::env::var_os(OUTPUT).unwrap().into(), &base);
        let logger = Logger::start(&directory.parent().unwrap().join("native logs")).unwrap();
        let result = native(&source, &directory);
        let mut file = File::create_new(directory.join("sample.json")).unwrap();
        serde_json::to_writer(&mut file, &result).unwrap();
        writeln!(file).unwrap();
        logger.finish(0).unwrap();
        return;
    }
    let commit = String::from_utf8(
        Command::new("git")
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_owned();
    assert!(commit.len() == 40 && commit.bytes().all(|byte| byte.is_ascii_hexdigit()));
    fs::create_dir_all(&base).unwrap();
    let scratch = private_tempfile::tempdir_in(&base).unwrap();
    let mut workloads = Vec::new();
    for size in SIZES {
        let work = scratch.path().join(size.to_string());
        fs::create_dir(&work).unwrap();
        let source = work.join("input.bin");
        let mut input = File::create_new(&source).unwrap();
        let block: Vec<u8> = (0..64 * 1024).map(|index| (index % 251) as u8).collect();
        for chunk in (0..size).step_by(block.len()) {
            input
                .write_all(&block[..block.len().min(size - chunk)])
                .unwrap();
        }
        input.sync_all().unwrap();
        drop(input);
        let expected = digest(&source);
        let mut samples = BTreeMap::<&str, Vec<Value>>::new();
        for _ in 0..3 {
            let directory = private_tempfile::tempdir_in(&work).unwrap();
            let mut command = Command::new(std::env::current_exe().unwrap());
            command.args(["--exact", CASE, "--test-threads=1", "--color=never"]);
            let (result, wall) = run(command, scratch.path(), true, &source, directory.path());
            assert_eq!(result.status.code(), Some(0));
            assert!(result.stderr.is_empty());
            assert!(
                std::str::from_utf8(&result.stdout)
                    .unwrap()
                    .contains("1 passed")
            );
            samples.entry("rust-native").or_default().push(sample(
                "rust-native",
                directory.path(),
                size,
                &expected,
                wall,
            ));
            assert_eq!(digest(&source), expected);
        }
        let native_summary = summarize(&samples["rust-native"]);
        workloads.push(json!({"bytes":size,"samples":samples,"native_summary":native_summary}));
    }
    let report = json!({"schema_version":1,"baseline_commit":"c4559ecef08c1fb47cc57669230d2f6013520416",
        "candidate_commit":commit,"os":std::env::consts::OS,"architecture":std::env::consts::ARCH,
        "workers":1,"workloads":workloads,"scope":"upload source hashing and local split/merge, not network throughput",
        "limits":"debug harness; lifetime peak RSS includes initialization; warm OS caches; native disk reread/security checks retained"});
    let mut file = File::create(root.join(".ci-work/resource-report.json")).unwrap();
    serde_json::to_writer_pretty(&mut file, &report).unwrap();
    writeln!(file).unwrap();
}

#[path = "common/private_tempfile.rs"]
mod private_tempfile;
