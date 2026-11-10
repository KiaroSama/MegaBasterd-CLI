//! Confirmed upload finalization keeps sharing, private result logs and local commands consistent.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::cli::auto_account_peer_tests::Capture;
use crate::crypto::keys;
use crate::terminal::output::Output;
use std::io::Write;

const CHILD: &str = "cli::upload::tree_peer_tests::finalization_tests::post_upload_command_child_observes_the_literal_path_and_prior_log";

#[test]
fn post_upload_command_child_observes_the_literal_path_and_prior_log() {
    let arguments: Vec<_> = std::env::args_os().collect();
    if !arguments
        .windows(2)
        .any(|pair| pair[0] == "--exact" && pair[1] == CHILD)
    {
        return;
    }
    assert_eq!(arguments.len(), 6);
    assert_eq!(arguments[3], "--nocapture");
    assert_eq!(arguments[4], "--test-threads=1");
    let source = std::path::PathBuf::from(&arguments[5]);
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/upload-tree-peers");
    assert!(
        source
            .canonicalize()
            .unwrap()
            .starts_with(base.canonicalize().unwrap())
    );
    assert_eq!(source.file_name().unwrap(), "file  ;$(not-shell).bin");
    assert_eq!(std::fs::read(&source).unwrap(), b"data");
    let log = std::fs::read_to_string(source.with_extension("jsonl")).unwrap();
    assert_eq!(
        log.lines().count(),
        1,
        "the result log must precede the command"
    );
    let record: Value = serde_json::from_str(log.trim()).unwrap();
    assert_eq!(record["handle"], "FILE0001");
    assert_eq!(record["account"], "fixture@example.invalid");
    assert!(record.get("public_link").is_some());
    let mut marker = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(source.with_extension("hook-marker"))
        .unwrap();
    serde_json::to_writer(&mut marker, &json!({"path":source})).unwrap();
    writeln!(marker).unwrap();
    marker.flush().unwrap();
    marker.sync_all().unwrap();
}

#[derive(Clone, Copy, Debug)]
enum Finalization {
    ProtectedShare,
    ShareRefused,
    MissingCommand,
}

#[test]
fn confirmed_finalization_shares_logs_and_runs_the_literal_command_once_without_failing_the_upload()
{
    for mode in [
        Finalization::ProtectedShare,
        Finalization::ShareRefused,
        Finalization::MissingCommand,
    ] {
        let scratch = scratch();
        let source = scratch.path().join("file  ;$(not-shell).bin");
        std::fs::write(&source, b"data").unwrap();
        let mut context = Context::test_context(scratch.path());
        let stdout = Capture::default();
        let stderr = Capture::default();
        context.output = Output::with_writers(true, false, stdout.clone(), stderr.clone());
        let log_path = source.with_extension("jsonl");
        context.config.upload_log_path = Some(log_path.to_str().unwrap().into());
        let current_dir = std::env::current_dir().unwrap().canonicalize().unwrap();
        let executable = std::env::current_exe().unwrap().canonicalize().unwrap();
        let relative = executable
            .strip_prefix(&current_dir)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(!relative.contains(char::is_whitespace));
        context.config.run_command = Some(if matches!(mode, Finalization::MissingCommand) {
            let absent = scratch
                .path()
                .canonicalize()
                .unwrap()
                .join("definitely-absent-post-upload-program");
            assert!(!absent.exists());
            let relative = absent.strip_prefix(&current_dir).unwrap().to_str().unwrap();
            assert!(!relative.contains(char::is_whitespace));
            relative.to_owned()
        } else {
            format!("{relative} --exact {CHILD} --nocapture --test-threads=1")
        });
        let mut options = options(&source);
        options.share = !matches!(mode, Finalization::MissingCommand);
        options.share_password =
            matches!(mode, Finalization::ProtectedShare).then(|| "synthetic share password".into());
        let receipt = scratch.path().join("private receipt/result.json");
        let mut state =
            TransferState::new("upload", "finalization fixture", &receipt, 4, &[1; 16]).unwrap();
        state.completed.insert(0, [2; 16]);
        state.completion_token = Some(TOKEN.into());
        state.registration_started = true;
        state.registered_handle = Some("FILE0001".into());
        let states = States::new(&receipt);
        states.save(&state).unwrap();
        let before = std::fs::read(&receipt).unwrap();
        let uploaded = confirmed_receipt(
            &state,
            &[1; 24],
            source.file_name().unwrap().to_str().unwrap(),
            &receipt,
        )
        .unwrap();
        let wrapped = wire::aes_key_wrap_encrypt(&uploaded.raw_key, &MASTER).unwrap();
        let attrs = wire::encrypt_attributes(&json!({"n":uploaded.name}), &[1; 16]).unwrap();
        let node = json!({"h":"FILE0001","p":"ROOT0001","t":0,"s":4,
            "k":wire::b64_url_encode(&wrapped),"a":wire::b64_url_encode(&attrs)});
        let mut shares = 0;
        let ((), calls) = test_peer::with_peer(
            |request| {
                let value = command(request);
                Some(match value["a"].as_str().unwrap() {
                    "f" => response(json!({"f":[{"h":"ROOT0001","t":2},node]})),
                    "l" => {
                        shares += 1;
                        assert_eq!(value, json!({"a":"l","n":"FILE0001"}));
                        response(if matches!(mode, Finalization::ShareRefused) {
                            json!(-11)
                        } else {
                            json!("AQIDBAUG")
                        })
                    }
                    _ => panic!("finalization replayed an upload or unrelated operation"),
                })
            },
            |address| {
                let mut cloud = cloud(address);
                finalize(&context, &options, &mut cloud, &source, &uploaded, 1.5).unwrap();
                let first_log = std::fs::read(&log_path).unwrap();
                let first_output = stdout.0.lock().unwrap().clone();
                let marker = source.with_extension("hook-marker");
                let first_marker = if matches!(mode, Finalization::MissingCommand) {
                    assert!(!marker.exists());
                    None
                } else {
                    let bytes = std::fs::read(&marker).unwrap();
                    let value: Value = serde_json::from_slice(&bytes).unwrap();
                    assert_eq!(value, json!({"path":source}));
                    Some(bytes)
                };
                finalize(&context, &options, &mut cloud, &source, &uploaded, 2.0).unwrap();
                assert_eq!(std::fs::read(&log_path).unwrap(), first_log);
                assert_eq!(*stdout.0.lock().unwrap(), first_output);
                if let Some(bytes) = first_marker {
                    assert_eq!(std::fs::read(&marker).unwrap(), bytes);
                } else {
                    assert!(!marker.exists());
                }
            },
        );
        let output = String::from_utf8(stdout.0.lock().unwrap().clone()).unwrap();
        let records: Vec<Value> = output
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record["status"], "success");
        assert_eq!(record["handle"], "FILE0001");
        assert_eq!(record["name"], "file  ;$(not-shell).bin");
        assert_eq!(record["size"], 4);
        assert_eq!(record["elapsed_seconds"], 1.5);
        assert_eq!(record["account"], "fixture@example.invalid");
        assert_eq!(record["thumbnail"]["status"], "not_applicable");
        let log = std::fs::read_to_string(&log_path).unwrap();
        assert_eq!(log.lines().count(), 1);
        let logged: Value = serde_json::from_str(log.trim()).unwrap();
        assert_eq!(logged["handle"], "FILE0001");
        assert_eq!(logged["account"], "fixture@example.invalid");
        assert!(logged.get("public_link").is_some());
        assert_eq!(logged["public_link"], record["share_link"]);
        chrono::DateTime::parse_from_rfc3339(logged["ts"].as_str().unwrap()).unwrap();
        let human = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
        assert!(human.contains("[INFO] Uploaded file  ;$(not-shell).bin"));
        match mode {
            Finalization::ProtectedShare => {
                let link = record["share_link"].as_str().unwrap();
                let protected = link.strip_prefix("https://mega.nz/#P!").unwrap();
                let decoded =
                    keys::decrypt_password_link(protected, "synthetic share password").unwrap();
                assert_eq!(decoded.node_type, 0);
                assert_eq!(decoded.public_handle, [1, 2, 3, 4, 5, 6]);
                assert_eq!(&*decoded.raw_key, &*uploaded.raw_key);
                assert!(!human.contains("[WARNING]"));
                assert_eq!((shares, calls.len()), (1, 2));
            }
            Finalization::ShareRefused => {
                assert!(record["share_link"].is_null());
                assert!(logged["public_link"].is_null());
                assert!(human.contains("[WARNING] Upload succeeded, but public sharing failed:"));
                assert!(human.contains("Access denied"));
                assert_eq!((shares, calls.len()), (1, 2));
            }
            Finalization::MissingCommand => {
                assert!(record["share_link"].is_null());
                assert!(human.contains("[WARNING] Post-upload command failed:"));
                assert_eq!((shares, calls.len()), (0, 0));
            }
        }
        let completed = states.load().unwrap().unwrap();
        assert!(completed.finalization_started && completed.finalization_completed);
        let mut expected: Value = serde_json::from_slice(&before).unwrap();
        expected["data"]["finalization_started"] = json!(true);
        expected["data"]["finalization_completed"] = json!(true);
        expected["data"]["revision"] = json!(2);
        let actual: Value = serde_json::from_slice(&std::fs::read(&receipt).unwrap()).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(std::fs::read(&source).unwrap(), b"data");
    }
}
