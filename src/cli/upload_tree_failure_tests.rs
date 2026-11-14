//! Actual structured upload preserves successful siblings and refuses children of a failed folder.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::cli::auto_account_peer_tests::Capture;
use crate::terminal::output::Output;

fn records(capture: &Capture) -> Vec<Value> {
    let bytes = capture.0.lock().unwrap();
    std::str::from_utf8(&bytes)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[test]
fn failed_file_preserves_successful_siblings_and_reports_strict_aggregate_failure() {
    for keep_going in [false, true] {
        let scratch = scratch();
        let source = scratch.path().join("photos");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("bad.txt"), b"bad").unwrap();
        std::fs::write(source.join("ok.txt"), b"ok").unwrap();
        let mut context = Context::test_context(scratch.path());
        let stdout = Capture::default();
        context.output = Output::with_writers(true, true, stdout.clone(), Capture::default());
        let manifest = upload_tree::walk(&source, &context.control).unwrap();
        assert_eq!(manifest.bytes, 5);
        let mut options = options(&source);
        options.keep_going = keep_going;
        options.share = false;
        let states = scratch.path().join("states");
        let vault = Vault::new("synthetic sibling passphrase");
        let mut nodes = vec![json!({"h":"ROOT0001","t":2})];
        let mut slots = 0;
        let mut bodies = 0;
        let mut registered = 0;
        let ((), calls) = test_peer::with_peer(
            |request| {
                if request.path.starts_with("/native-peer-upload/tree/") {
                    assert_eq!(request.path, "/native-peer-upload/tree/0");
                    bodies += 1;
                    assert_eq!(request.body.len(), if bodies == 1 { 3 } else { 2 });
                    return Some(Response {
                        status: if bodies == 1 { 400 } else { 200 },
                        headers: vec![],
                        body: if bodies == 1 {
                            vec![]
                        } else {
                            TOKEN.as_bytes().to_vec()
                        },
                    });
                }
                let value = command(request);
                Some(match value["a"].as_str().unwrap() {
                    "f" => response(json!({"f":nodes})),
                    "u" => {
                        slots += 1;
                        assert_eq!(value["s"], if slots == 1 { 3 } else { 2 });
                        response(json!({"p":SLOT}))
                    }
                    "p" if value["n"][0]["t"] == 1 => {
                        assert_eq!(nodes.len(), 1);
                        assert_eq!(value["t"], "ROOT0001");
                        let mut node = value["n"][0].clone();
                        node["h"] = json!("FOLD0001");
                        node["p"] = json!("ROOT0001");
                        nodes.push(node);
                        response(json!({"f":[{"h":"FOLD0001"}]}))
                    }
                    "p" => {
                        registered += 1;
                        assert_eq!(registered, 1);
                        assert_eq!(value["t"], "FOLD0001");
                        assert_eq!(value["n"][0]["h"], TOKEN);
                        response(json!({"f":[{"h":"FILE0001"}]}))
                    }
                    _ => panic!("sibling failure fixture emitted an unexpected action"),
                })
            },
            |address| {
                let mut progress = Progress::new(false);
                let item = progress.add("photos", manifest.bytes).unwrap();
                let job = Job {
                    path: source.clone(),
                    size: manifest.bytes,
                    tree: None,
                    item,
                };
                let error = structured(
                    &context,
                    &options,
                    &mut cloud(address),
                    &vault,
                    &job,
                    &manifest,
                    "ROOT0001",
                    1,
                    &states,
                    None,
                    &RateLimiter::new(0.0).unwrap(),
                    &progress,
                )
                .unwrap_err();
                if keep_going {
                    assert!(
                        matches!(error, Error::Protocol(message) if message == "1 directory upload item(s) failed; successful remote nodes were preserved")
                    );
                } else {
                    assert_eq!(error.code(), "transfer_failed");
                    assert_eq!(error.exit_code(), 1);
                    assert!(
                        error
                            .to_string()
                            .contains("1 directory upload item(s) failed")
                    );
                    assert!(matches!(error, Error::Transfer(_)));
                }
                let snapshot = progress.snapshot(item).unwrap();
                assert_eq!(snapshot.completed, 2);
                assert_ne!(snapshot.status, Status::Complete);
                let bad_row = progress.snapshot(item + 1).unwrap();
                assert_eq!(
                    (bad_row.total, bad_row.completed, bad_row.status),
                    (3, 0, Status::Failed)
                );
                assert_eq!(
                    progress.snapshot(item + 2).unwrap().status,
                    Status::Complete
                );
                assert!(!progress.close(false).unwrap());
                assert_eq!(
                    progress.snapshot(item + 2).unwrap().status,
                    Status::Complete
                );
                let rows = progress.frame().unwrap().0;
                assert!(
                    rows.iter()
                        .any(|row| row.starts_with("bad.txt ") && row.contains("Failed"))
                );
                assert!(rows.iter().all(|row| !row.contains("ETA")));
                let mut outcomes: Vec<_> = std::fs::read_dir(&states)
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .filter(|path| {
                        path.extension()
                            .is_some_and(|extension| extension == "json")
                            && !path
                                .file_name()
                                .unwrap()
                                .to_string_lossy()
                                .starts_with("tree-")
                    })
                    .map(|path| States::new(&path).load().unwrap().unwrap())
                    .collect();
                outcomes.sort_by_key(|state| state.size);
                assert_eq!(outcomes.len(), 2);
                let failed = outcomes.iter().find(|state| state.size == 3).unwrap();
                assert!(failed.completed.is_empty() && failed.completion_token.is_none());
                assert!(!failed.registration_started);
                let success = outcomes.iter().find(|state| state.size == 2).unwrap();
                assert_eq!(success.registered_handle.as_deref(), Some("FILE0001"));
                assert_eq!(success.completion_token.as_deref(), Some(TOKEN));
                assert!(success.finalization_completed);
            },
        );
        assert_eq!((slots, bodies, registered), (2, 2, 1));
        let output = records(&stdout);
        assert_eq!(output.len(), 2);
        assert_eq!(output[0]["status"], "failed");
        assert_eq!(output[0]["path"], source.join("bad.txt").to_str().unwrap());
        assert_eq!(output[1]["status"], "success");
        assert_eq!(output[1]["name"], "ok.txt");
        assert_eq!(output[1]["size"], 2);
        assert_eq!(output[1]["handle"], "FILE0001");
        assert_eq!(calls.len(), 7);
        assert_eq!(std::fs::read(source.join("bad.txt")).unwrap(), b"bad");
        assert_eq!(std::fs::read(source.join("ok.txt")).unwrap(), b"ok");
    }
}

#[test]
fn finalization_output_failure_keeps_a_registered_child_failed_and_never_replays_it() {
    struct BrokenOutput;
    impl std::io::Write for BrokenOutput {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "fixture output closed",
            ))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let scratch = scratch();
    let source = scratch.path().join("photos");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(source.join("item.txt"), b"ok").unwrap();
    let mut context = Context::test_context(scratch.path());
    context.output = Output::with_writers(true, true, BrokenOutput, Capture::default());
    let manifest = upload_tree::walk(&source, &context.control).unwrap();
    let mut options = options(&source);
    options.share = false;
    let states = scratch.path().join("states");
    let vault = Vault::new("synthetic finalize passphrase");
    let mut nodes = vec![json!({"h":"ROOT0001","t":2})];
    let mut registered = 0;
    let ((), calls) = test_peer::with_peer(
        |request| {
            if request.path.starts_with("/native-peer-upload/tree/") {
                assert_eq!(request.body.len(), 2);
                return Some(Response {
                    status: 200,
                    headers: vec![],
                    body: TOKEN.as_bytes().to_vec(),
                });
            }
            let value = command(request);
            Some(match value["a"].as_str().unwrap() {
                "f" => response(json!({"f":nodes})),
                "u" => response(json!({"p":SLOT})),
                "p" if value["n"][0]["t"] == 1 => {
                    let mut folder = value["n"][0].clone();
                    folder["h"] = json!("FOLD0001");
                    folder["p"] = json!("ROOT0001");
                    nodes.push(folder);
                    response(json!({"f":[{"h":"FOLD0001"}]}))
                }
                "p" => {
                    registered += 1;
                    assert_eq!(value["n"][0]["h"], TOKEN);
                    response(json!({"f":[{"h":"FILE0001"}]}))
                }
                _ => panic!("unexpected finalization-failure action"),
            })
        },
        |address| {
            let mut cloud = cloud(address);
            for _ in 0..2 {
                let mut progress = Progress::new(false);
                let item = progress.add("photos", manifest.bytes).unwrap();
                let job = Job {
                    path: source.clone(),
                    size: manifest.bytes,
                    tree: None,
                    item,
                };
                let error = structured(
                    &context,
                    &options,
                    &mut cloud,
                    &vault,
                    &job,
                    &manifest,
                    "ROOT0001",
                    1,
                    &states,
                    None,
                    &RateLimiter::new(0.0).unwrap(),
                    &progress,
                )
                .unwrap_err();
                assert!(matches!(error, Error::AmbiguousMutation(_)));
                assert_eq!(progress.snapshot(item + 1).unwrap().status, Status::Failed);
                assert!(!progress.close(false).unwrap());
                let rows = progress.frame().unwrap().0;
                assert!(rows.iter().any(|row| row.starts_with("item.txt ")
                    && row.contains("Failed")
                    && !row.contains("Done")));
            }
        },
    );
    assert_eq!(registered, 1);
    assert_eq!(calls.len(), 5);
    let saved: Vec<_> = std::fs::read_dir(&states)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.extension().is_some_and(|ext| ext == "json")
                && !p
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("tree-")
        })
        .map(|p| States::new(p).load().unwrap().unwrap())
        .collect();
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].registered_handle.as_deref(), Some("FILE0001"));
    assert_eq!(saved[0].completion_token.as_deref(), Some(TOKEN));
    assert!(saved[0].finalization_started && !saved[0].finalization_completed);
    assert_eq!(std::fs::read(source.join("item.txt")).unwrap(), b"ok");
}

#[test]
fn failed_folder_and_its_child_are_reported_without_a_child_upload_slot() {
    let scratch = scratch();
    let source = scratch.path().join("photos");
    std::fs::create_dir_all(source.join("broken")).unwrap();
    std::fs::write(source.join("broken/child.txt"), b"child").unwrap();
    let mut context = Context::test_context(scratch.path());
    let stdout = Capture::default();
    context.output = Output::with_writers(true, true, stdout.clone(), Capture::default());
    let manifest = upload_tree::walk(&source, &context.control).unwrap();
    let mut options = options(&source);
    options.keep_going = true;
    options.share = false;
    let mut nodes = vec![json!({"h":"ROOT0001","t":2})];
    let mut folders = 0;
    let ((), calls) = test_peer::with_peer(
        |request| {
            let value = command(request);
            Some(match value["a"].as_str().unwrap() {
                "f" => response(json!({"f":nodes})),
                "p" => {
                    assert_eq!(value["n"][0]["t"], 1);
                    folders += 1;
                    if folders == 1 {
                        let mut node = value["n"][0].clone();
                        node["h"] = json!("FOLD0001");
                        node["p"] = json!("ROOT0001");
                        nodes.push(node);
                        response(json!({"f":[{"h":"FOLD0001"}]}))
                    } else {
                        assert_eq!(folders, 2);
                        assert_eq!(value["t"], "FOLD0001");
                        response(json!(-11))
                    }
                }
                _ => panic!("a failed folder's child reached a slot or node registration"),
            })
        },
        |address| {
            let mut progress = Progress::new(false);
            let item = progress.add("photos", manifest.bytes).unwrap();
            let job = Job {
                path: source.clone(),
                size: manifest.bytes,
                tree: None,
                item,
            };
            let error = structured(
                &context,
                &options,
                &mut cloud(address),
                &Vault::new("synthetic folder passphrase"),
                &job,
                &manifest,
                "ROOT0001",
                1,
                &scratch.path().join("states"),
                None,
                &RateLimiter::new(0.0).unwrap(),
                &progress,
            )
            .unwrap_err();
            assert!(
                matches!(error, Error::Protocol(message) if message == "2 directory upload item(s) failed; successful remote nodes were preserved")
            );
            assert_eq!(progress.snapshot(item).unwrap().completed, 0);
            assert_eq!(progress.snapshot(item + 1).unwrap().status, Status::Failed);
            assert!(!progress.close(false).unwrap());
            let rows = progress.frame().unwrap().0;
            let child = Path::new("broken").join("child.txt");
            assert!(rows.iter().any(|row| {
                row.starts_with(&format!("{} ", child.display())) && row.contains("Failed")
            }));
            assert!(rows.iter().all(|row| !row.contains("ETA")));
        },
    );
    let output = records(&stdout);
    assert_eq!(output.len(), 2);
    assert!(output.iter().all(|row| row["status"] == "failed"));
    assert_eq!(output[0]["path"], source.join("broken").to_str().unwrap());
    assert!(
        output[0]["error"]
            .as_str()
            .unwrap()
            .contains("Access denied")
    );
    assert_eq!(
        Path::new(output[1]["path"].as_str().unwrap()),
        source.join("broken/child.txt")
    );
    assert_eq!(
        output[1]["error"],
        "Protocol error: Parent cloud folder creation failed"
    );
    assert_eq!(folders, 2);
    assert_eq!(calls.len(), 4);
    assert_eq!(
        std::fs::read(source.join("broken/child.txt")).unwrap(),
        b"child"
    );
}
