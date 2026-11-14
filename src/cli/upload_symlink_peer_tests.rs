//! Actual structured upload never transmits linked files or creates linked directory placeholders.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::cli::auto_account_peer_tests::Capture;
use crate::terminal::output::Output;

#[test]
fn structured_upload_registers_only_real_entries_and_preserves_outside_link_targets() {
    let scratch = scratch();
    let source = scratch.path().join("docs");
    let outside = scratch.path().join("outside");
    std::fs::create_dir(&source).unwrap();
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(source.join("real.txt"), b"real").unwrap();
    std::fs::write(outside.join("not-selected.txt"), b"outside bytes").unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&outside, source.join("linked")).unwrap();
        std::os::unix::fs::symlink(outside.join("not-selected.txt"), source.join("notes.lnk"))
            .unwrap();
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::symlink_dir(&outside, source.join("linked"))
            .expect("Windows fixture requires symbolic-link privilege or Developer Mode");
        std::os::windows::fs::symlink_file(
            outside.join("not-selected.txt"),
            source.join("notes.lnk"),
        )
        .expect("Windows fixture requires symbolic-link privilege or Developer Mode");
    }
    let mut context = Context::test_context(scratch.path());
    let stdout = Capture::default();
    context.output = Output::with_writers(true, true, stdout.clone(), Capture::default());
    let manifest = upload_tree::walk(&source, &context.control).unwrap();
    assert_eq!(
        (manifest.bytes, manifest.skipped, manifest.entries.len()),
        (4, 2, 1)
    );
    assert_eq!(manifest.entries[0].relative, Path::new("real.txt"));
    assert!(!manifest.entries[0].directory);
    let mut options = options(&source);
    options.share = false;
    let vault = Vault::new("synthetic link exclusion passphrase");
    let states = scratch.path().join("private upload state");
    let mut folders = 0;
    let mut files = 0;
    let mut bodies = Vec::new();
    let ((), calls) = test_peer::with_peer(
        |request| {
            assert_eq!(request.method, "POST");
            if request.path.starts_with("/native-peer-upload/tree/") {
                assert_eq!(request.path, "/native-peer-upload/tree/0");
                assert_eq!(request.body.len(), 4);
                bodies.push(request.body.clone());
                assert_eq!(bodies.len(), 1, "a linked file was transmitted");
                return Some(Response {
                    status: 200,
                    headers: vec![],
                    body: TOKEN.as_bytes().to_vec(),
                });
            }
            let value = command(request);
            Some(match value["a"].as_str().unwrap() {
                "f" => response(json!({"f":[{"h":"ROOT0001","t":2}]})),
                "u" => {
                    assert_eq!(value["s"], 4);
                    response(json!({"p":SLOT}))
                }
                "p" => {
                    let node = &value["n"][0];
                    let raw = wire::aes_key_wrap_decrypt(
                        &wire::b64_url_decode(node["k"].as_str().unwrap()).unwrap(),
                        &MASTER,
                    )
                    .unwrap();
                    let (handle, aes_key) = if node["t"] == 1 {
                        folders += 1;
                        assert_eq!(folders, 1, "linked directory became a remote placeholder");
                        assert_eq!(value["t"], "ROOT0001");
                        assert_eq!(raw.len(), 16);
                        ("FOLD0001", raw.to_vec())
                    } else {
                        files += 1;
                        assert_eq!((files, bodies.len()), (1, 1));
                        assert_eq!(node["t"], 0);
                        assert_eq!(node["h"], TOKEN);
                        assert_eq!(value["t"], "FOLD0001");
                        let key = crate::crypto::keys::unpack_file_key(&wire::bytes_to_a32(&raw))
                            .unwrap();
                        assert_eq!(
                            wire::ctr_crypt_at_offset(
                                key.aes_key.as_slice(),
                                &key.nonce,
                                0,
                                &bodies[0]
                            )
                            .unwrap(),
                            b"real"
                        );
                        ("FILE0001", key.aes_key.to_vec())
                    };
                    let attributes = wire::decrypt_attributes(
                        &wire::b64_url_decode(node["a"].as_str().unwrap()).unwrap(),
                        &aes_key,
                    )
                    .unwrap();
                    assert_eq!(
                        attributes["n"],
                        if node["t"] == 1 { "docs" } else { "real.txt" }
                    );
                    response(json!({"f":[{"h":handle}]}))
                }
                _ => panic!("unexpected link-exclusion upload action"),
            })
        },
        |address| {
            let mut progress = Progress::new(false);
            let item = progress.add("docs", manifest.bytes).unwrap();
            let job = Job {
                path: source.clone(),
                size: manifest.bytes,
                tree: None,
                item,
            };
            structured(
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
            .unwrap();
            let totals = progress.totals().unwrap();
            assert_eq!(
                (
                    totals.items,
                    totals.finished,
                    totals.failed,
                    totals.completed
                ),
                (1, 1, 0, 4)
            );
            assert!(progress.close(true).unwrap());
        },
    );
    assert_eq!((folders, files, bodies.len(), calls.len()), (1, 1, 1, 5));
    let bytes = stdout.0.lock().unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    let records: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["status"], "success");
    assert_eq!(records[0]["name"], "real.txt");
    assert_eq!(records[0]["size"], 4);
    assert!(!text.contains("not-selected") && !text.contains("notes.lnk"));
    assert_eq!(std::fs::read(source.join("real.txt")).unwrap(), b"real");
    assert_eq!(
        std::fs::read(outside.join("not-selected.txt")).unwrap(),
        b"outside bytes"
    );
}
