//! Two actual post-quota refreshes rendezvous before independently rerouting to the spare account.
#![allow(clippy::unwrap_used)]

use super::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Condvar, Mutex},
    time::Duration,
};

fn together(arrivals: &(Mutex<usize>, Condvar)) {
    let mut count = arrivals.0.lock().unwrap();
    *count += 1;
    assert!(*count <= 2, "unexpected additional quota operation");
    arrivals.1.notify_all();
    let (count, _) = arrivals
        .1
        .wait_timeout_while(count, Duration::from_secs(2), |count| *count != 2)
        .unwrap();
    assert_eq!(*count, 2, "two quota operations did not arrive together");
}

#[test]
fn two_post_quota_refreshes_keep_independent_sequences_and_cached_auth_even_when_lookup_fails() {
    for (quota_code, refresh_refused) in [(-17, false), (-24, true)] {
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/auto-account-quota");
        std::fs::create_dir_all(&base).unwrap();
        let scratch = crate::test_support::tempdir_in(base).unwrap();
        seed_accounts(
            scratch.path(),
            &[(A, "session-a", 128), (B, "session-b", 64)],
        );
        let paths: Vec<_> = (0..3)
            .map(|index| {
                let path = scratch.path().join(format!("f{index}.bin"));
                std::fs::write(&path, [index as u8; 4]).unwrap();
                path
            })
            .collect();
        let stdout = Capture::default();
        let stderr = Capture::default();
        let quota_slots = (Mutex::new(0), Condvar::new());
        let quota_refreshes = (Mutex::new(0), Condvar::new());
        let spare_slots = Mutex::new(0usize);
        let bodies = Mutex::new(Vec::<Vec<u8>>::new());
        let registered = Mutex::new(BTreeSet::new());
        let (closed, closure) = std::sync::mpsc::sync_channel(20);
        let (code, calls) = test_peer::with_raw_parallel_peer(
            |request, stream| {
                let mut send = |response| {
                    test_peer::respond(stream, response, true);
                    super::super::client_lifecycle_peer_tests::observe_close(stream);
                    closed.try_send(()).unwrap();
                };
                assert_eq!(request.method, "POST");
                if request.path.starts_with("/native-peer-upload/quota/") {
                    assert_eq!(request.body.len(), 4);
                    bodies.lock().unwrap().push(request.body.clone());
                    return send(Response {
                        status: 200,
                        headers: vec![],
                        body: TOKEN.as_bytes().to_vec(),
                    });
                }
                let commands: Value = serde_json::from_slice(&request.body).unwrap();
                assert_eq!(commands.as_array().unwrap().len(), 1);
                let command = &commands[0];
                let url =
                    url::Url::parse(&format!("https://testserver.com{}", request.path)).unwrap();
                let query: BTreeMap<_, _> = url
                    .query_pairs()
                    .map(|(key, value)| (key.into_owned(), value.into_owned()))
                    .collect();
                let sid = query["sid"].as_str();
                assert!(matches!(sid, "session-a" | "session-b"));
                send(match command["a"].as_str().unwrap() {
                    "ug" => {
                        assert_eq!(query["id"], "1");
                        response(json!({"u":"testuser"}))
                    }
                    "f" => {
                        assert_eq!(query["id"], "1");
                        response(json!({"f":[{"h":"ROOT0001","t":2}]}))
                    }
                    "u" => {
                        assert_eq!(query["id"], "2");
                        assert_eq!(command["s"], 4);
                        if sid == "session-a" {
                            together(&quota_slots);
                            response(json!(quota_code))
                        } else {
                            let mut count = spare_slots.lock().unwrap();
                            *count += 1;
                            assert!(*count <= 3);
                            response(json!({"p":format!(
                                "https://upload.mega.nz/native-peer-upload/quota/{}", *count
                            )}))
                        }
                    }
                    "uq" => {
                        assert_eq!(sid, "session-a");
                        assert_eq!(query["id"], "3");
                        assert_eq!(command, &json!({"a":"uq","strg":1,"xfer":1}));
                        // Neither refresh may return until both failed-transfer forks reached uq3.
                        together(&quota_refreshes);
                        response(if refresh_refused {
                            json!(-11)
                        } else {
                            json!({"mstrg":128,"cstrg":128})
                        })
                    }
                    "p" => {
                        assert_eq!(sid, "session-b");
                        assert_eq!(query["id"], "3");
                        assert_eq!(command["t"], "ROOT0001");
                        assert_eq!(command["n"].as_array().unwrap().len(), 1);
                        let node = &command["n"][0];
                        assert_eq!(node["h"], TOKEN);
                        let raw = wire::aes_key_wrap_decrypt(
                            &wire::b64_url_decode(node["k"].as_str().unwrap()).unwrap(),
                            &MASTER,
                        )
                        .unwrap();
                        let key = keys::unpack_file_key(&wire::bytes_to_a32(&raw)).unwrap();
                        let attrs = wire::decrypt_attributes(
                            &wire::b64_url_decode(node["a"].as_str().unwrap()).unwrap(),
                            key.aes_key.as_slice(),
                        )
                        .unwrap();
                        let name = attrs["n"].as_str().unwrap();
                        let index = match name {
                            "f0.bin" => 0,
                            "f1.bin" => 1,
                            "f2.bin" => 2,
                            _ => panic!("unexpected uploaded source"),
                        };
                        assert_eq!(
                            bodies
                                .lock()
                                .unwrap()
                                .iter()
                                .filter(|body| {
                                    wire::ctr_crypt_at_offset(
                                        key.aes_key.as_slice(),
                                        &key.nonce,
                                        0,
                                        body,
                                    )
                                    .unwrap()
                                        == vec![index; 4]
                                })
                                .count(),
                            1
                        );
                        assert!(registered.lock().unwrap().insert(name.to_owned()));
                        response(json!({"f":[{"h":format!("FILE{index:04}")}]}))
                    }
                    _ => {
                        panic!("quota refresh repeated login/MFA/logout or an unrelated API action")
                    }
                })
            },
            |address| {
                let mut context = Context::test_peer(
                    scratch.path(),
                    Api::test_peer(address).unwrap(),
                    Output::with_writers(true, true, stdout.clone(), stderr.clone()),
                );
                let saved: Vec<_> = [A, B]
                    .iter()
                    .map(|email| {
                        let path = context.paths.session(email);
                        let bytes = std::fs::read(&path).unwrap();
                        (path, bytes)
                    })
                    .collect();
                let mut args: Vec<std::ffi::OsString> =
                    vec!["mb".into(), "-q".into(), "upload".into()];
                args.extend(paths.iter().cloned().map(|path| path.into_os_string()));
                args.extend([
                    "--auto-account".into(),
                    "--json".into(),
                    "-w".into(),
                    "1".into(),
                    "-P".into(),
                    "2".into(),
                    "--vault-passphrase".into(),
                    "synthetic vault passphrase".into(),
                ]);
                let command = Cli::try_parse_from(args).unwrap().command.unwrap();
                let result = dispatch(&mut context, command).unwrap();
                for _ in 0..20 {
                    closure.recv_timeout(Duration::from_secs(2)).unwrap();
                }
                assert!(closure.try_recv().is_err());
                for (path, bytes) in saved {
                    assert_eq!(std::fs::read(path).unwrap(), bytes);
                }
                if !refresh_refused {
                    let account = context.accounts().find(Some(A)).unwrap();
                    assert_eq!(
                        (account.quota_total, account.quota_used),
                        (Some(128), Some(128))
                    );
                }
                result
            },
        );
        assert_eq!(code, 0);
        assert_eq!(*quota_slots.0.lock().unwrap(), 2);
        assert_eq!(*quota_refreshes.0.lock().unwrap(), 2);
        assert_eq!(*spare_slots.lock().unwrap(), 3);
        assert_eq!(bodies.lock().unwrap().len(), 3);
        assert_eq!(calls.len(), 20);
        let mut actions = BTreeMap::<(String, String, String), usize>::new();
        for request in calls
            .iter()
            .filter(|request| request.path.starts_with("/cs?"))
        {
            let url = url::Url::parse(&format!("https://testserver.com{}", request.path)).unwrap();
            let query: BTreeMap<_, _> = url
                .query_pairs()
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect();
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            *actions
                .entry((
                    query["sid"].clone(),
                    body[0]["a"].as_str().unwrap().into(),
                    query["id"].clone(),
                ))
                .or_default() += 1;
        }
        assert_eq!(
            actions,
            BTreeMap::from([
                (("session-a".into(), "ug".into(), "1".into()), 1),
                (("session-b".into(), "ug".into(), "1".into()), 1),
                (("session-a".into(), "f".into(), "1".into()), 2),
                (("session-a".into(), "u".into(), "2".into()), 2),
                (("session-a".into(), "uq".into(), "3".into()), 2),
                (("session-b".into(), "f".into(), "1".into()), 3),
                (("session-b".into(), "u".into(), "2".into()), 3),
                (("session-b".into(), "p".into(), "3".into()), 3),
            ])
        );
        assert_eq!(
            *registered.lock().unwrap(),
            BTreeSet::from([
                "f0.bin".to_owned(),
                "f1.bin".to_owned(),
                "f2.bin".to_owned(),
            ])
        );
        let text = String::from_utf8(stdout.0.lock().unwrap().clone()).unwrap();
        let records: Vec<Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(records.len(), 3);
        assert!(records.iter().all(|record| record["event"] == "result"
            && record["status"] == "success"
            && record["size"] == 4));
        for (index, path) in paths.iter().enumerate() {
            assert_eq!(std::fs::read(path).unwrap(), [index as u8; 4]);
        }
        for capture in [&stdout, &stderr] {
            let text = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
            for secret in [
                "session-a",
                "session-b",
                "synthetic password",
                "synthetic vault passphrase",
            ] {
                assert!(!text.contains(secret));
            }
        }
    }
}
