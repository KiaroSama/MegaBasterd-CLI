//! Own-cloud mutations checked through actual TLS/API serialization and fresh listing reads.
#![allow(clippy::unwrap_used)]

use serde_json::{Value, json};

use super::{
    api::Api,
    auth::Session,
    cloud::Cloud,
    test_peer::{self, Request, Response},
};
use crate::{
    crypto::{keys, wire},
    error::Error,
};

const MASTER: [u8; 16] = [9; 16];
const FOLDER_KEY: [u8; 16] = [7; 16];

fn command(request: &Request) -> Value {
    assert_eq!(request.method, "POST");
    let envelope: Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(envelope.as_array().unwrap().len(), 1);
    envelope[0].clone()
}

fn reply(value: Value) -> Response {
    Response {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: serde_json::to_vec(&json!([value])).unwrap(),
    }
}

fn cloud(address: std::net::SocketAddr) -> Cloud {
    Cloud::new(
        Api::test_peer(address).unwrap(),
        Session {
            sid: "synthetic-session".into(),
            master_key: MASTER,
            rsa_private_key: None,
            user_handle: "testuser".into(),
            email: "fixture@example.invalid".into(),
        },
    )
}

fn encrypted_node(handle: &str, kind: u8, name: &str, raw: &[u8]) -> Value {
    let aes = if kind == 0 {
        keys::unpack_file_key(&wire::bytes_to_a32(raw))
            .unwrap()
            .aes_key
            .to_vec()
    } else {
        raw.to_vec()
    };
    json!({"h":handle,"p":"ROOT0001","t":kind,"s":17,"ts":5,
        "k":wire::b64_url_encode(&wire::aes_key_wrap_encrypt(raw,&MASTER).unwrap()),
        "a":wire::b64_url_encode(&wire::encrypt_attributes(&json!({"n":name}),&aes).unwrap())})
}

#[test]
fn mkdir_rename_move_delete_preserve_keys_and_refresh_the_actual_remote_listing() {
    let file_key: Vec<u8> = (0..32).collect();
    let file_aes = keys::unpack_file_key(&wire::bytes_to_a32(&file_key))
        .unwrap()
        .aes_key;
    let mut nodes = vec![
        json!({"h":"ROOT0001","t":2}),
        json!({"h":"TRASH001","t":4}),
        json!({"h":"OPAQUE01","p":"ROOT0001","t":1}),
        encrypted_node("FOLDER01", 1, "before", &FOLDER_KEY),
        encrypted_node("FILE0001", 0, "before.bin", &file_key),
    ];
    let mut created = 0;
    let mut renamed = Vec::new();
    let (_, calls) = test_peer::with_peer(
        |request| {
            let value = command(request);
            Some(match value["a"].as_str().unwrap() {
                "f" => reply(json!({"f":nodes})),
                "p" => {
                    created += 1;
                    assert_eq!(
                        value["t"],
                        if created == 1 { "ROOT0001" } else { "NEW00001" }
                    );
                    assert_eq!(value["n"].as_array().unwrap().len(), 1);
                    let mut node = value["n"][0].clone();
                    assert_eq!(node["h"], "xxxxxxxx");
                    assert_eq!(node["t"], 1);
                    let key = wire::aes_key_wrap_decrypt(
                        &wire::b64_url_decode(node["k"].as_str().unwrap()).unwrap(),
                        &MASTER,
                    )
                    .unwrap();
                    assert_eq!(key.len(), 16);
                    let attrs = wire::decrypt_attributes(
                        &wire::b64_url_decode(node["a"].as_str().unwrap()).unwrap(),
                        &key,
                    )
                    .unwrap();
                    assert_eq!(
                        attrs,
                        json!({"n":if created == 1 {"photos"} else {"nested"}})
                    );
                    let handle = format!("NEW{created:05}");
                    node["h"] = json!(handle);
                    node["p"] = value["t"].clone();
                    nodes.push(node);
                    reply(json!({"f":[{"h":handle}]}))
                }
                "a" => {
                    let handle = value["n"].as_str().unwrap();
                    let rewrapped = wire::aes_key_wrap_decrypt(
                        &wire::b64_url_decode(value["key"].as_str().unwrap()).unwrap(),
                        &MASTER,
                    )
                    .unwrap();
                    let attribute_bytes =
                        wire::b64_url_decode(value["attr"].as_str().unwrap()).unwrap();
                    let expected_name = if handle == "FOLDER01" {
                        assert_eq!(rewrapped.as_slice(), &FOLDER_KEY);
                        assert_eq!(
                            wire::decrypt_attributes(&attribute_bytes, &FOLDER_KEY).unwrap(),
                            json!({"n":"after"})
                        );
                        "after"
                    } else {
                        assert_eq!(handle, "FILE0001");
                        assert_eq!(rewrapped.len(), 32);
                        assert_eq!(rewrapped, file_key);
                        assert_eq!(
                            wire::decrypt_attributes(&attribute_bytes, &file_aes).unwrap(),
                            json!({"n":"after.bin"})
                        );
                        assert!(
                            wire::decrypt_attributes(&attribute_bytes, &file_key[..16]).is_err(),
                            "raw first16 must not decrypt a file name"
                        );
                        "after.bin"
                    };
                    renamed.push((handle.to_owned(), expected_name));
                    let node = nodes.iter_mut().find(|node| node["h"] == handle).unwrap();
                    node["a"] = value["attr"].clone();
                    node["k"] = value["key"].clone();
                    reply(json!(0))
                }
                "m" => {
                    assert_eq!(value, json!({"a":"m","n":"FILE0001","t":"NEW00001"}));
                    let node = nodes
                        .iter_mut()
                        .find(|node| node["h"] == "FILE0001")
                        .unwrap();
                    node["p"] = json!("NEW00001");
                    reply(json!(0))
                }
                "d" => {
                    assert_eq!(value, json!({"a":"d","n":"FILE0001"}));
                    nodes.retain(|node| node["h"] != "FILE0001");
                    reply(json!(0))
                }
                _ => panic!("unexpected own-cloud mutation"),
            })
        },
        |address| {
            let mut cloud = cloud(address);
            let root = cloud.root().unwrap();
            assert_eq!(root, "ROOT0001");
            let folder = cloud.mkdir("photos", None).unwrap();
            assert_eq!(cloud.find(&folder).unwrap().name, "photos");
            assert_eq!(cloud.find("photos").unwrap().handle, folder);
            assert!(cloud.find(&folder).unwrap().is_folder());
            let nested = cloud.mkdir("nested", Some(&folder)).unwrap();
            assert_eq!(cloud.find("photos/nested").unwrap().handle, nested);
            cloud.rename("FOLDER01", "after").unwrap();
            assert_eq!(cloud.find("FOLDER01").unwrap().name, "after");
            cloud.rename("FILE0001", "after.bin").unwrap();
            assert_eq!(cloud.find("FILE0001").unwrap().name, "after.bin");
            assert_eq!(cloud.find("after.bin").unwrap().handle, "FILE0001");
            cloud.move_node("FILE0001", &folder).unwrap();
            assert_eq!(cloud.find("FILE0001").unwrap().parent, folder);
            assert_eq!(cloud.find("photos/after.bin").unwrap().handle, "FILE0001");
            assert!(
                cloud.move_node(&folder, &nested).is_err(),
                "cycle refused before m"
            );
            for target in ["OPAQUE01", "TRASH001"] {
                let error = cloud.rename(target, "missing key").unwrap_err();
                assert!(matches!(&error, Error::Protocol(_)));
                assert!(error.to_string().contains("missing node key"));
                assert!(!error.to_string().contains(target));
                assert_eq!(error.exit_code(), 1);
            }
            cloud.delete("FILE0001").unwrap();
            assert!(cloud.tree().unwrap().node("FILE0001").is_none());
            for error in [
                cloud.rename("absent", "x").unwrap_err(),
                cloud.delete("absent").unwrap_err(),
            ] {
                assert!(matches!(&error, Error::Invalid(_)));
                assert!(error.to_string().contains("Node not found"));
                assert!(!error.to_string().contains("absent"));
                assert_eq!(error.exit_code(), 2);
            }
            assert!(cloud.find("FOLDER01").is_ok());
        },
    );
    assert_eq!(created, 2);
    assert_eq!(
        renamed,
        [
            ("FOLDER01".into(), "after"),
            ("FILE0001".into(), "after.bin")
        ]
    );
    let actions: Vec<_> = calls
        .iter()
        .map(|request| command(request)["a"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        actions,
        [
            "f", "p", "f", "p", "f", "a", "f", "a", "f", "m", "f", "d", "f"
        ]
    );
}

#[test]
fn malformed_folder_registration_is_ambiguous_without_replay_and_refreshes_the_listing() {
    for malformed in [
        json!({"f":["not-a-dict"]}),
        json!({"f":[{"no_handle":1}]}),
        json!({"f":[{"h":42}]}),
    ] {
        let mut nodes = vec![json!({"h":"ROOT0001","t":2})];
        let mut mutations = 0;
        let (_, calls) = test_peer::with_peer(
            |request| {
                let value = command(request);
                Some(match value["a"].as_str().unwrap() {
                    "f" => reply(json!({"f":nodes})),
                    "p" => {
                        mutations += 1;
                        assert_eq!(value["t"], "ROOT0001");
                        let mut created = value["n"][0].clone();
                        created["h"] = json!("NEW00001");
                        created["p"] = json!("ROOT0001");
                        nodes.push(created);
                        reply(malformed.clone())
                    }
                    _ => panic!("malformed mkdir sent an unrelated action"),
                })
            },
            |address| {
                let mut cloud = cloud(address);
                assert_eq!(cloud.tree().unwrap().nodes.len(), 1);
                let error = cloud.mkdir("newdir", None).unwrap_err();
                assert!(matches!(&error, Error::AmbiguousMutation("p")));
                assert_eq!(error.code(), "ambiguous_mutation");
                assert_eq!(error.exit_code(), 1);
                assert!(!error.retryable_network());
                assert!(!error.to_string().contains("newdir"));
                assert_eq!(cloud.find("newdir").unwrap().handle, "NEW00001");
                assert_eq!(cloud.tree().unwrap().nodes.len(), 2);
            },
        );
        assert_eq!(mutations, 1, "uncertain folder creation was replayed");
        let actions: Vec<_> = calls
            .iter()
            .map(|request| command(request)["a"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(actions, ["f", "p", "f"]);
    }
}

#[test]
fn late_remote_nodes_remain_invisible_until_explicit_cache_invalidation() {
    let late = encrypted_node("LATE0001", 1, "late", &FOLDER_KEY);
    let mut listings = 0;
    let (_, calls) = test_peer::with_peer(
        |request| {
            let value = command(request);
            assert_eq!(value, json!({"a":"f","c":1}));
            listings += 1;
            assert!(
                listings <= 2,
                "a cached lookup unexpectedly fetched another listing"
            );
            let mut nodes = vec![json!({"h":"ROOT0001","t":2})];
            if listings == 2 {
                nodes.push(late.clone());
            }
            Some(reply(json!({"f":nodes})))
        },
        |address| {
            let mut cloud = cloud(address);
            assert_eq!(cloud.tree().unwrap().nodes.len(), 1);
            assert!(cloud.find("late").is_err());
            assert_eq!(cloud.tree().unwrap().nodes.len(), 1);
            cloud.invalidate();
            assert_eq!(cloud.find("late").unwrap().handle, "LATE0001");
            assert_eq!(cloud.tree().unwrap().nodes.len(), 2);
            assert_eq!(cloud.find("LATE0001").unwrap().name, "late");
            assert_eq!(cloud.session.sid, "synthetic-session");
        },
    );
    assert_eq!(listings, 2);
    assert_eq!(calls.len(), 2);
}

#[test]
fn failed_or_dropped_cloud_worker_keeps_sibling_cache_session_and_base_client_usable() {
    let listing = json!({"f":[
        {"h":"ROOT0001","t":2},
        encrypted_node("FOLDER01", 1, "before", &FOLDER_KEY),
    ]});
    let (_, calls) = test_peer::with_peer(
        |request| {
            let value = command(request);
            Some(match value["a"].as_str().unwrap() {
                "f" => reply(listing.clone()),
                "a" => {
                    assert_eq!(value["n"], "FOLDER01");
                    reply(json!(-11))
                }
                "ug" => reply(json!({"u":"testuser"})),
                _ => panic!("worker cleanup sent a logout or unrelated mutation"),
            })
        },
        |address| {
            let mut base = cloud(address);
            let mut first = Cloud::new(base.api.fork().unwrap(), base.session.clone());
            let mut second = Cloud::new(base.api.fork().unwrap(), base.session.clone());
            assert_eq!(first.find("FOLDER01").unwrap().name, "before");
            assert_eq!(second.find("FOLDER01").unwrap().name, "before");
            second.invalidate();
            assert_eq!(first.find("FOLDER01").unwrap().name, "before");
            assert!(matches!(
                second.rename("FOLDER01", "refused"),
                Err(Error::Mega { code: -11, .. })
            ));
            assert_eq!(first.find("FOLDER01").unwrap().name, "before");
            assert_eq!(first.session.sid, "synthetic-session");
            assert_eq!(second.session.sid, "synthetic-session");
            assert_eq!(base.session.sid, "synthetic-session");
            assert_eq!(first.session.master_key, MASTER);
            drop(second);
            assert_eq!(
                first.api.request(json!({"a":"ug"}), &[]).unwrap(),
                json!({"u":"testuser"})
            );
            drop(first);
            assert_eq!(
                base.api.request(json!({"a":"ug"}), &[]).unwrap(),
                json!({"u":"testuser"})
            );
            assert_eq!(base.find("FOLDER01").unwrap().name, "before");
            assert_eq!(base.session.sid, "synthetic-session");
        },
    );
    let actions: Vec<_> = calls
        .iter()
        .map(|request| command(request)["a"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(actions, ["f", "f", "f", "a", "ug", "ug", "f"]);
    let ids: Vec<_> = calls
        .iter()
        .map(|request| {
            let url = url::Url::parse(&format!("https://testserver.com{}", request.path)).unwrap();
            assert!(
                url.query_pairs()
                    .any(|(key, value)| key == "sid" && value == "synthetic-session")
            );
            url.query_pairs()
                .find(|(key, _)| key == "id")
                .unwrap()
                .1
                .into_owned()
        })
        .collect();
    assert_eq!(ids, ["1", "1", "2", "3", "2", "1", "2"]);
}
