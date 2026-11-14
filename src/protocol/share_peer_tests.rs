//! Real Cloud export/import uses the bounded TLS peer and independently decoded wire keys.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::{
    crypto::{keys, wire},
    protocol::{
        api::Api,
        auth::Session,
        links,
        test_peer::{self, Response},
    },
};

const MASTER: [u8; 16] = [9; 16];
const SHARE: [u8; 16] = [7; 16];

fn command(request: &test_peer::Request) -> Value {
    assert_eq!(request.method, "POST");
    let commands: Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(commands.as_array().unwrap().len(), 1);
    commands[0].clone()
}

fn response(value: Value) -> Response {
    Response {
        status: 200,
        headers: vec![],
        body: serde_json::to_vec(&json!([value])).unwrap(),
    }
}

fn cloud(address: std::net::SocketAddr) -> Cloud {
    Cloud::new(
        Api::test_peer(address).unwrap(),
        Session {
            sid: "invented-share-session".into(),
            master_key: MASTER,
            rsa_private_key: None,
            user_handle: "testuser".into(),
            email: "fixture@example.invalid".into(),
        },
    )
}

fn node(handle: &str, parent: &str, kind: u8, name: &str, wrapping: &[u8]) -> Value {
    if kind >= 2 {
        return json!({"h":handle,"p":parent,"t":kind});
    }
    let raw: Vec<u8> = (0..if kind == 0 { 32 } else { 16 }).collect();
    let attribute_key = if kind == 0 {
        keys::unpack_file_key(&wire::bytes_to_a32(&raw))
            .unwrap()
            .aes_key
            .to_vec()
    } else {
        raw.clone()
    };
    json!({"h":handle,"p":parent,"t":kind,"s":17,
        "k":wire::b64_url_encode(&wire::aes_key_wrap_encrypt(&raw,wrapping).unwrap()),
        "a":wire::b64_url_encode(&wire::encrypt_attributes(&json!({"n":name}),&attribute_key).unwrap())})
}

#[test]
fn actual_exports_roundtrip_full_file_and_folder_keys_and_password_types_then_remove_once() {
    let mut keyless = node("keyless", "root", 0, "unavailable.bin", &MASTER);
    keyless["k"] = json!("owner:!!!not-base64!!!");
    let listing = json!({"f":[node("root","",2,"",&MASTER),node("trash","",4,"",&MASTER),
        node("file","root",0,"file.bin",&MASTER),node("folder","root",1,"album",&MASTER),
        keyless]});
    let mut exported = std::collections::BTreeSet::new();
    let ((), calls) = test_peer::with_peer(
        |request| {
            let value = command(request);
            Some(response(match value["a"].as_str().unwrap() {
                "f" => listing.clone(),
                "l" if value.get("d").is_some() => {
                    assert_eq!(value, json!({"a":"l","n":"file","d":1}));
                    assert!(exported.remove("file"));
                    json!(0)
                }
                "l" => {
                    assert!(matches!(value["n"].as_str(), Some("file" | "folder")));
                    exported.insert(value["n"].as_str().unwrap().to_owned());
                    json!("AQIDBAUG")
                }
                _ => panic!("unexpected share action"),
            }))
        },
        |address| {
            let mut cloud = cloud(address);
            for (handle, kind, width) in [("file", 0, 32), ("folder", 1, 16)] {
                let plain = cloud.export(handle, None).unwrap();
                assert!(!plain.contains("#P!"));
                let parsed = links::parse_link(&plain).unwrap();
                assert_eq!(parsed.public_id, "AQIDBAUG");
                assert_eq!(parsed.is_file(), kind == 0);
                assert_eq!(
                    wire::b64_url_decode(parsed.key.as_deref().unwrap()).unwrap(),
                    (0u8..width).collect::<Vec<_>>()
                );
                let protected = cloud
                    .export(handle, Some("invented share password"))
                    .unwrap();
                let encoded = protected.strip_prefix("https://mega.nz/#P!").unwrap();
                let decoded =
                    keys::decrypt_password_link(encoded, "invented share password").unwrap();
                assert_eq!(decoded.node_type, kind);
                assert_eq!(decoded.public_handle, [1, 2, 3, 4, 5, 6]);
                assert_eq!(decoded.raw_key.as_slice(), (0u8..width).collect::<Vec<_>>());
                assert!(keys::decrypt_password_link(encoded, "wrong password").is_err());
            }
            for (target, expected) in [
                ("missing", "Node not found at the selected cloud path"),
                ("trash", "Only files and folders can be shared"),
            ] {
                assert!(matches!(
                    cloud.export(target, None),
                    Err(Error::Invalid(message)) if message == expected
                ));
            }
            let unavailable = cloud.find("keyless").unwrap();
            assert!(unavailable.is_file() && unavailable.raw_key.is_none());
            assert!(matches!(
                cloud.export("keyless", None),
                Err(Error::Protocol(message))
                    if message == "Cannot access node content: missing node key"
            ));
            cloud.unexport("file").unwrap();
        },
    );
    assert_eq!(
        exported,
        std::collections::BTreeSet::from(["folder".to_owned()])
    );
    assert_eq!(calls.len(), 6);
    assert_eq!(
        calls
            .iter()
            .filter(|request| command(request)["a"] == "l")
            .count(),
        5
    );
}

#[test]
fn actual_imports_keep_all_hierarchy_and_subtree_keys_with_master_key_and_share_authorization() {
    for subtree in [false, true] {
        let source = json!({"f":[node("shared","outside",1,"album",&SHARE),
            node("first","shared",0,"one.jpg",&SHARE),node("branch","shared",1,"raw",&SHARE),
            node("deep","branch",0,"two.cr2",&SHARE)]});
        let decoded = decode_import_listing(&source, &SHARE).unwrap();
        assert!(decoded.skipped.is_empty());
        let mut stored = vec![node("target", "", 2, "", &MASTER)];
        let mut imported = Vec::new();
        let ((), calls) = test_peer::with_peer(
            |request| {
                let value = command(request);
                if value["a"] == "f" {
                    return Some(response(json!({"f":stored})));
                }
                assert_eq!(value["a"], "p");
                assert_eq!(value["sm"], 1);
                let query =
                    url::Url::parse(&format!("https://testserver.com{}", request.path)).unwrap();
                assert!(query.query_pairs().any(|(k, v)| k == "n" && v == "SHAREID"));
                let incoming = &value["n"][0];
                let original = source["f"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|node| node["h"] == incoming["h"])
                    .unwrap();
                assert_eq!(incoming["t"], original["t"]);
                assert_eq!(incoming["a"], original["a"]);
                let raw = wire::aes_key_wrap_decrypt(
                    &wire::b64_url_decode(incoming["k"].as_str().unwrap()).unwrap(),
                    &MASTER,
                )
                .unwrap();
                assert_eq!(
                    raw,
                    (0u8..if incoming["t"] == 0 { 32 } else { 16 }).collect::<Vec<_>>()
                );
                imported.push((
                    incoming["h"].as_str().unwrap().to_owned(),
                    value["t"].as_str().unwrap().to_owned(),
                ));
                let mut created = incoming.clone();
                created["h"] = json!(format!("new{}", imported.len()));
                created["p"] = value["t"].clone();
                stored.push(created.clone());
                Some(response(json!({"f":[created]})))
            },
            |address| {
                let mut cloud = cloud(address);
                assert_eq!(cloud.tree().unwrap().nodes.len(), 1);
                let root = if subtree { "branch" } else { "shared" };
                let result = cloud
                    .import_nodes(&decoded.tree, root, "target", "SHAREID")
                    .unwrap();
                result.require_complete("Share import").unwrap();
                assert_eq!(result.completed.len(), if subtree { 2 } else { 4 });
                let result = cloud.tree().unwrap();
                let paths: &[(&str, &str)] = if subtree {
                    &[("raw/two.cr2", "two.cr2")]
                } else {
                    &[
                        ("album/one.jpg", "one.jpg"),
                        ("album/raw/two.cr2", "two.cr2"),
                    ]
                };
                for (path, name) in paths {
                    let file = result.find(path).unwrap();
                    assert_eq!(file.key().unwrap(), (0u8..32).collect::<Vec<_>>());
                    assert_eq!(file.name, *name);
                    assert_eq!(file.attrs, json!({"n":name}));
                }
                if subtree {
                    assert!(result.find("album").is_err());
                }
                assert!(
                    cloud
                        .import_nodes(&decoded.tree, "absent", "target", "SHAREID")
                        .is_err()
                );
            },
        );
        assert_eq!(calls.len(), if subtree { 4 } else { 6 });
        assert_eq!(
            imported,
            if subtree {
                vec![
                    ("branch".into(), "target".into()),
                    ("deep".into(), "new1".into()),
                ]
            } else {
                vec![
                    ("shared".into(), "target".into()),
                    ("first".into(), "new1".into()),
                    ("branch".into(), "new1".into()),
                    ("deep".into(), "new3".into()),
                ]
            }
        );
    }
}
