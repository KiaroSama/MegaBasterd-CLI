#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::mpsc;
use std::time::Duration;

use serde_json::{Value, json};

use super::{Cloud, Session};
use crate::crypto::{keys, wire};
use crate::error::Error;
use crate::protocol::{api::Api, nodes::Tree, test_peer};

const MASTER: [u8; 16] = [9; 16];
const SHARE: [u8; 16] = [7; 16];
const BOUND: Duration = Duration::from_secs(5);

fn command(request: &test_peer::Request) -> Value {
    assert_eq!(request.method, "POST");
    assert_eq!(request.headers["content-type"], "application/json");
    let envelope: Value = serde_json::from_slice(&request.body).unwrap();
    let commands = envelope.as_array().unwrap();
    assert_eq!(commands.len(), 1);
    commands[0].clone()
}

fn with_peer(
    mut reply: impl FnMut(&str, &Value) -> Option<Value> + Send,
    run: impl FnOnce(&mut Cloud),
) -> Vec<(String, Value)> {
    let (_, calls) = test_peer::with_peer(
        |request| {
            reply(&request.path, &command(request)).map(|value| test_peer::Response {
                status: 200,
                headers: vec![("Content-Type".into(), "application/json".into())],
                body: serde_json::to_vec(&json!([value])).unwrap(),
            })
        },
        |address| {
            let mut cloud = Cloud::new(
                Api::test_peer(address).unwrap(),
                Session {
                    sid: "synthetic-session".into(),
                    master_key: MASTER,
                    rsa_private_key: None,
                    user_handle: "testuser".into(),
                    email: "fixture@example.invalid".into(),
                },
            );
            run(&mut cloud);
        },
    );
    calls
        .iter()
        .map(|request| (request.path.clone(), command(request)))
        .collect()
}

fn node(handle: &str, parent: &str, kind: u8, name: &str, wrapping: &[u8]) -> Value {
    if kind >= 2 {
        return json!({"h":handle,"p":parent,"t":kind});
    }
    let raw: Vec<_> = (0..if kind == 0 { 32 } else { 16 }).collect();
    let key = if kind == 0 {
        keys::unpack_file_key(&wire::bytes_to_a32(&raw))
            .unwrap()
            .aes_key
            .to_vec()
    } else {
        raw.clone()
    };
    json!({"h":handle,"p":parent,"t":kind,"s":if kind==0 {17} else {0},
        "k":format!("owner:{}",wire::b64_url_encode(&wire::aes_key_wrap_encrypt(&raw,wrapping).unwrap())),
        "a":wire::b64_url_encode(&wire::encrypt_attributes(&json!({"n":name,"custom":"é"}),&key).unwrap())})
}

#[test]
fn trash_definitive_rejection_preserves_siblings_and_reports_partial_failure() {
    let mut nodes = vec![
        node("root", "", 2, "", &MASTER),
        node("trash", "", 4, "", &MASTER),
        node("keep", "root", 0, "keep.bin", &MASTER),
        node("first", "trash", 0, "first.bin", &MASTER),
        node("middle", "trash", 0, "middle.bin", &MASTER),
        node("last", "trash", 0, "last.bin", &MASTER),
    ];
    let calls = with_peer(
        |_, command| match command["a"].as_str().unwrap() {
            "f" => Some(json!({"f":nodes})),
            "d" if command["n"] == "middle" => Some(json!(-11)),
            "d" => {
                nodes.retain(|node| node["h"] != command["n"]);
                Some(json!(0))
            }
            _ => panic!("unexpected cloud request"),
        },
        |cloud| {
            assert_eq!(cloud.tree().unwrap().children("trash").len(), 3);
            let outcome = cloud.empty_trash().unwrap();
            assert_eq!(outcome.completed, ["first", "last"]);
            assert!(matches!(
                outcome.rejections.as_slice(),
                [Error::Mega { code: -11, .. }]
            ));
            let error = outcome.require_complete("Trash cleanup").unwrap_err();
            assert_eq!(error.exit_code(), 1);
            assert!(error.to_string().contains("completed=2 failed=1"));
            let remaining = cloud.tree().unwrap();
            assert!(remaining.node("keep").is_some());
            assert!(remaining.node("middle").is_some());
            assert!(remaining.node("first").is_none());
            assert!(remaining.node("last").is_none());
        },
    );
    let deleted: Vec<_> = calls
        .iter()
        .filter(|(_, v)| v["a"] == "d")
        .map(|(_, v)| v["n"].as_str().unwrap())
        .collect();
    assert_eq!(deleted, ["first", "middle", "last"]);
    assert_eq!(calls.iter().filter(|(_, v)| v["a"] == "f").count(), 2);
}

fn source_tree() -> Tree {
    Tree::decode(
        &json!({"f":[
            node("shared", "outside", 1, "album", &SHARE),
            node("first", "shared", 0, "first.bin", &SHARE),
            node("middle", "shared", 0, "middle.bin", &SHARE),
            node("last", "shared", 0, "last.bin", &SHARE),
        ]}),
        &SHARE,
    )
    .unwrap()
}

fn trash_listing() -> Value {
    json!({"f":[
        node("root", "", 2, "", &MASTER),
        node("trash", "", 4, "", &MASTER),
        node("first", "trash", 0, "first.bin", &MASTER),
        node("middle", "trash", 0, "middle.bin", &MASTER),
        node("last", "trash", 0, "last.bin", &MASTER),
    ]})
}

#[test]
fn import_definitive_rejection_keeps_siblings_keys_and_hierarchy_but_returns_partial() {
    let source = json!({"f":[
        node("shared", "outside", 1, "album", &SHARE),
        node("middle", "shared", 0, "blocked.bin", &SHARE),
        node("branch", "shared", 1, "sub", &SHARE),
        node("deep", "branch", 0, "OAD -  09v2.mkv", &SHARE),
    ]});
    let tree = Tree::decode(&source, &SHARE).unwrap();
    let mut stored = vec![node("target", "", 2, "", &MASTER)];
    let mut next = 0;
    let calls = with_peer(
        |path, command| match command["a"].as_str().unwrap() {
            "f" => Some(json!({"f":stored})),
            "p" => {
                let query = url::Url::parse(&format!("https://testserver.com{path}")).unwrap();
                assert!(query.query_pairs().any(|(k, v)| k == "n" && v == "SHAREID"));
                assert_eq!(command["sm"], 1);
                let incoming = &command["n"][0];
                let original = source["f"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|node| node["h"] == incoming["h"])
                    .unwrap();
                assert_eq!(
                    incoming["a"], original["a"],
                    "import rewrote original ciphertext"
                );
                if incoming["h"] == "middle" {
                    return Some(json!(-11));
                }
                next += 1;
                let mut created = incoming.clone();
                created["h"] = json!(format!("new{next}"));
                created["p"] = command["t"].clone();
                stored.push(created.clone());
                Some(json!({"f":[created]}))
            }
            _ => panic!("unexpected import request"),
        },
        |cloud| {
            assert_eq!(cloud.tree().unwrap().nodes.len(), 1);
            let outcome = cloud
                .import_nodes(&tree, "shared", "target", "SHAREID")
                .unwrap();
            assert_eq!(outcome.completed, ["new1", "new2", "new3"]);
            assert!(matches!(
                outcome.rejections.as_slice(),
                [Error::Mega { code: -11, .. }]
            ));
            let error = outcome.require_complete("Share import").unwrap_err();
            assert_eq!(error.exit_code(), 1);
            assert!(error.to_string().contains("completed=3 failed=1"));
            let listing = cloud.tree().unwrap();
            let file = listing.find("album/sub/OAD -  09v2.mkv").unwrap();
            assert_eq!(file.attrs["custom"], "é");
            assert_eq!(file.key().unwrap(), (0u8..32).collect::<Vec<_>>());
            assert!(listing.find("album/blocked.bin").is_err());
        },
    );
    let imports: Vec<_> = calls
        .iter()
        .filter(|(_, v)| v["a"] == "p")
        .map(|(_, v)| (v["n"][0]["h"].as_str().unwrap(), v["t"].as_str().unwrap()))
        .collect();
    assert_eq!(
        imports,
        [
            ("shared", "target"),
            ("middle", "new1"),
            ("branch", "new1"),
            ("deep", "new2")
        ]
    );
    assert_eq!(calls.iter().filter(|(_, v)| v["a"] == "f").count(), 2);
}

#[test]
fn ambiguous_mutation_stops_both_operations_without_replay_or_later_sibling() {
    for import in [false, true] {
        let tree = source_tree();
        let mut mutations = 0;
        let mut remote = trash_listing();
        let calls = with_peer(
            |_, command| {
                if command["a"] == "f" {
                    return Some(remote.clone());
                }
                mutations += 1;
                if mutations == 2 {
                    return None; // The server closes after receiving the mutation body.
                }
                if import {
                    Some(json!({"f":[{"h":format!("new{mutations}")}]}))
                } else {
                    remote["f"]
                        .as_array_mut()
                        .unwrap()
                        .retain(|n| n["h"] != command["n"]);
                    Some(json!(0))
                }
            },
            |cloud| {
                let outcome = if import {
                    cloud
                        .import_nodes(&tree, "shared", "root", "SHAREID")
                        .map(|_| ())
                } else {
                    cloud.empty_trash().map(|_| ())
                };
                assert!(matches!(outcome, Err(Error::AmbiguousMutation(_))));
                if !import {
                    assert!(cloud.tree().unwrap().node("first").is_none());
                }
            },
        );
        let changes: Vec<_> = calls.iter().filter(|(_, v)| v["a"] != "f").collect();
        assert_eq!(
            changes.len(),
            2,
            "unknown mutation was replayed or siblings continued"
        );
        let field = if import { "h" } else { "n" };
        let last = if import {
            &changes[1].1["n"][0]
        } else {
            &changes[1].1
        };
        assert_eq!(last[field], if import { "first" } else { "middle" });
    }
}

#[test]
fn cancellation_while_a_mutation_reply_arrives_stops_both_operations_without_replay() {
    for import in [false, true] {
        let tree = source_tree();
        let (cancel, receiver) = mpsc::sync_channel::<crate::transfers::control::Control>(1);
        let calls = with_peer(
            |_, command| {
                if command["a"] == "f" {
                    return Some(trash_listing());
                }
                receiver.recv_timeout(BOUND).unwrap().cancel();
                None // Cancellation races with a received mutation; its remote outcome is unknown.
            },
            |cloud| {
                cancel.send(cloud.api.control.clone()).unwrap();
                let outcome = if import {
                    cloud
                        .import_nodes(&tree, "shared", "root", "SHAREID")
                        .map(|_| ())
                } else {
                    cloud.empty_trash().map(|_| ())
                };
                let error = outcome.unwrap_err();
                assert!(matches!(
                    error,
                    Error::Canceled | Error::AmbiguousMutation(_)
                ));
                assert_ne!(error.exit_code(), 0);
                assert!(
                    cloud.cached.is_none(),
                    "partial mutation kept a stale listing"
                );
            },
        );
        assert_eq!(calls.iter().filter(|(_, v)| v["a"] != "f").count(), 1);
    }
}

#[test]
fn cancellation_before_any_mutation_remains_130_and_sends_no_request() {
    for import in [false, true] {
        let tree = source_tree();
        let calls = with_peer(
            |_, _| panic!("pre-canceled operation contacted the API"),
            |cloud| {
                cloud.api.control.cancel();
                let result = if import {
                    cloud
                        .import_nodes(&tree, "shared", "target", "SHAREID")
                        .map(|_| ())
                } else {
                    cloud.empty_trash().map(|_| ())
                };
                let error = result.unwrap_err();
                assert!(matches!(error, Error::Canceled));
                assert_eq!(error.exit_code(), 130);
            },
        );
        assert!(calls.is_empty());
    }
}

#[test]
fn failed_import_parent_preserves_source_target_fallback_and_independent_siblings() {
    let tree = Tree::decode(
        &json!({"f":[
            node("shared", "outside", 1, "album", &SHARE),
            node("blocked", "shared", 1, "blocked", &SHARE),
            node("sibling", "shared", 1, "kept", &SHARE),
            node("orphan", "blocked", 0, "surviving-child.bin", &SHARE),
            node("deep", "sibling", 0, "kept.bin", &SHARE),
        ]}),
        &SHARE,
    )
    .unwrap();
    let calls = with_peer(
        |_, command| {
            let source = command["n"][0]["h"].as_str().unwrap();
            if source == "blocked" {
                Some(json!(-11))
            } else {
                Some(json!({"f":[{"h":format!("new-{source}")}]}))
            }
        },
        |cloud| {
            let outcome = cloud
                .import_nodes(&tree, "shared", "target", "SHAREID")
                .unwrap();
            assert_eq!(
                outcome.completed,
                ["new-shared", "new-sibling", "new-orphan", "new-deep"]
            );
            assert!(matches!(
                outcome.rejections.as_slice(),
                [Error::Mega { code: -11, .. }]
            ));
            let error = outcome.require_complete("Share import").unwrap_err();
            assert!(error.to_string().contains("completed=4 failed=1"));
            assert_eq!(error.exit_code(), 1);
        },
    );
    let imported: Vec<_> = calls
        .iter()
        .map(|(_, v)| v["n"][0]["h"].as_str().unwrap())
        .collect();
    assert_eq!(imported, ["shared", "blocked", "sibling", "orphan", "deep"]);
    assert_eq!(calls[3].1["t"], "target");
    assert_eq!(calls.last().unwrap().1["t"], "new-sibling");
}

#[test]
fn trash_cleanup_deletes_only_its_children_and_an_empty_repeat_sends_no_deletion() {
    let mut nodes = vec![
        node("root", "", 2, "", &MASTER),
        node("trash", "", 4, "", &MASTER),
        node("keep", "root", 1, "keep", &MASTER),
        node("first", "trash", 0, "old0.bin", &MASTER),
        node("middle", "trash", 0, "old1.bin", &MASTER),
        node("last", "trash", 0, "old2.bin", &MASTER),
    ];
    let calls = with_peer(
        |_, command| match command["a"].as_str().unwrap() {
            "f" => Some(json!({"f":nodes})),
            "d" => {
                let handle = command["n"].as_str().unwrap();
                assert!(matches!(handle, "first" | "middle" | "last"));
                assert_eq!(command, &json!({"a":"d","n":handle}));
                let before = nodes.len();
                nodes.retain(|node| node["h"] != handle);
                assert_eq!(nodes.len() + 1, before, "child deleted more than once");
                Some(json!(0))
            }
            _ => panic!("trash cleanup sent an unrelated action"),
        },
        |cloud| {
            assert_eq!(cloud.tree().unwrap().children("trash").len(), 3);
            let outcome = cloud.empty_trash().unwrap();
            assert_eq!(outcome.completed, ["first", "middle", "last"]);
            assert!(outcome.rejections.is_empty());
            outcome.require_complete("Trash cleanup").unwrap();
            let listing = cloud.tree().unwrap();
            assert!(listing.children("trash").is_empty());
            assert_eq!(listing.find("keep").unwrap().name, "keep");
            assert_eq!(listing.nodes.len(), 3);
            let empty = cloud.empty_trash().unwrap();
            assert!(empty.completed.is_empty() && empty.rejections.is_empty());
            empty.require_complete("Trash cleanup").unwrap();
        },
    );
    assert_eq!(
        calls
            .iter()
            .map(|(_, value)| value.clone())
            .collect::<Vec<_>>(),
        [
            json!({"a":"f","c":1}),
            json!({"a":"d","n":"first"}),
            json!({"a":"d","n":"middle"}),
            json!({"a":"d","n":"last"}),
            json!({"a":"f","c":1}),
        ]
    );
    assert_eq!(
        nodes
            .iter()
            .map(|node| node["h"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["root", "trash", "keep"]
    );
}

#[test]
fn successful_and_empty_operations_keep_their_success_contract() {
    let tree = source_tree();
    let mut next = 0;
    let calls = with_peer(
        |_, command| {
            if command["a"] == "f" {
                return Some(json!({"f":[node("trash", "", 4, "", &MASTER)]}));
            }
            next += 1;
            Some(json!({"f":[{"h":format!("new{next}")}]}))
        },
        |cloud| {
            let emptied = cloud.empty_trash().unwrap();
            assert!(emptied.completed.is_empty());
            emptied.require_complete("Trash cleanup").unwrap();
            let imported = cloud
                .import_nodes(&tree, "shared", "target", "SHAREID")
                .unwrap();
            imported.require_complete("Share import").unwrap();
            assert_eq!(imported.completed, ["new1", "new2", "new3", "new4"]);
        },
    );
    assert_eq!(calls.iter().filter(|(_, v)| v["a"] == "d").count(), 0);
    assert_eq!(calls.iter().filter(|(_, v)| v["a"] == "p").count(), 4);
}
