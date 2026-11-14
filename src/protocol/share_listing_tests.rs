//! Share-import decoding tolerates only unusable wrapped keys, never malformed listing structure.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::crypto::{keys, wire};
use serde_json::json;

fn node(handle: &str, parent: &str, kind: u8, name: &str) -> Value {
    let raw: Vec<u8> = (0..if kind == 0 { 32 } else { 16 }).collect();
    let key = if kind == 0 {
        keys::unpack_file_key(&wire::bytes_to_a32(&raw))
            .unwrap()
            .aes_key
            .to_vec()
    } else {
        raw.clone()
    };
    json!({"h":handle,"p":parent,"t":kind,"s":17,
        "k":wire::b64_url_encode(&wire::aes_key_wrap_encrypt(&raw,&[7;16]).unwrap()),
        "a":wire::b64_url_encode(&wire::encrypt_attributes(&json!({"n":name}),&key).unwrap())})
}

#[test]
fn import_listing_skips_invalid_or_empty_wrapped_keys_but_keeps_valid_siblings_and_graph() {
    let mut broken = node("bad", "root", 0, "bad.bin");
    broken["k"] = json!("owner:!!!not-base64!!!");
    let mut empty = node("empty", "root", 0, "empty.bin");
    empty["k"] = json!("");
    let listing = json!({"f":[node("root","outside",1,"album"),broken,empty,
        node("branch","root",1,"raw"),node("good","branch",0,"good.bin")]});
    let decoded = decode_import_listing(&listing, &[7; 16]).unwrap();
    assert_eq!(decoded.skipped, ["bad", "empty"]);
    assert_eq!(decoded.tree.nodes.len(), 3);
    assert_eq!(decoded.tree.node("good").unwrap().parent, "branch");
    assert_eq!(decoded.tree.node("good").unwrap().name, "good.bin");
    assert_eq!(
        decoded
            .tree
            .descendants("branch")
            .unwrap()
            .iter()
            .map(|n| n.handle.as_str())
            .collect::<Vec<_>>(),
        ["branch", "good"]
    );
    assert!(
        Tree::decode(&listing, &[7; 16]).is_err(),
        "ordinary public decode became tolerant"
    );
    let empty = decode_import_listing(&json!({"f":[]}), &[7; 16]).unwrap();
    assert!(empty.tree.nodes.is_empty() && empty.skipped.is_empty());
    assert!(decode_import_listing(&json!({"f":[]}), &[7; 15]).is_err());
}

#[test]
fn malformed_import_listing_and_attributes_are_refused_before_any_node_can_be_imported() {
    let good = node("good", "outside", 0, "good.bin");
    let mut broken_attributes = good.clone();
    broken_attributes["a"] = json!(wire::b64_url_encode(&[0; 16]));
    let mut wrong_type = good.clone();
    wrong_type["k"] = json!(42);
    let mut cycle = node("cycle", "cycle", 1, "cycle");
    cycle["k"] = json!("");
    for malformed in [
        json!(null),
        json!([]),
        json!({"f":null}),
        json!({"f":{}}),
        json!({"f":[null]}),
        json!({"f":[good.clone(),{"p":"outside","t":1}]}),
        json!({"f":[good.clone(),good.clone()]}),
        json!({"f":[good.clone(),wrong_type]}),
        json!({"f":[good.clone(),broken_attributes]}),
        json!({"f":[good,cycle]}),
    ] {
        assert!(decode_import_listing(&malformed, &[7; 16]).is_err());
    }
}
