#![allow(clippy::unwrap_used)]

use megabasterd_cli::{
    crypto::wire,
    protocol::nodes::{self, Tree},
};
use serde_json::{Value, json};

const MASTER: [u8; 16] = [1; 16];

#[test]
fn well_formed_account_node_without_encryption_fields_preserves_baseline_metadata() {
    let node = nodes::decode_account(&json!({"h":"abc","t":1,"s":10,"ts":5}), &MASTER).unwrap();
    assert_eq!(node.handle, "abc");
    assert_eq!(node.size, 10);
    assert_eq!(node.timestamp, 5);
    assert!(node.raw_key.is_none() && node.name.is_empty());
    let error = nodes::decode_account(&json!({"h":"abc","t":0,"s":"1234"}), &MASTER)
        .err()
        .unwrap();
    assert!(matches!(&error, megabasterd_cli::error::Error::Protocol(_)));
    assert!(error.to_string().contains("Node s"));
}

#[test]
fn account_metadata_survives_unavailable_keys_without_exposing_a_usable_key() {
    for raw in [
        json!({"h":"opaque01","t":1,"s":10,"ts":5}),
        json!({"h":"opaque01","p":"root0001","t":0,"s":10,"ts":5,"k":"owner:not-a-key","a":""}),
        json!({"h":"opaque01","p":"root0001","t":0,"s":10,"ts":5,
            "k":format!("owner:{}",wire::b64_url_encode(&[0;32])),"a":wire::b64_url_encode(&[0;16])}),
    ] {
        let node = nodes::decode_account(&raw, &MASTER).unwrap();
        assert_eq!(node.handle, "opaque01");
        assert_eq!((node.size, node.timestamp), (10, 5));
        assert!(node.name.is_empty());
        assert!(node.raw_key.is_none());
        assert!(node.key().is_err());
        assert!(node.attribute_key().is_err());
        assert!(
            nodes::decode(&raw, &MASTER).is_err(),
            "public shares must not accept an unusable node"
        );
    }
}

#[test]
fn account_tolerance_never_hides_malformed_wire_field_types() {
    for raw in [
        json!("not-a-dict"),
        json!(["h", "t"]),
        json!({"t":0}),
        json!({"h":12345,"t":0}),
        json!({"h":"abc"}),
        json!({"h":"abc","t":"0"}),
        json!({"h":"abc","t":0,"s":"1234"}),
        json!({"h":"abc","t":0,"ts":"now"}),
        json!({"h":"abc","t":0,"k":99}),
        json!({"h":"abc","t":0,"p":99}),
        json!({"h":"abc","t":0,"a":99}),
        json!({"h":"abc","t":0,"u":99}),
    ] {
        assert!(
            matches!(
                nodes::decode_account(&raw, &MASTER),
                Err(megabasterd_cli::error::Error::Protocol(_))
            ),
            "malformed node did not produce a typed protocol error: {raw}"
        );
    }
    assert!(nodes::decode_account(&json!({"h":"abc","t":0,"a":"not base64!"}), &MASTER).is_err());
    assert!(nodes::decode_account(&json!({"h":"abc","t":1}), &[0; 15]).is_err());
    assert!(Tree::decode_account(&json!(["not", "an", "object"]), &MASTER).is_err());
    assert!(Tree::decode_account(&json!({"f":{"h":"abc"}}), &MASTER).is_err());
    assert!(Tree::decode_account(&json!({"f":["not-a-node"]}), &MASTER).is_err());
    assert!(
        Tree::decode_account(&json!({}), &MASTER)
            .unwrap()
            .nodes
            .is_empty()
    );
}

#[test]
fn account_tree_keeps_unavailable_siblings_and_decrypts_owned_names_exactly() {
    let wrapped = wire::b64_url_encode(&wire::aes_key_wrap_encrypt(&[7; 16], &MASTER).unwrap());
    let attributes = wire::b64_url_encode(
        &wire::encrypt_attributes(&json!({"n":"Owned  folder"}), &[7; 16]).unwrap(),
    );
    let listing: Value = json!({"f":[
        {"h":"root0001","t":2},
        {"h":"opaque01","p":"root0001","t":1},
        {"h":"owned001","p":"root0001","t":1,"k":format!("owner:{wrapped}"),"a":attributes},
    ]});
    let tree = Tree::decode_account(&listing, &MASTER).unwrap();
    assert_eq!(tree.nodes.len(), 3);
    assert_eq!(tree.children("root0001").len(), 2);
    assert!(tree.find("opaque01").unwrap().key().is_err());
    assert_eq!(tree.find("Owned  folder").unwrap().handle, "owned001");
    assert_eq!(tree.find("Owned  folder").unwrap().key().unwrap(), &[7; 16]);
    assert!(tree.find("Owned folder").is_err());
    assert!(Tree::decode(&listing, &MASTER).is_err());
    for (pattern, regex) in [
        ("owned", false),
        ("^OWNED  FOLDER$", true),
        ("", false),
        (".*", true),
    ] {
        let found = tree.search(pattern, regex).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].handle, "owned001");
    }
    assert!(tree.search("[", true).is_err());
}
