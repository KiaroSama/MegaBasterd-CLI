#![allow(clippy::unwrap_used)]

use megabasterd_cli::{
    crypto::{keys, wire},
    protocol::{nodes::Node, shares::import_request},
};
use serde_json::json;
use zeroize::Zeroizing;

#[test]
fn imported_attributes_preserve_original_json_spelling_and_refuse_stale_ciphertext() {
    let key: Vec<u8> = (0..16).collect();
    // A valid MEGA attribute with whitespace/key order that reserialization cannot preserve.
    let mut plaintext = b"MEGA{ \"custom\" : \"value\", \"n\" : \"folder\" }".to_vec();
    plaintext.resize(plaintext.len().next_multiple_of(16), 0);
    let original = wire::b64_url_encode(&wire::aes_cbc_encrypt(&plaintext, &key).unwrap());
    let raw = json!({"h":"folder", "p":"outside", "t":1,
        "k":wire::b64_url_encode(&wire::aes_key_wrap_encrypt(&key, &[7;16]).unwrap()),
        "a":original});
    let mut node = megabasterd_cli::protocol::nodes::decode(&raw, &[7; 16]).unwrap();
    let request = import_request(&node, "target", &[9; 16]).unwrap();
    assert_eq!(request["n"][0]["a"], original);
    node.attrs["n"] = json!("changed");
    assert!(matches!(
        import_request(&node, "target", &[9; 16]),
        Err(megabasterd_cli::error::Error::Integrity(_))
    ));
}

#[test]
fn shared_import_rewraps_full_file_key_and_preserves_type_attributes_and_share_mode() {
    let attrs = json!({"n":"OAD -  09v2.mkv", "custom":"é"});
    for (kind, raw) in [
        (0, (0_u8..32).collect::<Vec<_>>()),
        (1, (0_u8..16).collect::<Vec<_>>()),
    ] {
        let node = Node {
            handle: "AQIDBAUG".into(),
            parent: "parent".into(),
            node_type: kind,
            size: if kind == 0 { 123 } else { 0 },
            timestamp: 0,
            name: "OAD -  09v2.mkv".into(),
            raw_key: Some(Zeroizing::new(raw.clone())),
            attrs: attrs.clone(),
            encrypted_attrs: None,
        };
        let request = import_request(&node, "destination", &[9; 16]).unwrap();
        assert_eq!(request["a"], "p");
        assert_eq!(request["t"], "destination");
        assert_eq!(request["sm"], 1);
        assert_eq!(request["n"][0]["t"], kind);
        assert_eq!(request["n"][0]["h"], "AQIDBAUG");
        let encrypted_key = wire::b64_url_decode(request["n"][0]["k"].as_str().unwrap()).unwrap();
        assert_eq!(
            wire::aes_key_wrap_decrypt(&encrypted_key, &[9; 16]).unwrap(),
            raw
        );
        let attribute_key = if kind == 0 {
            keys::unpack_file_key(&wire::bytes_to_a32(&raw))
                .unwrap()
                .aes_key
                .to_vec()
        } else {
            raw
        };
        let encrypted_attributes =
            wire::b64_url_decode(request["n"][0]["a"].as_str().unwrap()).unwrap();
        assert_eq!(
            wire::decrypt_attributes(&encrypted_attributes, &attribute_key).unwrap(),
            attrs
        );
        assert!(import_request(&node, "", &[9; 16]).is_err());
    }
}
