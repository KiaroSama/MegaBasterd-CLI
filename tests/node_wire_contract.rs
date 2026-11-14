//! Synthetic ciphertext comes from independent Node/OpenSSL AES, never the native writer.
#![allow(clippy::unwrap_used)]

use megabasterd_cli::{crypto::wire, protocol::nodes::Tree};
use serde_json::{Value, json};

const MASTER: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
const FOLDER_KEY: [u8; 16] = [
    32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
];
const FILE_KEY: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];

fn listing(report: bool) -> Value {
    let file = if report {
        json!({"h":"report01","p":"docs0001","u":"self0000","t":0,"s":4096,
            "ts":1700000000,"k":"self0000:CpQLtUFu8EXxw5RYxlPqWgf-73Th1QNukA7uEY6UkpM",
            "a":"fMO7QbpUb5z-CO_WA29Avd5EUEf0GVsBBJkr5P2I2Wo"})
    } else {
        json!({"h":"file0001","p":"docs0001","u":"self0000","t":0,"s":1024,
            "ts":1700000000,"k":"self0000:CpQLtUFu8EXxw5RYxlPqWgf-73Th1QNukA7uEY6UkpM",
            "a":"03zo7iMrEbV_jIkRMEiVsqG6qgy9Dxknd6YUEZcu9ok"})
    };
    json!({"f":[
        {"h":"root0001","t":2},
        {"h":"inbox001","t":3},
        {"h":"trash001","t":4},
        {"h":"docs0001","p":"root0001","u":"self0000","t":1,"s":0,
            "ts":1700000000,"k":"self0000:W-h-LltEfJRLIcmvd1bA2A","a":"qoJ7ufolYI4PoyIkCieq6g"},
        file,
        {"h":"empty001","p":"root0001","u":"self0000","t":1,"s":0,
            "ts":1700000000,"k":"self0000:W-h-LltEfJRLIcmvd1bA2A",
            "a":"GHq3v7EAuqsezgglZdaIexpRooOLgJ7ofw5JX7xOWB0"}
    ]})
}

#[test]
fn independent_encrypted_nodes_preserve_roots_key_widths_owner_prefix_and_attribute_magic() {
    let listing = listing(false);
    let encoded = serde_json::to_vec(&listing).unwrap();
    let restored: Value = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(restored, listing);
    let tree = Tree::decode_account(&restored, &MASTER).unwrap();
    let mut system: Vec<_> = tree
        .nodes
        .iter()
        .filter(|node| node.node_type >= 2)
        .map(|node| node.node_type)
        .collect();
    system.sort_unstable();
    assert_eq!(system, [2, 3, 4]);
    for (kind, handle) in [(2, "root0001"), (3, "inbox001"), (4, "trash001")] {
        let root = tree.root(kind).unwrap();
        assert_eq!(root.handle, handle);
        assert!(root.name.is_empty() && root.raw_key.is_none());
    }
    let folder = tree.find("docs").unwrap();
    let file = tree.find("docs/a.bin").unwrap();
    assert_eq!(folder.key().unwrap(), FOLDER_KEY);
    assert_eq!(file.key().unwrap(), FILE_KEY);
    assert_eq!(folder.key().unwrap().len(), 16);
    assert_eq!(file.key().unwrap().len(), 32);
    assert_eq!(wire::bytes_to_a32(file.key().unwrap()).len(), 8);
    assert_eq!(folder.name, "docs");
    assert_eq!(file.name, "a.bin");

    for (node, expected_width, expected_name) in [(folder, 16, "docs"), (file, 32, "a.bin")] {
        let raw = listing["f"]
            .as_array()
            .unwrap()
            .iter()
            .find(|raw| raw["h"].as_str() == Some(node.handle.as_str()))
            .unwrap();
        let (owner, wrapped) = raw["k"].as_str().unwrap().split_once(':').unwrap();
        assert_eq!(owner, "self0000");
        assert_eq!(wire::b64_url_decode(wrapped).unwrap().len(), expected_width);
        let attributes = wire::b64_url_decode(raw["a"].as_str().unwrap()).unwrap();
        assert_eq!(attributes.len() % 16, 0);
        let key = node.attribute_key().unwrap();
        let plaintext = wire::aes_cbc_decrypt(&attributes, &key).unwrap();
        assert!(plaintext.starts_with(b"MEGA"));
        assert_eq!(
            wire::decrypt_attributes(&attributes, &key).unwrap(),
            json!({"n":expected_name})
        );
    }
}

#[test]
fn file_attributes_use_the_literal_xor_of_both_packed_key_halves() {
    let tree = Tree::decode_account(&listing(false), &MASTER).unwrap();
    let file = tree.find("docs/a.bin").unwrap();
    assert_eq!(file.key().unwrap(), FILE_KEY);
    assert_eq!(file.attribute_key().unwrap().as_slice(), &[0x10; 16]);
    assert_eq!(
        tree.find("docs")
            .unwrap()
            .attribute_key()
            .unwrap()
            .as_slice(),
        FOLDER_KEY
    );
}

#[test]
fn an_independent_encrypted_tree_keeps_exact_names_parents_types_and_file_size() {
    let tree = Tree::decode_account(&listing(true), &MASTER).unwrap();
    let mut names: Vec<_> = tree
        .nodes
        .iter()
        .filter(|node| !node.name.is_empty())
        .map(|node| node.name.as_str())
        .collect();
    names.sort_unstable();
    assert_eq!(names, ["docs", "empty", "report.pdf"]);
    let report = tree.find("docs/report.pdf").unwrap();
    assert!(report.is_file());
    assert_eq!(report.handle, "report01");
    assert_eq!(report.parent, "docs0001");
    assert_eq!(report.size, 4096);
    assert_eq!(report.timestamp, 1_700_000_000);
    assert!(tree.find("docs").unwrap().is_folder());
    assert_eq!(tree.find("docs").unwrap().parent, "root0001");
    assert!(tree.find("empty").unwrap().is_folder());
    assert!(tree.children("empty001").is_empty());
}
