#![allow(clippy::unwrap_used)]

use megabasterd_cli::{
    cli::info::folder_document,
    protocol::{
        links,
        nodes::{Node, Tree},
    },
};
use serde_json::json;

fn node(handle: &str, parent: &str, kind: u8, name: &str, size: u64) -> Node {
    Node {
        handle: handle.into(),
        parent: parent.into(),
        node_type: kind,
        size,
        timestamp: 0,
        name: name.into(),
        raw_key: None,
        attrs: json!({"n":name}),
        encrypted_attrs: None,
    }
}

#[test]
fn folder_info_counts_the_selected_subtree_and_reports_download_include_paths() {
    let tree = Tree::new(vec![
        node("root", "outside", 1, "Show", 0),
        node("sub", "root", 1, "Season", 0),
        node("file", "sub", 0, "OAD -  09v2.mkv", 12),
        node("other", "root", 0, "other.mkv", 99),
    ])
    .unwrap();
    let link =
        links::parse_link("https://mega.nz/folder/abcdefgh#AAAAAAAAAAAAAAAAAAAAAA/folder/sub")
            .unwrap();
    let document = folder_document(&link, &tree).unwrap();
    assert_eq!(document["type"], "Folder (inside folder share)");
    assert_eq!(document["node_count"], 2);
    assert_eq!(document["file_count"], 1);
    assert_eq!(document["total_size"], 12);
    assert_eq!(
        document["files"],
        json!([{ "path":"Season/OAD -  09v2.mkv", "size":12, "handle":"file" }])
    );
    let link =
        links::parse_link("https://mega.nz/folder/abcdefgh#AAAAAAAAAAAAAAAAAAAAAA/file/file")
            .unwrap();
    let document = folder_document(&link, &tree).unwrap();
    assert_eq!(
        document,
        json!({"type":"File (in folder share)","name":"OAD -  09v2.mkv", "folder_id":"abcdefgh", "file_handle":"file", "size":12})
    );
}
