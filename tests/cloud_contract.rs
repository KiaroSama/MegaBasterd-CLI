#![allow(clippy::unwrap_used)]
use megabasterd_cli::protocol::nodes::{Node, Tree};

fn node(handle: &str, parent: &str, kind: u8, name: &str) -> Node {
    Node {
        handle: handle.to_owned(),
        parent: parent.to_owned(),
        node_type: kind,
        size: 0,
        timestamp: 0,
        name: name.to_owned(),
        raw_key: None,
        encrypted_attrs: None,
        attrs: serde_json::json!({"n":name}),
    }
}

#[test]
fn node_graph_detects_cycles_duplicates_and_resolves_exact_paths() {
    let tree = Tree::new(vec![
        node("root", "", 2, ""),
        node("folder", "root", 1, "Season 1"),
        node("file", "folder", 0, "OAD -  09v2.mkv"),
    ])
    .unwrap();
    assert_eq!(
        tree.find("Season 1/OAD -  09v2.mkv").unwrap().handle,
        "file"
    );
    assert_eq!(tree.find("file").unwrap().name, "OAD -  09v2.mkv");
    assert!(tree.find("Season 1/OAD - 09v2.mkv").is_err());
    assert!(Tree::new(vec![node("a", "b", 1, "a"), node("b", "a", 1, "b")]).is_err());
    assert!(Tree::new(vec![node("a", "", 1, "a"), node("a", "", 1, "other")]).is_err());
}
