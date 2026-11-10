#![allow(clippy::unwrap_used)]

use megabasterd_cli::{
    protocol::{
        links,
        nodes::{Node, Tree},
    },
    transfers::{
        folders,
        planner::{self, Job},
    },
};
use serde_json::json;

fn node(handle: &str, parent: &str, kind: u8, name: &str) -> Node {
    Node {
        handle: handle.into(),
        parent: parent.into(),
        node_type: kind,
        size: 17,
        timestamp: 0,
        name: name.into(),
        raw_key: None,
        attrs: json!({"n":name}),
        encrypted_attrs: None,
    }
}

#[test]
fn folder_selection_preserves_include_paths_and_distinguishes_skip_from_no_match() {
    let tree = Tree::new(vec![
        node("root", "outside", 1, "Show"),
        node("file", "root", 0, "OAD -  09v2.mkv"),
        node("other", "root", 0, "readme.txt"),
    ])
    .unwrap();
    let jobs = planner::plan(&tree, None).unwrap();
    let selected =
        folders::select_jobs(jobs.clone(), &["Show/OAD -  09v2.mkv".into()], &[], None).unwrap();
    assert_eq!(selected.len(), 1);
    assert_eq!(
        selected[0].relative.to_string_lossy().replace('\\', "/"),
        "Show/OAD -  09v2.mkv"
    );
    assert!(folders::select_jobs(jobs.clone(), &["*.missing".into()], &[], None).is_err());
    assert!(
        folders::select_jobs(jobs.clone(), &[], &[], Some(&[]))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        folders::select_jobs(jobs, &[], &[], Some(&[2])).unwrap()[0]
            .node
            .handle,
        "other"
    );
}

#[test]
fn cyclic_folder_ancestry_is_refused_before_any_file_plan() {
    let error = Tree::new(vec![
        node("root", "", 1, "Root"),
        node("A", "B", 1, "Loop A"),
        node("B", "A", 1, "Loop B"),
        node("victim", "A", 0, "payload.bin"),
    ])
    .err()
    .unwrap();
    assert!(matches!(&error, megabasterd_cli::error::Error::Protocol(_)));
    assert!(error.to_string().contains("parent cycle"));
    assert_eq!(error.exit_code(), 1);
    assert!(!error.retryable_network());
}

#[test]
fn root_subfolder_and_single_file_plans_preserve_exact_paths_without_disk_writes() {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/folder-plans");
    std::fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    let tree = Tree::new(vec![
        node("root", "", 1, "Root Folder"),
        node("sub", "root", 1, "Season 01"),
        node("nested", "sub", 1, "Extras"),
        node("deep", "nested", 0, "Trailer.mkv"),
        node("top", "root", 0, "cover.jpg"),
    ])
    .unwrap();
    for (selected, expected) in [
        (
            None,
            vec![
                ("deep", "Root Folder/Season 01/Extras/Trailer.mkv"),
                ("top", "Root Folder/cover.jpg"),
            ],
        ),
        (Some("sub"), vec![("deep", "Season 01/Extras/Trailer.mkv")]),
        (
            Some("deep"),
            vec![("deep", "Root Folder/Season 01/Extras/Trailer.mkv")],
        ),
    ] {
        let jobs = planner::plan(&tree, selected).unwrap();
        let actual: Vec<_> = jobs
            .iter()
            .map(|job| (job.node.handle.as_str(), scratch.path().join(&job.relative)))
            .collect();
        let expected: Vec<_> = expected
            .into_iter()
            .map(|(handle, path)| (handle, scratch.path().join(path)))
            .collect();
        assert_eq!(actual, expected);
        assert!(std::fs::read_dir(scratch.path()).unwrap().next().is_none());
    }
    let tree = Tree::new(vec![
        node("root", "", 1, "Root"),
        node("sub", "root", 1, "Sub"),
        node("f", "sub", 0, "a.bin"),
    ])
    .unwrap();
    for selected in [None, Some("f")] {
        let jobs = planner::plan(&tree, selected).unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].relative, std::path::Path::new("Root/Sub/a.bin"));
    }
    assert!(std::fs::read_dir(scratch.path()).unwrap().next().is_none());

    let tree = Tree::new(vec![
        node("root", "", 1, "Root Folder"),
        node("sub", "root", 1, "Season 01"),
        node("deep", "sub", 0, "Episode 01.mkv"),
        node("top", "root", 0, "cover.jpg"),
    ])
    .unwrap();
    let existing = scratch.path().join("Root Folder/cover.jpg");
    std::fs::create_dir_all(existing.parent().unwrap()).unwrap();
    std::fs::write(&existing, b"old").unwrap();
    let jobs = planner::plan(&tree, None).unwrap();
    assert_eq!(jobs.len(), 2);
    assert_eq!(
        jobs[0].relative,
        std::path::Path::new("Root Folder/Season 01/Episode 01.mkv")
    );
    assert_eq!(scratch.path().join(&jobs[1].relative), existing);
    let selected = planner::plan(&tree, Some("deep")).unwrap();
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].relative, jobs[0].relative);
    assert_eq!(std::fs::read(&existing).unwrap(), b"old");
    assert!(!scratch.path().join("Root Folder/Season 01").exists());
}

#[test]
fn hostile_folder_components_stay_inside_the_output_root_without_planning_side_effects() {
    use std::path::{Component, Path};

    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/folder-plans");
    std::fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    let output = scratch.path().join("out");
    std::fs::create_dir(&output).unwrap();
    for (nodes, expected) in [
        (
            vec![
                node("root", "", 1, ".."),
                node("top", "root", 0, "payload.exe"),
            ],
            "unnamed/payload.exe",
        ),
        (
            vec![
                node("root", "", 1, "Root"),
                node("evil", "root", 1, ".."),
                node("f", "evil", 0, "x.bin"),
            ],
            "Root/unnamed/x.bin",
        ),
        (
            vec![node("root", "", 1, "Root"), node("f", "root", 0, "..")],
            "Root/unnamed",
        ),
        (
            vec![
                node("root", "", 1, ".."),
                node("evil", "root", 1, ".."),
                node("f", "evil", 0, "escape.bin"),
            ],
            "unnamed/unnamed/escape.bin",
        ),
        (
            vec![
                node("root", "", 1, "Root Folder"),
                node("sub", "root", 1, "Season 01"),
                node("deep", "sub", 0, "Episode 01.mkv"),
            ],
            "Root Folder/Season 01/Episode 01.mkv",
        ),
        (
            vec![
                node("root", "", 1, "Root"),
                node("f", "root", 0, "Película Año 2024 — épisode.mkv"),
            ],
            "Root/Película Año 2024 — épisode.mkv",
        ),
    ] {
        let tree = Tree::new(nodes).unwrap();
        for selected in [None, Some(tree.nodes.last().unwrap().handle.as_str())] {
            let jobs = planner::plan(&tree, selected).unwrap();
            assert_eq!(jobs.len(), 1);
            let relative = &jobs[0].relative;
            assert_eq!(relative, Path::new(expected));
            assert!(!relative.is_absolute());
            assert!(
                relative
                    .components()
                    .all(|part| matches!(part, Component::Normal(_)))
            );
            let destination = output.join(relative);
            assert!(destination.starts_with(&output));
            assert!(!destination.exists());
        }
        assert!(std::fs::read_dir(&output).unwrap().next().is_none());
        let siblings: Vec<_> = std::fs::read_dir(scratch.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(siblings, std::slice::from_ref(&output));
    }
}

#[test]
fn downloaded_child_identity_is_not_just_the_parent_share() {
    use megabasterd_cli::protocol::metadata::{DownloadSource, FileInfo};
    let file = |handle: &str| FileInfo {
        name: "file".into(),
        size: 1,
        raw_key: zeroize::Zeroizing::new(vec![1; 32]),
        url: String::new(),
        handle: handle.into(),
        public_id: "share".into(),
        source: DownloadSource::Folder,
    };
    assert_ne!(
        file("first").source_identity().unwrap(),
        file("second").source_identity().unwrap()
    );
}

#[test]
fn file_selection_applies_numbering_after_glob_filters() {
    let jobs = vec![
        Job {
            node: node("one", "root", 0, "one.txt"),
            relative: "Show/one.txt".into(),
        },
        Job {
            node: node("two", "root", 0, "two.mkv"),
            relative: "Show/two.mkv".into(),
        },
    ];
    let chosen = folders::select_jobs(jobs, &["*.mkv".into()], &[], Some(&[1])).unwrap();
    assert_eq!(chosen[0].node.handle, "two");
    let link =
        links::parse_link("https://mega.nz/folder/abcdefgh#AAAAAAAAAAAAAAAAAAAAAA/file/ijklmnop")
            .unwrap();
    assert_eq!(link.subpath.as_deref(), Some("ijklmnop"));
}
