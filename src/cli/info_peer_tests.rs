//! Public folder metadata through the actual parsed command and production output writer.
#![allow(clippy::unwrap_used)]

use std::{
    io::{self, Write},
    path::Path,
    sync::{Arc, Mutex},
};

use clap::Parser;
use serde_json::{Value, json};

use super::{args::Cli, context::Context, dispatch};
use crate::{
    crypto::{keys, wire},
    protocol::{
        api::Api,
        nodes::Tree,
        test_peer::{self, Response},
    },
    terminal::output::Output,
    transfers::{folders, planner},
};

const SHARE: &str = "PUBLICID0";
const LINK: &str = "https://mega.nz/folder/PUBLICID0#EBESExQVFhcYGRobHB0eHw";
const NAME: &str = "OAD -  09v2.mkv";

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut output = self.0.lock().unwrap();
        if bytes.len() > (16 * 1024usize).saturating_sub(output.len()) {
            return Err(io::Error::other(
                "Public info output fixture bound exceeded",
            ));
        }
        output.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Capture {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

fn node(handle: &str, parent: &str, name: &str, kind: u8, size: u64) -> Value {
    let raw: Vec<u8> = (0..if kind == 0 { 32 } else { 16 }).collect();
    let attribute_key = if kind == 0 {
        keys::unpack_file_key(&wire::bytes_to_a32(&raw))
            .unwrap()
            .aes_key
            .to_vec()
    } else {
        raw.clone()
    };
    let folder_key: Vec<u8> = (16..32).collect();
    json!({"h":handle,"p":parent,"t":kind,"s":size,
        "a":wire::b64_url_encode(&wire::encrypt_attributes(&json!({"n":name}), &attribute_key).unwrap()),
        "k":format!("owner:{}",wire::b64_url_encode(&wire::aes_key_wrap_encrypt(&raw, &folder_key).unwrap()))})
}

#[test]
fn parsed_public_folder_info_keeps_exact_json_paths_counts_types_and_read_only_behavior() {
    let listing = json!({"f":[
        node("rootAAAA", "outsideX", "Season 1", 1, 0),
        node("fileAAAA", "rootAAAA", NAME, 0, 108_036_378),
        node("subBBBBB", "rootAAAA", "extras", 1, 0),
        node("fileBBBB", "subBBBBB", "clip.mkv", 0, 1024),
    ]});
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/public-info-peers");
    std::fs::create_dir_all(&base).unwrap();
    for (json_mode, subfolder) in [(true, false), (true, true), (false, false)] {
        let scratch = crate::test_support::tempdir_in(&base).unwrap();
        let stdout = Capture::default();
        let stderr = Capture::default();
        assert_eq!(std::fs::read_dir(scratch.path()).unwrap().count(), 0);
        let (code, calls) = test_peer::with_peer(
            |request| {
                assert_eq!(request.method, "POST");
                let url =
                    url::Url::parse(&format!("https://testserver.com{}", request.path)).unwrap();
                assert_eq!(url.path(), "/cs");
                assert!(
                    url.query_pairs()
                        .any(|(key, value)| key == "n" && value == SHARE)
                );
                assert!(!url.query_pairs().any(|(key, _)| key == "sid"));
                assert_eq!(
                    serde_json::from_slice::<Value>(&request.body).unwrap(),
                    json!([{"a":"f","c":1,"r":1,"ca":1}])
                );
                Some(Response {
                    status: 200,
                    headers: vec![("Content-Type".into(), "application/json".into())],
                    body: serde_json::to_vec(&json!([listing])).unwrap(),
                })
            },
            |address| {
                let mut context = Context::test_peer(
                    scratch.path(),
                    Api::test_peer(address).unwrap(),
                    Output::with_writers(json_mode, true, stdout.clone(), stderr.clone()),
                );
                let url = if subfolder {
                    format!("{LINK}/folder/subBBBBB")
                } else {
                    LINK.to_owned()
                };
                let mut arguments = vec!["mb", "-q", "info", &url];
                if json_mode {
                    arguments.push("--json");
                }
                let command = Cli::try_parse_from(arguments).unwrap().command.unwrap();
                dispatch(&mut context, command).unwrap()
            },
        );
        assert_eq!(code, 0);
        assert_eq!(
            calls.len(),
            1,
            "info must not authenticate or fetch file bytes"
        );
        assert_eq!(
            std::fs::read_dir(scratch.path()).unwrap().count(),
            0,
            "public metadata must not create accounts, queue, transfer state or output directories"
        );
        assert!(
            stderr.text().is_empty(),
            "quiet metadata command has no human diagnostics"
        );
        let text = stdout.text();
        assert!(!text.contains("EBESExQVFhcYGRobHB0eHw"));
        if !json_mode {
            assert!(text.contains("Folder share"));
            assert!(text.contains("Season 1/OAD -  09v2.mkv"));
            assert!(serde_json::from_str::<Value>(&text).is_err());
            continue;
        }
        let document: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            text.lines().count(),
            1,
            "stdout is exactly one JSON document"
        );
        let files = document["files"].as_array().unwrap();
        assert_eq!(document["public_id"], SHARE);
        if subfolder {
            assert_eq!(document["type"], "Folder (inside folder share)");
            assert_eq!(document["node_count"].as_u64(), Some(2));
            assert_eq!(document["file_count"].as_u64(), Some(1));
            assert_eq!(document["total_size"].as_u64(), Some(1024));
            assert_eq!(
                files,
                &vec![json!({"path":"extras/clip.mkv","size":1024,"handle":"fileBBBB"})]
            );
        } else {
            assert_eq!(document["type"], "Folder share");
            assert_eq!(document["node_count"].as_u64(), Some(4));
            assert_eq!(document["file_count"].as_u64(), Some(2));
            assert_eq!(document["total_size"].as_u64(), Some(108_037_402));
            assert_eq!(files.len(), 2);
            let big = files
                .iter()
                .find(|file| file["handle"] == "fileAAAA")
                .unwrap();
            assert_eq!(big["path"], "Season 1/OAD -  09v2.mkv");
            assert_eq!(big["size"].as_u64(), Some(108_036_378));
            let clip = files
                .iter()
                .find(|file| file["handle"] == "fileBBBB")
                .unwrap();
            assert_eq!(clip["path"], "Season 1/extras/clip.mkv");
            assert_eq!(clip["size"].as_u64(), Some(1024));
            let folder_key: Vec<u8> = (16..32).collect();
            let tree = Tree::decode(&listing, &folder_key).unwrap();
            let jobs = planner::plan(&tree, None).unwrap();
            let selected =
                folders::select_jobs(jobs, &[big["path"].as_str().unwrap().into()], &[], None)
                    .unwrap();
            assert_eq!(selected.len(), 1);
            assert_eq!(selected[0].node.handle, "fileAAAA");
            assert_eq!(
                selected[0].relative.to_string_lossy().replace('\\', "/"),
                big["path"].as_str().unwrap()
            );
            assert_eq!(selected[0].node.name, NAME);
        }
    }
}
