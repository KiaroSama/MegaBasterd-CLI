//! Two corruptions keep two exact backups and recover into independently readable native stores.
#![allow(clippy::unwrap_used)]

use megabasterd_cli::storage::{config_store::ConfigStore, files::Store, queue::Queue};
use std::{collections::BTreeMap, ffi::OsString, fs, path::Path};

fn backup_inventory(path: &Path) -> BTreeMap<OsString, Vec<u8>> {
    fs::read_dir(path.parent().unwrap())
        .unwrap()
        .map(|entry| entry.unwrap())
        .filter(|entry| entry.file_name().to_string_lossy().contains(".corrupt-"))
        .map(|entry| (entry.file_name(), fs::read(entry.path()).unwrap()))
        .collect()
}

#[test]
fn config_and_queue_recovery_report_the_current_episode_and_do_not_duplicate_repeated_reads() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/recovery-episodes");
    fs::create_dir_all(&base).unwrap();
    let scratch = private_tempfile::tempdir_in(base).unwrap();
    for queue in [false, true] {
        let path = scratch.path().join(if queue {
            "queue/queue.json"
        } else {
            "config/config.json"
        });
        let mut backups = Vec::new();
        for bytes in [
            b"{\"episode\": \"A\",,,".as_slice(),
            b"[not even the same shape",
        ] {
            Store::new(&path)
                .lock()
                .unwrap()
                .write_bytes(bytes)
                .unwrap();
            let mut observed = None;
            for _ in 0..6 {
                if queue {
                    assert!(Queue::new(&path).list().is_err());
                } else {
                    assert!(ConfigStore::new(&path).load().is_err());
                }
                assert_eq!(fs::read(&path).unwrap(), bytes);
                let copies = backup_inventory(&path);
                assert_eq!(copies.len(), backups.len() + 1);
                for (name, expected) in &backups {
                    assert_eq!(copies[name].as_slice(), *expected);
                }
                let current_contents = copies
                    .iter()
                    .filter(|(name, _)| !backups.iter().any(|(old, _)| old == *name))
                    .map(|(_, contents)| contents.as_slice())
                    .collect::<Vec<_>>();
                assert_eq!(current_contents, [bytes]);
                if let Some(previous) = &observed {
                    assert_eq!(&copies, previous);
                }
                observed = Some(copies);
            }
            let observed = observed.unwrap();
            let current = Store::new(&path).lock().unwrap().preserve().unwrap();
            assert_eq!(backup_inventory(&path), observed);
            assert!(!backups.iter().any(|(name, _)| name == &current));
            assert_eq!(
                fs::read(path.parent().unwrap().join(&current)).unwrap(),
                bytes
            );
            let reported = if queue {
                Queue::new(&path).reset().unwrap()
            } else {
                ConfigStore::new(&path).recover(true).unwrap()
            };
            assert_eq!(reported.as_ref(), Some(&current));
            assert_eq!(backup_inventory(&path), observed);
            backups.push((current, bytes));
            if queue {
                assert!(Queue::new(&path).list().unwrap().is_empty());
            } else {
                assert_eq!(ConfigStore::new(&path).load().unwrap().0.max_workers, 8);
            }
            let document: serde_json::Value =
                serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            assert_eq!(document["version"], 2);
            if !queue {
                assert_eq!(document["data"]["max_workers"], 8);
            }
            for (name, expected) in &backups {
                assert_eq!(
                    fs::read(path.parent().unwrap().join(name))
                        .unwrap()
                        .as_slice(),
                    *expected
                );
            }
        }
        assert_eq!(backup_inventory(&path).len(), 2);
    }
}

#[path = "common/private_tempfile.rs"]
mod private_tempfile;
