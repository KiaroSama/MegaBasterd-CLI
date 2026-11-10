//! Corruption detection preserves one exact private copy without rewriting the source.
#![allow(clippy::unwrap_used)]

use std::{fs, path::Path};

use megabasterd_cli::{
    error::Error,
    storage::{config_store::ConfigStore, files::Store},
};

const MALFORMED: &[u8] = b"{\"max_workers\": 8,,,\n";

#[test]
fn repeated_and_concurrent_corrupt_loads_keep_one_verified_copy_per_distinct_content() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/config-backups");
    fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    for concurrent in [false, true] {
        let path = scratch.path().join(if concurrent {
            "concurrent/config.json"
        } else {
            "repeated/config.json"
        });
        Store::new(&path)
            .lock()
            .unwrap()
            .write_bytes(MALFORMED)
            .unwrap();
        if concurrent {
            std::thread::scope(|scope| {
                let (ready, readiness) = std::sync::mpsc::channel();
                let mut starts = Vec::new();
                let workers: Vec<_> = (0..2)
                    .map(|_| {
                        let (start, started) = std::sync::mpsc::sync_channel(1);
                        starts.push(start);
                        let ready = ready.clone();
                        let path = &path;
                        scope.spawn(move || {
                            ready.send(()).unwrap();
                            started
                                .recv_timeout(std::time::Duration::from_secs(2))
                                .unwrap();
                            ConfigStore::new(path).load()
                        })
                    })
                    .collect();
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
                for _ in 0..2 {
                    readiness
                        .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
                        .unwrap();
                }
                for start in starts {
                    start.send(()).unwrap();
                }
                for worker in workers {
                    let result = worker.join().unwrap();
                    assert!(
                        matches!(result, Err(Error::Corrupt(reason)) if reason.contains("private recovery copy was preserved"))
                    );
                }
            });
        } else {
            for _ in 0..5 {
                let error = ConfigStore::new(&path).load().err().unwrap();
                assert!(matches!(error, Error::Corrupt(_)));
                assert!(
                    error
                        .to_string()
                        .contains("private recovery copy was preserved")
                );
                assert_eq!(fs::read(&path).unwrap(), MALFORMED);
            }
        }
        let copies = || {
            let mut copies: Vec<_> = fs::read_dir(path.parent().unwrap())
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .filter(|path| {
                    path.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with("config.json.corrupt-")
                        && !path
                            .file_name()
                            .unwrap()
                            .to_string_lossy()
                            .ends_with(".lock")
                })
                .collect();
            copies.sort();
            copies
        };
        assert_eq!(fs::read(&path).unwrap(), MALFORMED);
        let original_copy = copies();
        assert_eq!(original_copy.len(), 1);
        assert_eq!(fs::read(&original_copy[0]).unwrap(), MALFORMED);
        assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 3);
        let locked = Store::new(&path).lock().unwrap();
        let replacement = b"{\"connect_proxy_password\":\"synthetic-backup-secret\",,,";
        locked.write_bytes(replacement).unwrap();
        drop(locked);
        let error = ConfigStore::new(&path).load().err().unwrap();
        assert!(!error.to_string().contains("synthetic-backup-secret"));
        assert_eq!(fs::read(&path).unwrap(), replacement);
        assert_eq!(fs::read(&original_copy[0]).unwrap(), MALFORMED);
        let current_copies = copies();
        assert_eq!(current_copies.len(), 2);
        let current = current_copies
            .iter()
            .find(|name| !original_copy.contains(name))
            .unwrap();
        assert_eq!(fs::read(current).unwrap(), replacement);
        // A differently valued occupant stays untouched; a new verified copy preserves this episode.
        Store::new(current)
            .lock()
            .unwrap()
            .write_bytes(b"unrelated recovery content")
            .unwrap();
        let error = ConfigStore::new(&path).load().err().unwrap();
        assert!(error.to_string().contains("copy was preserved"));
        assert_eq!(fs::read(current).unwrap(), b"unrelated recovery content");
        let after_collision = copies();
        assert_eq!(after_collision.len(), 3);
        let alternative = after_collision
            .iter()
            .find(|path| !current_copies.contains(path))
            .unwrap();
        assert_eq!(fs::read(alternative).unwrap(), replacement);
        assert_eq!(fs::read(&path).unwrap(), replacement);
        let locked = Store::new(&path).lock().unwrap();
        assert_eq!(
            path.parent().unwrap().join(locked.preserve().unwrap()),
            *alternative
        );
    }
}
