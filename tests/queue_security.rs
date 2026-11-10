// SPDX-License-Identifier: GPL-3.0-or-later
//! Native queue ciphertext and key recovery use the public storage interface.
#![allow(clippy::unwrap_used)]

use std::{fs, path::Path};

use megabasterd_cli::{
    crypto::wire,
    error::Error,
    platform::secure_files::PrivateDirectory,
    storage::{
        files::Store,
        queue::{JobStatus, JobType, Queue, QueuePayload},
    },
};
use serde_json::Value;

fn fixture() -> (private_tempfile::TempDir, Queue) {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/queue-security");
    fs::create_dir_all(&base).unwrap();
    let scratch = private_tempfile::tempdir_in(base).unwrap();
    let queue = Queue::new(scratch.path().join("private space/queue.json"));
    (scratch, queue)
}

fn payload(password: Option<&str>) -> QueuePayload {
    QueuePayload {
        source: "https://mega.nz/file/X#Y".into(),
        destination: "output with  two spaces".into(),
        account: Some("fixture-account@example.invalid".into()),
        password: password.map(str::to_owned),
        error: None,
    }
}

fn assert_corrupt<T>(result: megabasterd_cli::error::Result<T>) {
    let error = result.err().unwrap();
    assert!(matches!(&error, Error::Corrupt(_)));
    assert_eq!(error.code(), "storage_corrupt");
    assert_eq!(error.exit_code(), 1);
    assert!(!error.retryable_network());
    assert!(!error.to_string().contains("super-secret-link-pw"));
}

#[test]
fn full_payload_is_sealed_versioned_and_recovered_without_plaintext_metadata() {
    let (_scratch, queue) = fixture();
    for password in [Some("super-secret-link-pw"), None] {
        queue.add(JobType::Download, &payload(password)).unwrap();
    }
    let key_path = queue.path().with_file_name("queue.json.key");
    let key = fs::read(&key_path).unwrap();
    assert_eq!(key.len(), 32);
    PrivateDirectory::open(queue.path().parent().unwrap())
        .unwrap()
        .open_private(std::ffi::OsStr::new("queue.json.key"), false)
        .unwrap();
    let raw = fs::read_to_string(queue.path()).unwrap();
    let document: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(document["version"], 2);
    let rows = document["data"]["items"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    for sensitive in [
        "super-secret-link-pw",
        "https://mega.nz/file/X#Y",
        "output with  two spaces",
        "fixture-account@example.invalid",
    ] {
        assert!(!raw.contains(sensitive));
    }
    let reloaded = Queue::new(queue.path());
    let items = reloaded.list().unwrap();
    assert_eq!(items.len(), 2);
    for (index, password) in [Some("super-secret-link-pw"), None].into_iter().enumerate() {
        let row = &rows[index];
        for plaintext_field in ["source", "destination", "account", "password", "error"] {
            assert!(row.get(plaintext_field).is_none());
        }
        let token = row["enc_payload"].as_str().unwrap();
        let blob = wire::b64_url_decode(token).unwrap();
        assert_eq!(&blob[..4], b"MBQ2");
        assert!(blob.len() > 4 + 12 + 16);
        assert_eq!(wire::b64_url_encode(&blob), token);
        let decoded = reloaded.payload(&items[index]).unwrap();
        assert_eq!(decoded.source, "https://mega.nz/file/X#Y");
        assert_eq!(decoded.destination, "output with  two spaces");
        assert_eq!(
            decoded.account.as_deref(),
            Some("fixture-account@example.invalid")
        );
        assert_eq!(decoded.password.as_deref(), password);
        assert!(decoded.error.is_none());
        assert!(!format!("{:?}", items[index]).contains("super-secret-link-pw"));
    }
    assert_eq!(fs::read(&key_path).unwrap(), key);
    assert_eq!(fs::read_to_string(queue.path()).unwrap(), raw);
}

#[test]
fn modified_ciphertext_and_identity_are_refused_without_losing_the_original_job() {
    let (_scratch, queue) = fixture();
    queue
        .add(JobType::Download, &payload(Some("super-secret-link-pw")))
        .unwrap();
    let original = fs::read(queue.path()).unwrap();
    let key_path = queue.path().with_file_name("queue.json.key");
    let original_key = fs::read(&key_path).unwrap();
    let item = queue.list().unwrap().remove(0);
    let mut blob = wire::b64_url_decode(&item.enc_payload).unwrap();
    let last = blob.len() - 1;
    blob[last] ^= 0xff;
    let mut variants = Vec::new();
    let mut modified = item.clone();
    modified.enc_payload = wire::b64_url_encode(&blob);
    variants.push(modified);
    let mut renamed = item.clone();
    renamed.id = if item.id == "0".repeat(32) {
        "1".repeat(32)
    } else {
        "0".repeat(32)
    };
    variants.push(renamed);
    let mut retyped = item.clone();
    retyped.kind = JobType::Upload;
    variants.push(retyped);
    for changed in variants {
        assert_corrupt(queue.payload(&changed));
        assert_eq!(fs::read(queue.path()).unwrap(), original);
        assert_eq!(fs::read(&key_path).unwrap(), original_key);
    }
    let mut document: Value = serde_json::from_slice(&original).unwrap();
    document["data"]["items"][0]["enc_payload"] = wire::b64_url_encode(&blob).into();
    let damaged = serde_json::to_vec(&document).unwrap();
    Store::new(queue.path())
        .lock()
        .unwrap()
        .write_bytes(&damaged)
        .unwrap();
    assert_corrupt(queue.list());
    assert_corrupt(queue.add(JobType::Download, &payload(None)));
    assert_eq!(fs::read(queue.path()).unwrap(), damaged);
    assert_eq!(fs::read(&key_path).unwrap(), original_key);
    Store::new(queue.path())
        .lock()
        .unwrap()
        .write_bytes(&original)
        .unwrap();
    assert_eq!(
        queue
            .payload(&queue.list().unwrap()[0])
            .unwrap()
            .password
            .as_deref(),
        Some("super-secret-link-pw")
    );
}

#[test]
fn failed_retry_and_reload_keep_secrets_while_clearing_only_the_failure() {
    let (_scratch, queue) = fixture();
    let id = queue
        .add(JobType::Download, &payload(Some("super-secret-link-pw")))
        .unwrap();
    let claim = queue.claim_next("first-run").unwrap().unwrap();
    assert_eq!(claim.item.id, id);
    assert!(queue.touch(&claim.item).unwrap());
    queue
        .finish(
            &claim.item,
            JobStatus::Failed,
            Some("remote failure super-secret-link-pw"),
        )
        .unwrap();
    drop(claim);
    let reloaded = Queue::new(queue.path());
    let item = reloaded.list().unwrap().remove(0);
    let failed = reloaded.payload(&item).unwrap();
    assert_eq!(failed.password.as_deref(), Some("super-secret-link-pw"));
    assert_eq!(failed.error.as_deref(), Some("remote failure <redacted>"));
    assert!(reloaded.retry(&id).unwrap());
    let item = queue.list().unwrap().remove(0);
    assert_eq!(item.status, JobStatus::Pending);
    assert_eq!(item.lease_epoch, 1);
    assert!(item.run_id.is_none() && item.heartbeat_iso.is_none() && item.finished_iso.is_none());
    let retried = queue.payload(&item).unwrap();
    assert_eq!(retried.source, failed.source);
    assert_eq!(retried.destination, failed.destination);
    assert_eq!(retried.account, failed.account);
    assert_eq!(retried.password, failed.password);
    assert!(retried.error.is_none());
    assert!(
        !fs::read_to_string(queue.path())
            .unwrap()
            .contains("remote failure")
    );
    let completed = queue.claim_next("second-run").unwrap().unwrap();
    assert_eq!(completed.item.lease_epoch, 2);
    queue
        .finish(&completed.item, JobStatus::Done, None)
        .unwrap();
    drop(completed);
    assert!(!queue.retry(&id).unwrap());
    assert_eq!(queue.list().unwrap()[0].status, JobStatus::Done);
}

#[test]
fn missing_key_and_wrong_keys_preserve_ciphertext_and_refuse_mutation() {
    let (_scratch, queue) = fixture();
    queue
        .add(JobType::Download, &payload(Some("super-secret-link-pw")))
        .unwrap();
    let original = fs::read(queue.path()).unwrap();
    let key_path = queue.path().with_file_name("queue.json.key");
    let key = fs::read(&key_path).unwrap();
    fs::remove_file(&key_path).unwrap();
    assert_corrupt(queue.list());
    assert_corrupt(queue.add(JobType::Download, &payload(Some("new-password"))));
    assert!(!key_path.exists());
    assert_eq!(fs::read(queue.path()).unwrap(), original);
    let directory = PrivateDirectory::open(queue.path().parent().unwrap()).unwrap();
    use std::io::Write;
    let mut wrong = key.clone();
    wrong[0] ^= 1;
    for damaged in [vec![], b"xxxxxxxxxx".to_vec(), b"too-short".to_vec(), wrong] {
        if !key_path.exists() {
            directory
                .open_private(std::ffi::OsStr::new("queue.json.key"), true)
                .unwrap()
                .write_all(&damaged)
                .unwrap();
        } else {
            fs::write(&key_path, &damaged).unwrap();
        }
        assert_corrupt(queue.list());
        assert_corrupt(queue.add(JobType::Download, &payload(None)));
        assert_eq!(fs::read(&key_path).unwrap(), damaged);
        assert_eq!(fs::read(queue.path()).unwrap(), original);
    }
    fs::write(&key_path, &key).unwrap();
    assert_eq!(
        queue
            .payload(&queue.list().unwrap()[0])
            .unwrap()
            .password
            .as_deref(),
        Some("super-secret-link-pw")
    );
    assert_eq!(fs::read(queue.path()).unwrap(), original);
    assert_eq!(queue.list().unwrap().len(), 1);
}

#[test]
fn damaged_encrypted_document_preserves_exact_tokens_in_its_private_recovery_copy() {
    let (_scratch, queue) = fixture();
    queue
        .add(JobType::Download, &payload(Some("super-secret-link-pw")))
        .unwrap();
    let original = fs::read(queue.path()).unwrap();
    let key_path = queue.path().with_file_name("queue.json.key");
    let key = fs::read(&key_path).unwrap();
    let mut damaged = original.clone();
    damaged.extend_from_slice(b"\n<<garbage>>");
    Store::new(queue.path())
        .lock()
        .unwrap()
        .write_bytes(&damaged)
        .unwrap();
    assert_corrupt(queue.list());
    let backup = queue.reset().unwrap().unwrap();
    let directory = PrivateDirectory::open(queue.path().parent().unwrap()).unwrap();
    drop(directory.open_private(&backup, false).unwrap());
    assert_eq!(
        fs::read(queue.path().with_file_name(&backup)).unwrap(),
        damaged
    );
    assert_eq!(fs::read(&key_path).unwrap(), key);
    assert!(queue.list().unwrap().is_empty());
    Store::new(queue.path())
        .lock()
        .unwrap()
        .write_bytes(&original)
        .unwrap();
    assert_eq!(
        queue
            .payload(&queue.list().unwrap()[0])
            .unwrap()
            .password
            .as_deref(),
        Some("super-secret-link-pw")
    );
}

#[test]
fn malformed_queue_is_copied_once_without_creating_a_key_and_reset_can_recover() {
    for raw in [
        b"not json".as_slice(),
        b"{ this is not json ",
        b"{ this is not json",
        b"garbage",
        b"still not json",
        b"not json at all",
    ] {
        let (_scratch, queue) = fixture();
        Store::new(queue.path())
            .lock()
            .unwrap()
            .write_bytes(raw)
            .unwrap();
        for _ in 0..3 {
            assert_corrupt(Queue::new(queue.path()).list());
            assert_corrupt(queue.add(JobType::Download, &payload(Some("super-secret-link-pw"))));
            assert_eq!(fs::read(queue.path()).unwrap(), raw);
            assert!(!queue.path().with_file_name("queue.json.key").exists());
        }
        let backups: Vec<_> = fs::read_dir(queue.path().parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("queue.json.corrupt-")
            })
            .collect();
        assert_eq!(backups.len(), 1);
        assert_eq!(fs::read(&backups[0]).unwrap(), raw);
        assert_eq!(
            queue.reset().unwrap().unwrap(),
            backups[0].file_name().unwrap()
        );
        assert!(queue.list().unwrap().is_empty());
        queue.add(JobType::Download, &payload(Some("p"))).unwrap();
        assert_eq!(
            queue
                .payload(&queue.list().unwrap()[0])
                .unwrap()
                .password
                .as_deref(),
            Some("p")
        );
        assert_eq!(fs::read(&backups[0]).unwrap(), raw);
    }
}

#[path = "common/private_tempfile.rs"]
mod private_tempfile;
