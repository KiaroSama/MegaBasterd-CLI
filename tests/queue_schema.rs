// SPDX-License-Identifier: GPL-3.0-or-later
//! Fresh queue documents reject malformed metadata and authenticated invalid payloads atomically.
#![allow(clippy::unwrap_used)]

use std::{fs, path::Path};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use megabasterd_cli::{
    crypto::wire,
    error::Error,
    storage::{
        files::Store,
        queue::{JobStatus, JobType, Queue, QueuePayload},
    },
};
use serde_json::{Value, json};

struct Fixture {
    _scratch: private_tempfile::TempDir,
    queue: Queue,
    document: Value,
    key: Vec<u8>,
    nonce: u64,
}

impl Fixture {
    fn new() -> Self {
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/queue-schema");
        fs::create_dir_all(&base).unwrap();
        let scratch = private_tempfile::tempdir_in(base).unwrap();
        let queue = Queue::new(scratch.path().join("private space/queue.json"));
        queue.add(JobType::Download, &payload()).unwrap();
        let key = fs::read(queue.path().with_file_name("queue.json.key")).unwrap();
        let mut document: Value = serde_json::from_slice(&fs::read(queue.path()).unwrap()).unwrap();
        document["data"]["items"][0]["created_iso"] = "2026-01-01T00:00:00+00:00".into();
        document["data"]["items"][0]["size"] = 10.into();
        let fixture = Self {
            _scratch: scratch,
            queue,
            document,
            key,
            nonce: 0,
        };
        fixture.write(&serde_json::to_vec(&fixture.document).unwrap());
        let item = fixture.queue.list().unwrap().remove(0);
        assert_eq!(
            fixture.queue.payload(&item).unwrap().source,
            payload().source
        );
        fixture
    }

    fn write(&self, raw: &[u8]) {
        Store::new(self.queue.path())
            .lock()
            .unwrap()
            .write_bytes(raw)
            .unwrap();
    }

    fn refuse(&self, raw: &[u8]) {
        self.write(raw);
        for mutation in [false, true] {
            let result = if mutation {
                self.queue.add(JobType::Download, &payload()).map(|_| ())
            } else {
                self.queue.list().map(|_| ())
            };
            let error = result.err().unwrap();
            assert!(matches!(&error, Error::Corrupt(_)));
            assert_eq!(error.code(), "storage_corrupt");
            assert_eq!(error.exit_code(), 1);
            assert!(!error.retryable_network());
            assert_eq!(fs::read(self.queue.path()).unwrap(), raw);
        }
        assert_eq!(
            fs::read(self.queue.path().with_file_name("queue.json.key")).unwrap(),
            self.key
        );
        let copies: Vec<_> = fs::read_dir(self.queue.path().parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("queue.json.corrupt-")
            })
            .collect();
        assert_eq!(
            copies
                .iter()
                .filter(|path| fs::read(path).unwrap() == raw)
                .count(),
            1
        );
        assert!(
            !fs::read_dir(self.queue.path().parent().unwrap())
                .unwrap()
                .any(|entry| {
                    entry
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .ends_with(".tmp")
                })
        );
    }

    fn refuse_document(&self, document: &Value) {
        self.refuse(&serde_json::to_vec(document).unwrap());
    }

    fn sealed(&mut self, value: &Value) -> Value {
        // Independent wire-format fixture, not Queue::seal: valid AEAD must reach payload validation.
        self.nonce += 1;
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&self.nonce.to_be_bytes());
        let aad = format!(
            "megabasterd-cli/native-queue/2/{}/Download",
            self.document["data"]["items"][0]["id"].as_str().unwrap()
        );
        let plaintext = serde_json::to_vec(value).unwrap();
        let encrypted = Aes256Gcm::new_from_slice(&self.key)
            .unwrap()
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: &plaintext,
                    aad: aad.as_bytes(),
                },
            )
            .unwrap();
        let mut blob = b"MBQ2".to_vec();
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&encrypted);
        let mut document = self.document.clone();
        document["data"]["items"][0]["enc_payload"] = wire::b64_url_encode(&blob).into();
        document
    }
}

fn payload() -> QueuePayload {
    QueuePayload {
        source: "https://mega.nz/file/ID#<key>".into(),
        destination: "/tmp/out".into(),
        account: None,
        password: None,
        error: None,
    }
}

#[test]
fn malformed_metadata_roots_types_enums_and_mixed_entries_preserve_exact_documents() {
    let fixture = Fixture::new();
    for raw in [
        b"{broken".as_slice(),
        b"{\"not\":\"a list\"}",
        b"\"just a string\"",
        b"null",
        b"42",
        b"\xff not utf-8",
    ] {
        fixture.refuse(raw);
    }
    for data in [
        json!("just a string"),
        json!([]),
        json!({"items":"wrong"}),
        json!({"items":["a string",5,null]}),
        json!({"items":["just a string"]}),
    ] {
        fixture.refuse_document(&json!({"version":2,"data":data}));
    }
    for (field, values) in [
        (
            "status",
            vec![
                Value::Null,
                json!("sideways"),
                json!("weird"),
                json!(["pending"]),
                json!({"v":"pending"}),
            ],
        ),
        (
            "kind",
            vec![
                json!(["download"]),
                json!({"v":"download"}),
                json!(3),
                json!("teleport"),
            ],
        ),
        (
            "size",
            vec![
                json!(true),
                json!(-1),
                json!("10"),
                json!(1.5),
                json!("big"),
            ],
        ),
        ("id", vec![json!(""), json!("   "), json!(42)]),
        ("run_id", vec![json!(17)]),
        ("heartbeat_iso", vec![json!(["now"])]),
        ("finished_iso", vec![json!({"at":"now"})]),
        (
            "enc_payload",
            vec![json!(99), json!("!!! not base64 !!!"), json!("%%%")],
        ),
        ("created_iso", vec![json!(20260101)]),
        ("lease_epoch", vec![json!(-1), json!(true), json!("1")]),
    ] {
        for value in values {
            let mut bad = fixture.document.clone();
            bad["data"]["items"][0][field] = value;
            fixture.refuse_document(&bad);
        }
    }
    for field in [
        "id",
        "kind",
        "size",
        "status",
        "created_iso",
        "lease_epoch",
        "enc_payload",
    ] {
        let mut bad = fixture.document.clone();
        bad["data"]["items"][0]
            .as_object_mut()
            .unwrap()
            .remove(field);
        fixture.refuse_document(&bad);
    }
    let mut mixed = fixture.document.clone();
    let mut invalid = mixed["data"]["items"][0].clone();
    invalid["id"] = "1".repeat(32).into();
    invalid["size"] = true.into();
    mixed["data"]["items"].as_array_mut().unwrap().push(invalid);
    fixture.refuse_document(&mixed);
    let mut duplicate = fixture.document.clone();
    duplicate["data"]["items"]
        .as_array_mut()
        .unwrap()
        .push(fixture.document["data"]["items"][0].clone());
    fixture.refuse_document(&duplicate);
    let mut wrong_size = fixture.document.clone();
    wrong_size["data"]["items"][0]["size"] = true.into();
    fixture.refuse_document(&wrong_size);
    let backup = fixture.queue.reset().unwrap().unwrap();
    assert_eq!(
        fs::read(fixture.queue.path().with_file_name(backup)).unwrap(),
        serde_json::to_vec(&wrong_size).unwrap()
    );
    assert!(fixture.queue.list().unwrap().is_empty());
    fixture.queue.add(JobType::Download, &payload()).unwrap();
    assert_eq!(fixture.queue.list().unwrap().len(), 1);
}

#[test]
fn authenticated_payload_type_and_blank_source_violations_are_domain_errors_not_partial_loads() {
    let mut fixture = Fixture::new();
    let valid = serde_json::to_value(payload()).unwrap();
    let control = fixture.sealed(&valid);
    fixture.write(&serde_json::to_vec(&control).unwrap());
    let item = fixture.queue.list().unwrap().remove(0);
    assert_eq!(
        fixture.queue.payload(&item).unwrap().destination,
        "/tmp/out"
    );
    for (field, values) in [
        (
            "source",
            vec![
                json!(""),
                json!("   "),
                json!("  "),
                json!("\t\n"),
                json!(17),
                Value::Null,
            ],
        ),
        ("destination", vec![json!([]), json!(false)]),
        ("error", vec![json!(500)]),
        ("account", vec![json!([])]),
        ("password", vec![json!(1234)]),
    ] {
        for value in values {
            let mut bad = valid.clone();
            bad[field] = value;
            let document = fixture.sealed(&bad);
            fixture.refuse_document(&document);
        }
    }
    for field in ["source", "destination"] {
        let mut bad = valid.clone();
        bad.as_object_mut().unwrap().remove(field);
        let document = fixture.sealed(&bad);
        fixture.refuse_document(&document);
    }
    fixture.write(&serde_json::to_vec(&control).unwrap());
    assert_eq!(
        fixture
            .queue
            .payload(&fixture.queue.list().unwrap()[0])
            .unwrap()
            .source,
        payload().source
    );
}

#[test]
fn timestamps_and_lease_state_consistency_are_checked_before_mutation() {
    let fixture = Fixture::new();
    for stamp in [
        "2026-01-01T00:00:00",
        "not-a-date",
        "nope",
        "2026-13-45T99:99:99+00:00",
        "01/01/2026",
    ] {
        let mut bad = fixture.document.clone();
        bad["data"]["items"][0]["created_iso"] = stamp.into();
        fixture.refuse_document(&bad);
    }
    for field in ["finished_iso", "heartbeat_iso"] {
        let mut bad = fixture.document.clone();
        let item = &mut bad["data"]["items"][0];
        item["status"] = if field == "finished_iso" {
            "done"
        } else {
            "active"
        }
        .into();
        if field == "heartbeat_iso" {
            item["run_id"] = "run-1".into();
            item["lease_epoch"] = 1.into();
        }
        item[field] = "whenever".into();
        fixture.refuse_document(&bad);
    }
    for status in ["pending", "done", "failed", "canceled", "interrupted"] {
        for heartbeat in [false, true] {
            let mut bad = fixture.document.clone();
            let item = &mut bad["data"]["items"][0];
            item["status"] = status.into();
            item["run_id"] = "run-1".into();
            if heartbeat {
                item["heartbeat_iso"] = "2026-01-02T00:00:00Z".into();
            }
            if matches!(status, "done" | "failed" | "canceled") {
                item["finished_iso"] = "2026-01-02T00:00:00+00:00".into();
            }
            fixture.refuse_document(&bad);
        }
    }
    let mut finished_pending = fixture.document.clone();
    finished_pending["data"]["items"][0]["finished_iso"] = "2026-01-02T00:00:00+00:00".into();
    fixture.refuse_document(&finished_pending);
}

#[test]
fn supported_optional_nulls_distinct_jobs_and_utc_z_remain_usable() {
    let mut fixture = Fixture::new();
    let mut value = payload();
    value.destination.clear();
    let empty_destination = fixture.queue.add(JobType::Upload, &value).unwrap();
    let items = fixture.queue.list().unwrap();
    assert_eq!(items.len(), 2);
    assert_ne!(items[0].id, empty_destination);
    assert_eq!(items[1].id, empty_destination);
    let decoded = fixture.queue.payload(&items[1]).unwrap();
    assert!(decoded.destination.is_empty());
    assert!(decoded.account.is_none() && decoded.password.is_none() && decoded.error.is_none());
    let mut document: Value =
        serde_json::from_slice(&fs::read(fixture.queue.path()).unwrap()).unwrap();
    let first_id = items[0].id.clone();
    let first = &mut document["data"]["items"][0];
    first["created_iso"] = "2026-01-01T00:00:00Z".into();
    first["status"] = "done".into();
    first["size"] = 0.into();
    first["finished_iso"] = "2026-01-02T00:00:00Z".into();
    fixture.write(&serde_json::to_vec(&document).unwrap());
    let items = fixture.queue.list().unwrap();
    assert_eq!(
        items
            .iter()
            .map(|item| item.id.as_str())
            .collect::<Vec<_>>(),
        [first_id.as_str(), empty_destination.as_str()]
    );
    assert_eq!(items[0].status, JobStatus::Done);
    assert_eq!(items[0].size, 0);
    assert!(
        items[1].run_id.is_none()
            && items[1].heartbeat_iso.is_none()
            && items[1].finished_iso.is_none()
    );
    // A native crashed generation may lack its owner, but generation zero is not a legacy reader.
    document["data"]["items"][0]["status"] = "active".into();
    document["data"]["items"][0]["finished_iso"] = Value::Null;
    document["data"]["items"][0]["lease_epoch"] = 1.into();
    let ownerless = serde_json::to_vec(&document).unwrap();
    fixture.write(&ownerless);
    let items = fixture.queue.list().unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].id, first_id);
    assert_eq!(items[0].status, JobStatus::Active);
    assert_eq!(items[0].lease_epoch, 1);
    assert!(items[0].run_id.is_none() && items[0].heartbeat_iso.is_none());
    assert_eq!(fs::read(fixture.queue.path()).unwrap(), ownerless);
    assert_eq!(
        fixture.queue.recover_interrupted().unwrap(),
        std::slice::from_ref(&first_id)
    );
    let recovered = fixture.queue.list().unwrap();
    assert_eq!(recovered.len(), 2);
    assert_eq!(recovered[0].id, first_id);
    assert_eq!(recovered[0].status, JobStatus::Interrupted);
    assert_eq!(recovered[0].lease_epoch, 1);
    assert!(
        recovered[0].run_id.is_none()
            && recovered[0].heartbeat_iso.is_none()
            && recovered[0].finished_iso.is_none()
    );
    assert_eq!(
        fixture.queue.payload(&recovered[0]).unwrap().source,
        payload().source
    );
    assert_eq!(recovered[1].id, empty_destination);
    assert_eq!(recovered[1].status, JobStatus::Pending);
    assert_eq!(
        fs::read(fixture.queue.path().with_file_name("queue.json.key")).unwrap(),
        fixture.key
    );
    assert!(fixture.queue.recover_interrupted().unwrap().is_empty());
    let control = fixture.sealed(&serde_json::to_value(payload()).unwrap());
    fixture.write(&serde_json::to_vec(&control).unwrap());
    assert_eq!(fixture.queue.list().unwrap().len(), 1);
}

#[test]
fn unknown_fields_and_versions_are_preserved_instead_of_silently_dropped() {
    let mut fixture = Fixture::new();
    for level in ["envelope", "data", "item", "payload"] {
        let mut bad = fixture.document.clone();
        match level {
            "envelope" => bad["future"] = json!({"nested":1}),
            "data" => bad["data"]["future"] = json!({"nested":1}),
            "item" => bad["data"]["items"][0]["future"] = json!({"nested":1}),
            _ => {
                let mut payload = serde_json::to_value(payload()).unwrap();
                payload["future"] = json!({"nested":1});
                bad = fixture.sealed(&payload);
            }
        }
        fixture.refuse_document(&bad);
    }
    let before: Vec<_> = fs::read_dir(fixture.queue.path().parent().unwrap())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    for version in [0, 1, 999] {
        let mut document = fixture.document.clone();
        document["version"] = version.into();
        let raw = serde_json::to_vec(&document).unwrap();
        fixture.write(&raw);
        assert!(matches!(fixture.queue.list(), Err(Error::Corrupt(_))));
        assert!(matches!(fixture.queue.reset(), Err(Error::Corrupt(_))));
        assert_eq!(fs::read(fixture.queue.path()).unwrap(), raw);
    }
    let mut after: Vec<_> = fs::read_dir(fixture.queue.path().parent().unwrap())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    let mut before = before;
    before.sort();
    after.sort();
    assert_eq!(after, before);
}

#[path = "common/private_tempfile.rs"]
mod private_tempfile;
