//! Actual download, disk verification, publication and resume through the offline TLS peer.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{
    control::{Control, RateLimiter},
    download::{DownloadOptions, download},
};
use crate::error::Error;
use crate::protocol::{
    api::Api,
    metadata::{DownloadSource, FileInfo},
    test_peer::{self, Request, Response},
};
use crate::storage::transfer_state::States;
use crate::terminal::progress::Progress;

#[path = "download_cancel_peer_tests.rs"]
mod cancel_tests;
#[path = "download_claim_process_tests.rs"]
mod claim_process_tests;
#[path = "download_overwrite_tests.rs"]
mod overwrite_tests;
#[path = "download_resume_peer_tests.rs"]
mod resume_tests;
#[path = "download_ticket_peer_tests.rs"]
mod ticket_tests;

struct Fixture {
    size: u64,
    key: Vec<u8>,
    ciphertext: &'static [u8],
    hash: String,
}

impl Fixture {
    fn new(size: u64) -> Self {
        let vectors: Value =
            serde_json::from_str(include_str!("../../tests/fixtures/transfers/vectors.json"))
                .unwrap();
        let vector = vectors["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["size"] == size)
            .unwrap();
        let ciphertext: &[u8] = match size {
            0 => include_bytes!("../../tests/fixtures/transfers/ciphertext-0.bin"),
            17 => include_bytes!("../../tests/fixtures/transfers/ciphertext-17.bin"),
            131089 => include_bytes!("../../tests/fixtures/transfers/ciphertext-131089.bin"),
            _ => panic!("unknown source vector"),
        };
        assert_eq!(
            hex::encode(Sha256::digest(ciphertext)),
            vector["ciphertext_sha256"].as_str().unwrap()
        );
        Self {
            size,
            key: hex::decode(vector["raw_key"].as_str().unwrap()).unwrap(),
            ciphertext,
            hash: vector["plaintext_sha256"].as_str().unwrap().to_owned(),
        }
    }

    fn info(&self, address: std::net::SocketAddr) -> FileInfo {
        FileInfo {
            name: "OAD -  09v2.mkv".into(),
            size: self.size,
            raw_key: Zeroizing::new(self.key.clone()),
            url: format!("https://testserver.com:{}/cdn", address.port()),
            handle: "fixture".into(),
            public_id: "fixture".into(),
            source: DownloadSource::Public,
        }
    }

    fn reply(&self, request: &Request) -> Response {
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/cdn");
        assert!(request.body.is_empty());
        let range = request.headers["range"].strip_prefix("bytes=").unwrap();
        let (start, end) = range.split_once('-').unwrap();
        let (start, end) = (
            start.parse::<usize>().unwrap(),
            end.parse::<usize>().unwrap(),
        );
        assert!(start <= end && end < self.ciphertext.len());
        Response {
            status: 206,
            headers: vec![(
                "Content-Range".into(),
                format!("bytes {start}-{end}/{}", self.size),
            )],
            body: self.ciphertext[start..=end].to_vec(),
        }
    }

    fn assert_output(&self, path: &Path) {
        let bytes = std::fs::read(path).unwrap();
        assert_eq!(bytes.len() as u64, self.size);
        assert_eq!(hex::encode(Sha256::digest(&bytes)), self.hash);
        assert!(
            bytes
                .iter()
                .enumerate()
                .all(|(index, &byte)| byte == ((index * 13 + 7) % 256) as u8)
        );
    }
}

fn scratch() -> tempfile::TempDir {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/download-peers");
    std::fs::create_dir_all(&root).unwrap();
    tempfile::tempdir_in(root).unwrap()
}

fn options(verify: bool) -> DownloadOptions {
    DownloadOptions {
        workers: 1,
        verify,
        overwrite: false,
        resume: true,
        keep_state: true,
        quota_wait: 0,
        quota_attempts: 1,
    }
}

fn run(
    fixture: &Fixture,
    address: std::net::SocketAddr,
    path: &Path,
    states: &Path,
    control: &Control,
    verify: bool,
) -> crate::error::Result<PathBuf> {
    let mut api = Api::test_peer(address)?;
    // A fresh operation control is shared with its actual HTTP adapter, not a fake transfer worker.
    api.transport = crate::protocol::transport::Transport::test_peer(address, control.clone())?;
    api.control = control.clone();
    let progress = Progress::new(false);
    let item = progress.add(&fixture.info(address).name, fixture.size)?;
    download(
        api,
        fixture.info(address),
        path,
        states,
        &options(verify),
        &RateLimiter::new(0.0)?,
        &progress,
        item,
        control,
    )
}

fn state_path(directory: &Path, destination: &Path) -> PathBuf {
    directory.join(format!(
        "{}.json",
        hex::encode(Sha256::digest(destination.to_string_lossy().as_bytes()))
    ))
}

#[test]
fn source_vectors_download_to_exact_bytes_and_clear_only_completed_state() {
    for size in [0, 17, 131089] {
        let fixture = Fixture::new(size);
        let scratch = scratch();
        let destination = scratch
            .path()
            .join("output with spaces")
            .join("OAD -  09v2.mkv");
        let states = scratch.path().join("private state");
        let (_, calls) = test_peer::with_peer(
            |request| Some(fixture.reply(request)),
            |address| {
                assert_eq!(
                    run(
                        &fixture,
                        address,
                        &destination,
                        &states,
                        &Control::new(),
                        true
                    )
                    .unwrap(),
                    destination
                );
                fixture.assert_output(&destination);
                assert!(
                    States::new(state_path(&states, &destination))
                        .load()
                        .unwrap()
                        .is_none()
                );
                assert!(
                    destination
                        .with_file_name("OAD -  09v2.mkv.mbclaim")
                        .is_file()
                );
            },
        );
        let ranges: Vec<_> = calls.iter().map(|r| r.headers["range"].as_str()).collect();
        assert_eq!(
            ranges,
            match size {
                0 => vec![],
                17 => vec!["bytes=0-16"],
                _ => vec!["bytes=0-131071", "bytes=131072-131088"],
            }
        );
    }
}

#[test]
fn invalid_download_worker_counts_refuse_before_claim_state_or_network_even_without_verify() {
    let fixture = Fixture::new(17);
    let scratch = scratch();
    let destination = scratch.path().join("output").join("must-not-exist.bin");
    let states = scratch.path().join("private state");
    let (_, calls) = test_peer::with_peer(
        |_| panic!("invalid worker count contacted CDN"),
        |address| {
            for workers in [0, 65] {
                let control = Control::new();
                let api = Api::test_peer(address).unwrap();
                let progress = Progress::new(false);
                let item = progress.add("fixture", fixture.size).unwrap();
                let mut options = options(false);
                options.workers = workers;
                let error = download(
                    api,
                    fixture.info(address),
                    &destination,
                    &states,
                    &options,
                    &RateLimiter::new(0.0).unwrap(),
                    &progress,
                    item,
                    &control,
                )
                .unwrap_err();
                assert_eq!(error.exit_code(), 2);
            }
        },
    );
    assert!(calls.is_empty());
    assert!(!states.exists() && !destination.parent().unwrap().exists());
}

#[test]
fn corrupted_ciphertext_fails_disk_mac_without_publishing_a_final_file() {
    let fixture = Fixture::new(17);
    let scratch = scratch();
    let destination = scratch.path().join("damaged.bin");
    let states = scratch.path().join("private state");
    let (_, calls) = test_peer::with_peer(
        |request| {
            let mut response = fixture.reply(request);
            response.body[0] ^= 1;
            Some(response)
        },
        |address| {
            let error = run(
                &fixture,
                address,
                &destination,
                &states,
                &Control::new(),
                true,
            )
            .unwrap_err();
            assert!(matches!(error, Error::Integrity(_)));
            assert!(!destination.exists());
            let saved = States::new(state_path(&states, &destination))
                .load()
                .unwrap()
                .unwrap();
            assert_eq!(saved.completed.len(), 1);
            assert!(scratch.path().join(saved.staging_name.unwrap()).is_file());
        },
    );
    assert_eq!(calls.len(), 1);
}

#[test]
fn streamed_chunk_larger_than_its_range_closes_without_writing_plaintext_or_retrying() {
    for verify in [false, true] {
        let fixture = Fixture::new(131089);
        let scratch = scratch();
        let destination = scratch.path().join("overlong.bin");
        let states = scratch.path().join("private state");
        let (closed, closure) = mpsc::sync_channel(1);
        let (_, calls) = test_peer::with_raw_peer(
            |request, stream| {
                assert_eq!(request.method, "GET");
                assert_eq!(request.path, "/cdn");
                assert_eq!(request.headers["range"], "bytes=0-131071");
                // With no Content-Length, only the streaming cap can refuse this extra byte.
                stream.write_all(b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-131071/131089\r\nConnection: close\r\n\r\n").unwrap();
                stream.write_all(&fixture.ciphertext[..131073]).unwrap();
                stream.flush().unwrap();
                match stream.read(&mut [0]) {
                    Ok(0) => (),
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::UnexpectedEof
                                | std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionAborted
                        ) => {}
                    other => panic!("overlong chunk left its connection open: {other:?}"),
                }
                closed.send(()).unwrap();
            },
            |address| {
                let error = run(
                    &fixture,
                    address,
                    &destination,
                    &states,
                    &Control::new(),
                    verify,
                )
                .unwrap_err();
                assert!(matches!(error, Error::Protocol(message)
                    if message == "Decoded response exceeds its size limit"));
                closure.recv_timeout(Duration::from_secs(2)).unwrap();
                assert!(!destination.exists());
                let saved = States::new(state_path(&states, &destination))
                    .load()
                    .unwrap()
                    .unwrap();
                assert!(saved.completed.is_empty());
                let stage =
                    std::fs::read(scratch.path().join(saved.staging_name.unwrap())).unwrap();
                assert_eq!(stage.len(), fixture.size as usize);
                assert!(stage.iter().all(|&byte| byte == 0));
            },
        );
        assert_eq!(
            calls.len(),
            1,
            "overlong chunk retried or refreshed a ticket"
        );
    }
}

#[test]
fn invalid_range_or_short_body_never_publishes_or_records_completed_coverage() {
    for wrong_range in [false, true] {
        let fixture = Fixture::new(17);
        let scratch = scratch();
        let destination = scratch.path().join("refused.bin");
        let states = scratch.path().join("private state");
        let (_, calls) = test_peer::with_peer(
            |request| {
                let mut response = fixture.reply(request);
                if wrong_range {
                    response.headers[0].1 = "bytes 1-17/17".into();
                } else {
                    response.body.pop();
                }
                Some(response)
            },
            |address| {
                assert!(
                    run(
                        &fixture,
                        address,
                        &destination,
                        &states,
                        &Control::new(),
                        true
                    )
                    .is_err()
                );
                assert!(!destination.exists());
                assert!(
                    States::new(state_path(&states, &destination))
                        .load()
                        .unwrap()
                        .unwrap()
                        .completed
                        .is_empty()
                );
            },
        );
        assert_eq!(calls.len(), 1);
    }
}

#[test]
fn actual_partial_download_refuses_unhonored_ranges_before_decryption_even_without_mac_verification()
 {
    for variant in ["full200", "wrong-window", "missing-range", "unknown-total"] {
        let fixture = Fixture::new(131089);
        let scratch = scratch();
        let destination = scratch.path().join("refused.bin");
        let states = scratch.path().join("private state");
        let (_, calls) = test_peer::with_peer(
            |request| {
                assert_eq!(request.headers["range"], "bytes=0-131071");
                let mut response = fixture.reply(request);
                match variant {
                    "full200" => {
                        response.status = 200;
                        response.headers.clear();
                    }
                    "wrong-window" => response.headers[0].1 = "bytes 1-131072/131089".into(),
                    "missing-range" => response.headers.clear(),
                    "unknown-total" => response.headers[0].1 = "bytes 0-131071/*".into(),
                    _ => unreachable!(),
                }
                Some(response)
            },
            |address| {
                let error = run(
                    &fixture,
                    address,
                    &destination,
                    &states,
                    &Control::new(),
                    false,
                )
                .unwrap_err();
                assert!(matches!(error, Error::Protocol(_)), "{variant}: {error}");
                assert_eq!(error.exit_code(), 1);
                assert!(!destination.exists());
                let saved = States::new(state_path(&states, &destination))
                    .load()
                    .unwrap()
                    .unwrap();
                assert!(saved.completed.is_empty());
                let stage =
                    std::fs::read(scratch.path().join(saved.staging_name.unwrap())).unwrap();
                assert_eq!(stage.len(), 131089);
                assert!(
                    stage.iter().all(|&byte| byte == 0),
                    "Unvalidated ciphertext reached the staged plaintext"
                );
            },
        );
        assert_eq!(
            calls.len(),
            1,
            "Protocol refusal must not retry or refresh a CDN ticket"
        );
    }
}

#[test]
fn resume_skips_only_verified_disk_chunks_and_refetches_locally_tampered_coverage() {
    for tamper in [false, true] {
        let fixture = Fixture::new(131089);
        let scratch = scratch();
        let destination = scratch.path().join("resume.bin");
        let states = scratch.path().join("private state");
        let mut tails = 0;
        let (_, calls) = test_peer::with_peer(
            |request| {
                if request.headers["range"] == "bytes=131072-131088" {
                    tails += 1;
                    if tails == 1 {
                        return Some(Response {
                            status: 400,
                            headers: vec![],
                            body: vec![],
                        });
                    }
                }
                Some(fixture.reply(request))
            },
            |address| {
                assert!(
                    run(
                        &fixture,
                        address,
                        &destination,
                        &states,
                        &Control::new(),
                        true
                    )
                    .is_err()
                );
                assert!(!destination.exists());
                let saved = States::new(state_path(&states, &destination))
                    .load()
                    .unwrap()
                    .unwrap();
                assert_eq!(saved.completed.keys().copied().collect::<Vec<_>>(), [0]);
                if tamper {
                    let directory =
                        crate::platform::secure_files::OutputDirectory::open(scratch.path())
                            .unwrap();
                    let mut stage = directory
                        .open_file(
                            std::ffi::OsStr::new(saved.staging_name.as_ref().unwrap()),
                            false,
                        )
                        .unwrap();
                    stage.seek(SeekFrom::Start(7)).unwrap();
                    stage.write_all(b"!").unwrap();
                    stage.sync_all().unwrap();
                }
                run(
                    &fixture,
                    address,
                    &destination,
                    &states,
                    &Control::new(),
                    true,
                )
                .unwrap();
                fixture.assert_output(&destination);
            },
        );
        let ranges: Vec<_> = calls.iter().map(|r| r.headers["range"].as_str()).collect();
        let expected = if tamper {
            vec![
                "bytes=0-131071",
                "bytes=131072-131088",
                "bytes=0-131071",
                "bytes=131072-131088",
            ]
        } else {
            vec![
                "bytes=0-131071",
                "bytes=131072-131088",
                "bytes=131072-131088",
            ]
        };
        assert_eq!(ranges, expected);
    }
}

#[test]
fn cancellation_after_a_committed_chunk_preserves_exact_resume_coverage_in_both_verify_modes() {
    for verify in [false, true] {
        let fixture = Fixture::new(131089);
        let scratch = scratch();
        let destination = scratch.path().join("canceled-resume.bin");
        let states = scratch.path().join("private state");
        let control = Control::new();
        let (_, calls) = test_peer::with_peer(
            |request| {
                if request.headers["range"] == "bytes=131072-131088" {
                    // One worker cannot request this tail before committing the first chunk.
                    control.cancel();
                }
                Some(fixture.reply(request))
            },
            |address| {
                let error =
                    run(&fixture, address, &destination, &states, &control, verify).unwrap_err();
                assert!(matches!(error, Error::Canceled));
                assert_eq!(error.exit_code(), 130);
                assert!(!destination.exists());
                let saved = States::new(state_path(&states, &destination))
                    .load()
                    .unwrap()
                    .unwrap();
                assert_eq!(saved.completed.keys().copied().collect::<Vec<_>>(), [0]);
                let stage =
                    std::fs::read(scratch.path().join(saved.staging_name.unwrap())).unwrap();
                assert_eq!(stage.len(), fixture.size as usize);
                assert!(
                    stage[..131072]
                        .iter()
                        .enumerate()
                        .all(|(index, &byte)| byte == ((index * 13 + 7) % 256) as u8)
                );
                assert!(stage[131072..].iter().all(|&byte| byte == 0));
            },
        );
        assert_eq!(
            calls
                .iter()
                .map(|request| request.headers["range"].as_str())
                .collect::<Vec<_>>(),
            ["bytes=0-131071", "bytes=131072-131088"]
        );
    }
}

#[test]
fn cancellation_during_the_real_reply_never_publishes_even_without_verification() {
    for verify in [false, true] {
        let fixture = Fixture::new(17);
        let scratch = scratch();
        let destination = scratch.path().join("canceled.bin");
        let states = scratch.path().join("private state");
        let control = Control::new();
        let (_, calls) = test_peer::with_peer(
            |request| {
                control.cancel();
                Some(fixture.reply(request))
            },
            |address| {
                let error =
                    run(&fixture, address, &destination, &states, &control, verify).unwrap_err();
                assert_eq!(error.exit_code(), 130);
                assert!(!destination.exists());
            },
        );
        assert_eq!(calls.len(), 1);
    }
}
