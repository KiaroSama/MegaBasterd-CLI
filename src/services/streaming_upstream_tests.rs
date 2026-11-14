//! Exact upstream response policy through the real local HTTP/TLS stream path.
#![allow(clippy::unwrap_used)]

use super::{info, local, local_outcome};
use crate::error::Error;
use crate::protocol::{
    api::Api,
    test_peer::{self, Response},
};
use crate::services::streaming::StreamServer;
use crate::transfers::control::Control;
use serde_json::{Value, json};
use std::sync::atomic::{AtomicUsize, Ordering};

const SIZE: usize = 4096;
const CIPHERTEXT: &[u8] = include_bytes!("../../tests/fixtures/transfers/ciphertext-131089.bin");

#[test]
fn unaligned_stream_pump_preserves_exact_plaintext_across_short_and_single_byte_reads() {
    use std::io::{self, Read};
    use std::time::{Duration, Instant};

    struct Segmented<'a> {
        bytes: &'a [u8],
        first: Option<usize>,
        block: usize,
        reads: Vec<usize>,
    }
    impl Read for Segmented<'_> {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            let count = self
                .first
                .take()
                .unwrap_or(self.block)
                .min(output.len())
                .min(self.bytes.len());
            output[..count].copy_from_slice(&self.bytes[..count]);
            self.bytes = &self.bytes[count..];
            if count != 0 {
                self.reads.push(count);
            }
            Ok(count)
        }
    }

    let key: Vec<u8> = (0..16).collect();
    let nonce: Vec<u8> = (0..8).collect();
    for (start, first, block, reads) in [
        (5usize, 2usize, 64usize, vec![2, 57]),
        (5, 64, 64, vec![59]),
        (15, 1, 1, vec![1; 49]),
    ] {
        // The independent source fixture supplies ciphertext; the target only decrypts it.
        let mut source = Segmented {
            bytes: &CIPHERTEXT[start..64],
            first: Some(first),
            block,
            reads: Vec::new(),
        };
        let mut cipher =
            crate::crypto::wire::MegaCtr::at_offset(&key, &nonce, start as u64).unwrap();
        let mut output = Vec::new();
        super::super::pump(
            &mut source,
            &mut cipher,
            (64 - start) as u64,
            &Control::new(),
            Instant::now() + Duration::from_secs(1),
            |bytes| {
                output.extend_from_slice(bytes);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(source.reads, reads);
        assert!(source.bytes.is_empty());
        assert_eq!(
            output,
            (start..64)
                .map(|index| ((13 * index + 7) % 256) as u8)
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn a_paused_stream_pump_expires_without_reading_or_emitting_bytes() {
    use std::io::Cursor;
    use std::time::{Duration, Instant};

    let control = Control::new();
    assert!(control.toggle_pause().unwrap());
    struct CancelOnDrop(Control);
    impl Drop for CancelOnDrop {
        fn drop(&mut self) {
            self.0.cancel();
        }
    }
    let (finished, done) = std::sync::mpsc::sync_channel(1);
    std::thread::scope(|scope| {
        let shutdown = CancelOnDrop(control.clone());
        let worker_control = &control;
        let worker = scope.spawn(move || {
            let mut source = Cursor::new(&CIPHERTEXT[..64]);
            let mut cipher = crate::crypto::wire::MegaCtr::at_offset(&[0; 16], &[0; 8], 0).unwrap();
            let mut output = Vec::new();
            let result = super::super::pump(
                &mut source,
                &mut cipher,
                64,
                worker_control,
                Instant::now() + Duration::from_millis(25),
                |bytes| {
                    output.extend_from_slice(bytes);
                    Ok(())
                },
            );
            finished.send((result, source.position(), output)).unwrap();
        });
        let (result, position, output) = done.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(result, Err(Error::Timeout)));
        assert_eq!(position, 0);
        assert!(output.is_empty() && !control.is_canceled());
        assert!(!control.toggle_pause().unwrap());
        worker.join().unwrap();
        drop(shutdown);
    });
}

#[test]
fn exact_source_upstream_range_failures_return_502_without_serving_plaintext_or_retrying() {
    for (status, content_range, length) in [
        (200, None, SIZE),
        (206, None, 1024),
        (206, Some("bytes 0-1023/4096"), 1024),
        (206, Some("bytes 1024-4095/4096"), 1024),
        (206, Some("bytes 1024-2047/9999"), 1024),
        (206, Some("bytes */4096"), 1024),
        (206, Some("chunks 1024-2047/4096"), 1024),
        (206, Some("garbage"), 1024),
        (206, Some("bytes 1024-2047/4096"), 99),
    ] {
        let (_, calls) = test_peer::with_peer(
            |request| {
                assert_eq!(request.method, "GET");
                assert_eq!(request.path, "/cdn");
                assert_eq!(request.headers["range"], "bytes=1024-2047");
                Some(Response {
                    status,
                    headers: content_range
                        .map(|value| vec![("Content-Range".into(), value.into())])
                        .unwrap_or_default(),
                    body: CIPHERTEXT[..length].to_vec(),
                })
            },
            |address| {
                let mut source = info(address);
                source.size = SIZE as u64;
                let server = StreamServer::bind(
                    "127.0.0.1",
                    0,
                    Api::test_peer(address).unwrap(),
                    source,
                    None,
                    false,
                )
                .unwrap();
                let (response, handled) = local_outcome(
                    &server,
                    b"GET / HTTP/1.1\r\nHost: localhost\r\nRange: bytes=1024-2047\r\n\r\n",
                    &Control::new(),
                );
                assert_eq!(response.status, 502);
                assert_eq!(response.body, b"Upstream stream unavailable");
                assert_eq!(
                    response.headers["content-length"],
                    response.body.len().to_string()
                );
                assert!(!response.headers.contains_key("content-range"));
                assert!(!response.headers.contains_key("content-disposition"));
                assert!(matches!(handled, Err(Error::Protocol(_))));
            },
        );
        assert_eq!(
            calls.len(),
            1,
            "invalid ranges must neither refresh nor retry"
        );
    }
}

#[test]
fn exact_source_partial_unaligned_and_whole_file_successes_preserve_plaintext_bytes() {
    for (start, end, upstream_status, partial) in [
        (1024, 2047, 206, true),
        (1008, 2047, 206, true),
        (0, 4095, 200, false),
        (0, 4095, 206, false),
    ] {
        let (_, calls) = test_peer::with_peer(
            |request| {
                assert_eq!(request.method, "GET");
                assert_eq!(request.path, "/cdn");
                assert_eq!(request.headers["range"], format!("bytes={start}-{end}"));
                Some(Response {
                    status: upstream_status,
                    headers: if upstream_status == 206 {
                        vec![(
                            "Content-Range".into(),
                            format!("bytes {start}-{end}/{SIZE}"),
                        )]
                    } else {
                        vec![]
                    },
                    body: CIPHERTEXT[start..=end].to_vec(),
                })
            },
            |address| {
                let mut source = info(address);
                source.size = SIZE as u64;
                let server = StreamServer::bind(
                    "127.0.0.1",
                    0,
                    Api::test_peer(address).unwrap(),
                    source,
                    None,
                    false,
                )
                .unwrap();
                let range = if partial {
                    format!("Range: bytes={start}-{end}\r\n")
                } else {
                    String::new()
                };
                let response = local(
                    &server,
                    format!("GET / HTTP/1.1\r\nHost: localhost\r\n{range}\r\n").as_bytes(),
                    &Control::new(),
                );
                assert_eq!(response.status, if partial { 206 } else { 200 });
                // Independent source-oracle plaintext recipe, not the target cipher.
                assert_eq!(
                    response.body,
                    (start..=end)
                        .map(|i| ((13 * i + 7) % 256) as u8)
                        .collect::<Vec<_>>()
                );
                assert_eq!(
                    response.headers["content-length"],
                    (end - start + 1).to_string()
                );
                if partial {
                    assert_eq!(
                        response.headers["content-range"],
                        format!("bytes {start}-{end}/{SIZE}")
                    );
                } else {
                    assert!(!response.headers.contains_key("content-range"));
                }
            },
        );
        assert_eq!(calls.len(), 1);
    }
}

#[test]
fn expired_public_cdn_refreshes_once_then_validates_the_retried_range() {
    for invalid_after_refresh in [false, true] {
        let step = AtomicUsize::new(0);
        let (_, calls) = test_peer::with_peer(
            |request| match step.fetch_add(1, Ordering::SeqCst) {
                0 => {
                    assert_eq!(request.method, "GET");
                    assert_eq!(request.path, "/cdn");
                    assert_eq!(request.headers["range"], "bytes=1024-2047");
                    Some(Response {
                        status: 403,
                        headers: vec![],
                        body: vec![],
                    })
                }
                1 => {
                    assert_eq!(request.method, "POST");
                    assert!(request.path.starts_with("/cs?"));
                    let command: Value = serde_json::from_slice(&request.body).unwrap();
                    assert_eq!(command, json!([{"a":"g","g":1,"ssl":2,"p":"fixture"}]));
                    let host = &request.headers["host"];
                    Some(Response {
                        status: 200,
                        headers: vec![("Content-Type".into(), "application/json".into())],
                        body: serde_json::to_vec(
                            &json!([{"s":SIZE,"g":format!("https://{host}/fresh")}]),
                        )
                        .unwrap(),
                    })
                }
                2 => {
                    assert_eq!(request.method, "GET");
                    assert_eq!(request.path, "/fresh");
                    assert_eq!(request.headers["range"], "bytes=1024-2047");
                    Some(Response {
                        status: 206,
                        headers: vec![(
                            "Content-Range".into(),
                            if invalid_after_refresh {
                                "bytes 0-1023/4096"
                            } else {
                                "bytes 1024-2047/4096"
                            }
                            .into(),
                        )],
                        body: CIPHERTEXT[1024..2048].to_vec(),
                    })
                }
                _ => panic!("stream retried beyond its one refresh"),
            },
            |address| {
                let mut source = info(address);
                source.size = SIZE as u64;
                let server = StreamServer::bind(
                    "127.0.0.1",
                    0,
                    Api::test_peer(address).unwrap(),
                    source,
                    None,
                    false,
                )
                .unwrap();
                let (response, handled) = local_outcome(
                    &server,
                    b"GET / HTTP/1.1\r\nHost: localhost\r\nRange: bytes=1024-2047\r\n\r\n",
                    &Control::new(),
                );
                if invalid_after_refresh {
                    assert_eq!(response.status, 502);
                    assert_eq!(response.body, b"Upstream stream unavailable");
                    assert!(matches!(handled, Err(Error::Protocol(_))));
                } else {
                    handled.unwrap();
                    assert_eq!(response.status, 206);
                    assert_eq!(response.headers["content-range"], "bytes 1024-2047/4096");
                    assert_eq!(
                        response.body,
                        (1024..2048)
                            .map(|i| ((13 * i + 7) % 256) as u8)
                            .collect::<Vec<_>>()
                    );
                }
            },
        );
        assert_eq!(calls.len(), 3);
        assert_eq!(step.load(Ordering::SeqCst), 3);
    }
}
