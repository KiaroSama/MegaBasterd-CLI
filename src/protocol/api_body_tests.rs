//! API body limits stop decoded streaming and release the response before returning.
#![allow(clippy::unwrap_used)]

use std::{
    io::{self, Cursor, Read, Write},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
};

use flate2::{Compression, write::GzEncoder};

use super::*;
use crate::{
    protocol::{http_response::HttpResponse, test_peer},
    storage::proxies::{Pool, Routing},
};

const CAP: u64 = 4096;
const CHUNK: usize = 1024;

struct Observed<R> {
    inner: R,
    pulled: Arc<AtomicUsize>,
    closed: Arc<AtomicBool>,
}

impl<R: Read> Read for Observed<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = output.len().min(CHUNK);
        let count = self.inner.read(&mut output[..count])?;
        self.pulled.fetch_add(count, Ordering::Relaxed);
        Ok(count)
    }
}

impl<R> Drop for Observed<R> {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Relaxed);
    }
}

fn observed_request(body: impl Read + Send + 'static) -> (Result<Value>, usize, bool) {
    let pulled = Arc::new(AtomicUsize::new(0));
    let closed = Arc::new(AtomicBool::new(false));
    let response = HttpResponse::streamed(
        reqwest::StatusCode::OK,
        HeaderMap::new(),
        Observed {
            inner: body,
            pulled: pulled.clone(),
            closed: closed.clone(),
        },
    );
    let mut response = Some(response);
    let mut api = tests::api();
    let mut calls = 0;
    let result = api.request_with(
        json!({"a":"ug"}),
        &[],
        |_, _, body, payload| {
            calls += 1;
            assert_eq!(
                serde_json::from_slice::<Value>(body).unwrap(),
                json!([{"a":"ug"}])
            );
            let Some(response) = response.take() else {
                panic!("API body was replayed");
            };
            let reply = Reply::test_response(response);
            read_reply(reply, payload, CAP).map_err(AttemptFailure::after)
        },
        |_| panic!("complete or oversized API body gained a retry"),
    );
    assert_eq!(calls, 1);
    assert_eq!(api.sequence, 1);
    assert!(response.is_none());
    // The API is still alive, so closure must come from the individual response owner.
    (
        result,
        pulled.load(Ordering::Relaxed),
        closed.load(Ordering::Relaxed),
    )
}

#[test]
fn oversized_api_body_reads_at_most_the_cap_plus_one_and_drops_without_draining() {
    let (result, pulled, closed) = observed_request(io::repeat(b'x').take(1024 * 1024));
    assert!(
        matches!(result, Err(Error::Protocol(message)) if message == "Decoded response exceeds its size limit")
    );
    assert_eq!(pulled, 4097);
    assert!(pulled <= CAP as usize + CHUNK);
    assert!(closed);
}

#[test]
fn bounded_api_json_returns_the_exact_payload_and_reads_only_its_bytes() {
    for expected in [json!({"ok":true}), json!({"pad":"y".repeat(512)})] {
        let raw = serde_json::to_vec(&json!([expected.clone()])).unwrap();
        let length = raw.len();
        assert!(length < CAP as usize);
        let (result, pulled, closed) = observed_request(Cursor::new(raw));
        assert_eq!(result.unwrap(), expected);
        assert_eq!(pulled, length);
        assert!(closed);
    }
}

#[test]
fn headerless_streamed_non_json_is_a_typed_error_and_closes_without_retry() {
    let raw = b"<html>captive portal</html>";
    let (result, pulled, closed) = observed_request(Cursor::new(raw));
    let error = result.unwrap_err();
    assert!(
        matches!(&error, Error::Protocol(message) if message == "MEGA API returned invalid JSON")
    );
    assert_eq!(error.code(), "protocol_error");
    assert_eq!(error.exit_code(), 1);
    assert_eq!(pulled, raw.len());
    assert!(closed);
}

#[test]
fn exact_content_length_guards_accept_unknown_or_normal_lengths_and_refuse_oversize_before_reading()
{
    use reqwest::header::{CONTENT_LENGTH, CONTENT_TYPE, HeaderValue};

    let oversized = (MAX_RESPONSE_BYTES + 1).to_string();
    for declared in [Some("²"), Some(oversized.as_str()), Some("3"), None] {
        let pulled = Arc::new(AtomicUsize::new(0));
        let closed = Arc::new(AtomicBool::new(false));
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if let Some(value) = declared {
            headers.insert(
                CONTENT_LENGTH,
                HeaderValue::from_bytes(value.as_bytes()).unwrap(),
            );
        }
        let response = HttpResponse::streamed(
            reqwest::StatusCode::OK,
            headers,
            Observed {
                inner: Cursor::new(b"[0]"),
                pulled: pulled.clone(),
                closed: closed.clone(),
            },
        );
        let result = read_reply(
            Reply::test_response(response),
            &json!([{"a":"d"}]),
            MAX_RESPONSE_BYTES,
        );
        if declared == Some(oversized.as_str()) {
            assert!(matches!(result, Err(Error::Protocol(message))
                if message == "Remote response exceeds its size limit"));
            assert_eq!(pulled.load(Ordering::Relaxed), 0);
        } else {
            assert!(matches!(result, Ok(Exchange::Result(value)) if value == json!([0])));
            assert_eq!(pulled.load(Ordering::Relaxed), 3);
        }
        assert!(closed.load(Ordering::Relaxed));
    }
}

#[test]
fn actual_api_identity_and_gzip_streams_stop_without_eof_and_close_the_socket() {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    io::copy(&mut io::repeat(b'x').take(CAP + 1), &mut encoder).unwrap();
    let compressed = encoder.finish().unwrap();
    assert!(compressed.len() < CHUNK);
    for through_proxy in [false, true] {
        for gzip in [false, true] {
            let (closed, closure) = mpsc::sync_channel(1);
            let reply = |request: &test_peer::Request,
                         stream: &mut rustls::StreamOwned<
                rustls::ServerConnection,
                test_peer::DeadlineSocket,
            >| {
                assert_eq!(request.method, "POST");
                assert_eq!(request.connect_target.is_some(), through_proxy);
                assert_eq!(
                    serde_json::from_slice::<Value>(&request.body).unwrap(),
                    json!([{"a":"ug"}])
                );
                assert_eq!(request.headers["content-type"], "application/json");
                assert!(!request.headers.contains_key("proxy-authorization"));
                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n").unwrap();
                if gzip {
                    stream.write_all(b"Content-Encoding: gzip\r\n").unwrap();
                }
                stream.write_all(b"\r\n").unwrap();
                if gzip {
                    stream.write_all(&compressed).unwrap();
                } else {
                    let block = [b'x'; CHUNK];
                    for _ in 0..4 {
                        stream.write_all(&block).unwrap();
                    }
                    stream.write_all(b"x").unwrap();
                }
                stream.flush().unwrap();
                // No EOF or oversized Content-Length: an eager reader waits instead of rejecting.
                match stream.read(&mut [0]) {
                    Ok(0) => (),
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::UnexpectedEof
                                | io::ErrorKind::ConnectionReset
                                | io::ErrorKind::ConnectionAborted
                        ) => {}
                    other => panic!("oversized API response socket remained open: {other:?}"),
                }
                closed.send(()).unwrap();
            };
            let run = |address| {
                let mut api = Api::test_peer(address).unwrap();
                let route = through_proxy.then(|| {
                    let proxy = format!("http://127.0.0.1:{}", address.port());
                    let pool = Pool::new(vec![proxy.clone()], vec![], None).unwrap();
                    for _ in 0..2 {
                        pool.report(&proxy, false).unwrap();
                    }
                    api.transport.routing = Routing {
                        explicit: None,
                        pool: Some(pool.clone()),
                        force: true,
                    };
                    pool
                });
                let transport = api.transport.clone();
                let result = api.request_with(
                    json!({"a":"ug"}),
                    &[],
                    move |url, headers, body, payload| {
                        let reply = transport.send_api(url, headers, body)?;
                        read_reply(reply, payload, CAP).map_err(AttemptFailure::after)
                    },
                    |_| panic!("oversized API response gained a retry"),
                );
                assert!(
                    matches!(result, Err(Error::Protocol(message)) if message == "Decoded response exceeds its size limit")
                );
                closure.recv_timeout(Duration::from_secs(2)).unwrap();
                assert_eq!(api.sequence, 1);
                if let Some(pool) = route {
                    assert!(
                        pool.pick().unwrap().is_none(),
                        "oversized API body was credited or not blamed"
                    );
                }
            };
            let ((), calls) = if through_proxy {
                test_peer::with_raw_connect_peer(reply, run)
            } else {
                test_peer::with_raw_peer(reply, run)
            };
            assert_eq!(calls.len(), 1, "oversized API body was replayed");
        }
    }
}
