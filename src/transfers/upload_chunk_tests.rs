//! Real upload HTTP retry attempts with only the external backoff clock replaced.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::{
    protocol::test_peer::{self, Response},
    storage::proxies::Routing,
};
use std::{
    io::{Read, Write},
    sync::mpsc,
};

pub(super) fn require_eof(
    stream: &mut rustls::StreamOwned<rustls::ServerConnection, test_peer::DeadlineSocket>,
) {
    match stream.read(&mut [0]) {
        Ok(0) => (),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
            ) => {}
        other => panic!("upload retry retained a response connection: {other:?}"),
    }
}

#[test]
fn server_failures_retry_at_most_five_times_but_fixed_400_is_final() {
    for (status, failures, expected_calls, expected_waits) in [
        (503, 5, 5, vec![2, 4, 8, 16]),
        (503, 2, 3, vec![2, 4]),
        (400, 5, 1, vec![]),
    ] {
        let mut calls = 0;
        let mut waits = Vec::new();
        let (closed, closure) = mpsc::sync_channel(5);
        let (result, requests) = test_peer::with_raw_peer(
            |request, stream| {
                assert_eq!(request.method, "POST");
                assert_eq!(request.path, "/native-peer-upload/retries/0");
                assert_eq!(request.body, b"ciphertext");
                calls += 1;
                let status = if calls <= failures { status } else { 200 };
                let body = if calls <= failures {
                    &b""[..]
                } else {
                    &b"TOKEN"[..]
                };
                write!(stream,"HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",body.len()).unwrap();
                stream.write_all(body).unwrap();
                stream.flush().unwrap();
                require_eof(stream);
                closed.send(()).unwrap();
            },
            |address| {
                let control = Control::new();
                let transport = Transport::test_peer(address, control.clone()).unwrap();
                ChunkRequest {
                    transport: &transport,
                    endpoint: "https://upload.mega.nz/native-peer-upload/retries",
                    offset: 0,
                    final_chunk: true,
                    ciphertext: b"ciphertext",
                    limiter: &RateLimiter::new(0.0).unwrap(),
                    control: &control,
                }
                .with_wait(|duration| {
                    closure.recv_timeout(Duration::from_secs(2)).unwrap();
                    waits.push(duration.as_secs());
                    Ok(())
                })
            },
        );
        closure.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(calls, expected_calls);
        assert_eq!(requests.len(), expected_calls);
        assert_eq!(waits, expected_waits);
        if failures < 5 {
            assert!(matches!(result.unwrap(), Delivery::Accepted(Some(token)) if token == "TOKEN"));
        } else {
            assert!(matches!(result, Err(Error::Protocol(message))
                if message == format!("Upload chunk returned HTTP {status}")));
        }
    }
}

#[test]
fn an_unclassified_send_failure_is_returned_once_while_timeouts_keep_the_five_attempt_budget() {
    let control = Control::new();
    let transport = Transport::new(
        Routing {
            explicit: None,
            pool: None,
            force: false,
        },
        Duration::from_secs(1),
        "retry-fixture".into(),
        control.clone(),
    )
    .unwrap();
    let limiter = RateLimiter::new(0.0).unwrap();
    for failure in ["unclassified", "policy", "canceled", "timeout"] {
        let transient = failure == "timeout";
        assert!(control.checkpoint().is_ok());
        let mut attempts = 0;
        let mut waits = Vec::new();
        let result = ChunkRequest {
            transport: &transport,
            endpoint: "https://upload.mega.nz/native-count",
            offset: 0,
            final_chunk: true,
            ciphertext: &[7; 4096],
            limiter: &limiter,
            control: &control,
        }
        .with_send(
            |duration| {
                waits.push(duration.as_secs());
                Ok(())
            },
            |url| {
                attempts += 1;
                assert_eq!(url.as_str(), "https://upload.mega.nz/native-count/0");
                Err(match failure {
                    "unclassified" => Error::Transfer(Box::new(Error::protocol("unclassified"))),
                    "policy" => Error::protocol("no proxy available"),
                    "canceled" => Error::Canceled,
                    "timeout" => Error::Timeout,
                    _ => unreachable!(),
                })
            },
        );
        assert_eq!(attempts, if transient { 5 } else { 1 });
        assert_eq!(waits, if transient { vec![2, 4, 8, 16] } else { vec![] });
        assert!(control.checkpoint().is_ok());
        let error = result.err().unwrap();
        match failure {
            "unclassified" => {
                assert!(matches!(&error, Error::Transfer(cause)
                    if matches!(cause.as_ref(), Error::Protocol(message) if message == "unclassified")));
                assert_eq!(
                    error.to_string(),
                    "Transfer failed: Protocol error: unclassified"
                );
            }
            "policy" => {
                assert!(
                    matches!(&error, Error::Protocol(message) if message == "no proxy available")
                );
                assert_eq!(error.to_string(), "Protocol error: no proxy available");
            }
            "canceled" => {
                assert!(matches!(&error, Error::Canceled));
                assert_eq!(error.to_string(), "The operation was canceled.");
            }
            "timeout" => assert!(matches!(error, Error::Timeout)),
            _ => unreachable!(),
        }
    }
}

#[test]
fn cancellation_during_backoff_and_preexisting_force_policy_never_attempt_another_send() {
    for (policy, pre_canceled) in [(false, false), (true, false), (false, true)] {
        let control = Control::new();
        if pre_canceled {
            control.cancel();
        }
        let mut waits = Vec::new();
        let (result, calls) = test_peer::with_peer(
            |request| {
                assert!(
                    !policy && !pre_canceled,
                    "refused operation contacted the peer"
                );
                assert_eq!(request.method, "POST");
                Some(Response {
                    status: 503,
                    headers: vec![],
                    body: vec![],
                })
            },
            |address| {
                let mut transport = Transport::test_peer(address, control.clone()).unwrap();
                transport.routing.force = policy;
                ChunkRequest {
                    transport: &transport,
                    endpoint: "https://upload.mega.nz/native-peer-upload/retries",
                    offset: 0,
                    final_chunk: true,
                    ciphertext: b"ciphertext",
                    limiter: &RateLimiter::new(0.0).unwrap(),
                    control: &control,
                }
                .with_wait(|duration| {
                    waits.push(duration.as_secs());
                    control.cancel();
                    control.checkpoint()
                })
            },
        );
        if policy {
            assert!(
                matches!(result, Err(Error::Protocol(message)) if message.contains("direct connection was refused"))
            );
            assert!(calls.is_empty() && waits.is_empty());
        } else {
            assert!(matches!(result, Err(Error::Canceled)));
            if pre_canceled {
                assert!(calls.is_empty() && waits.is_empty());
            } else {
                assert_eq!(calls.len(), 1);
                assert_eq!(waits, [2]);
            }
        }
    }
}

#[test]
fn connection_and_body_failures_retry_five_times_and_preserve_the_network_error() {
    for (through_proxy, body_started) in
        [(false, false), (false, true), (true, false), (true, true)]
    {
        let mut waits = Vec::new();
        let reply = |request: &test_peer::Request,
                     stream: &mut rustls::StreamOwned<
            rustls::ServerConnection,
            test_peer::DeadlineSocket,
        >| {
            assert_eq!(request.method, "POST");
            assert_eq!(request.path, "/native-peer-upload/retries/0");
            assert_eq!(request.body, b"ciphertext");
            assert_eq!(request.connect_target.is_some(), through_proxy);
            if body_started {
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nT",
                    )
                    .unwrap();
                stream.flush().unwrap();
            }
            // Drop this owned TLS connection before its headers or complete body arrive.
        };
        let run = |address| {
            let control = Control::new();
            let mut transport = Transport::test_peer(address, control.clone()).unwrap();
            if through_proxy {
                transport.routing = Routing {
                    explicit: Some(format!("http://127.0.0.1:{}", address.port())),
                    pool: None,
                    force: true,
                };
            }
            ChunkRequest {
                transport: &transport,
                endpoint: "https://upload.mega.nz/native-peer-upload/retries",
                offset: 0,
                final_chunk: true,
                ciphertext: b"ciphertext",
                limiter: &RateLimiter::new(0.0).unwrap(),
                control: &control,
            }
            .with_wait(|duration| {
                waits.push(duration.as_secs());
                Ok(())
            })
        };
        let (result, calls) = if through_proxy {
            test_peer::with_raw_connect_peer(reply, run)
        } else {
            test_peer::with_raw_peer(reply, run)
        };
        let error = result.err().unwrap();
        assert!(
            error.retryable_network(),
            "network interruption lost its error type"
        );
        assert_eq!(calls.len(), 5);
        assert_eq!(waits, [2, 4, 8, 16]);
    }
}

#[test]
fn actual_upload_response_timeouts_retry_five_times_and_keep_the_timeout_type() {
    for through_proxy in [false, true] {
        let mut waits = Vec::new();
        let reply = |request: &test_peer::Request,
                     stream: &mut rustls::StreamOwned<
            rustls::ServerConnection,
            test_peer::DeadlineSocket,
        >| {
            assert_eq!(request.body, b"ciphertext");
            assert_eq!(request.connect_target.is_some(), through_proxy);
            // No response: the real request deadline must close this connection, not the peer.
            require_eof(stream);
        };
        let run = |address| {
            let control = Control::new();
            let mut transport = Transport::test_peer(address, control.clone()).unwrap();
            transport.timeout = Duration::from_secs(1);
            if through_proxy {
                transport.routing = Routing {
                    explicit: Some(format!("http://127.0.0.1:{}", address.port())),
                    pool: None,
                    force: true,
                };
            }
            ChunkRequest {
                transport: &transport,
                endpoint: "https://upload.mega.nz/native-peer-upload/retries",
                offset: 0,
                final_chunk: true,
                ciphertext: b"ciphertext",
                limiter: &RateLimiter::new(0.0).unwrap(),
                control: &control,
            }
            .with_wait(|duration| {
                waits.push(duration.as_secs());
                Ok(())
            })
        };
        let (result, calls) = if through_proxy {
            test_peer::with_raw_connect_peer(reply, run)
        } else {
            test_peer::with_raw_peer(reply, run)
        };
        let error = result.err().unwrap();
        assert!(
            matches!(&error, Error::Timeout)
                || matches!(&error, Error::Http(cause) if cause.is_timeout())
        );
        assert!(error.retryable_network());
        assert_eq!(calls.len(), 5);
        assert_eq!(waits, [2, 4, 8, 16]);
    }
}

#[test]
fn malformed_http_and_gzip_are_not_retried_as_transport_interruptions() {
    for response in [
        &b"HTTP/1.1 WRONG\r\nContent-Length: 0\r\n\r\n"[..],
        &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nwrong\r\n"[..],
        &b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 5\r\n\r\nwrong"[..],
    ] {
        let mut waits = Vec::new();
        let (result, calls) = test_peer::with_raw_peer(
            |request, stream| {
                assert_eq!(request.method, "POST");
                assert_eq!(request.body, b"ciphertext");
                stream.write_all(response).unwrap();
                stream.flush().unwrap();
            },
            |address| {
                let control = Control::new();
                let transport = Transport::test_peer(address, control.clone()).unwrap();
                ChunkRequest {
                    transport: &transport,
                    endpoint: "https://upload.mega.nz/native-peer-upload/retries",
                    offset: 0,
                    final_chunk: true,
                    ciphertext: b"ciphertext",
                    limiter: &RateLimiter::new(0.0).unwrap(),
                    control: &control,
                }
                .with_wait(|duration| {
                    waits.push(duration.as_secs());
                    Ok(())
                })
            },
        );
        let error = result.err().unwrap();
        assert!(
            !error.retryable_network(),
            "malformed framing gained a transport retry"
        );
        assert_eq!(calls.len(), 1);
        assert!(waits.is_empty());
    }
}

#[test]
fn oversized_response_headers_are_final_without_waiting_for_the_advertised_body() {
    let mut attempts = 0;
    let mut waits = Vec::new();
    let (result, calls) = test_peer::with_raw_peer(
        |request, stream| {
            assert_eq!(request.body, b"ciphertext");
            attempts += 1;
            if attempts == 1 {
                // Invalid transfer framing is deterministic, not a generic retryable socket error.
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 4097\r\nConnection: close\r\n\r\n",
                    )
                    .unwrap();
                stream.flush().unwrap();
            } else {
                panic!("oversized response was retried");
            }
        },
        |address| {
            let control = Control::new();
            let transport = Transport::test_peer(address, control.clone()).unwrap();
            ChunkRequest {
                transport: &transport,
                endpoint: "https://upload.mega.nz/native-peer-upload/retries",
                offset: 0,
                final_chunk: true,
                ciphertext: b"ciphertext",
                limiter: &RateLimiter::new(0.0).unwrap(),
                control: &control,
            }
            .with_wait(|duration| {
                waits.push(duration.as_secs());
                Ok(())
            })
        },
    );
    assert!(
        matches!(result, Err(Error::Protocol(message)) if message == "Remote response exceeds its size limit")
    );
    assert_eq!(calls.len(), 1);
    assert!(waits.is_empty());
}
