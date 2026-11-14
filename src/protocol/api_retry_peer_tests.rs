//! Actual API exchanges distinguish network interruption, malformed bodies and sent mutations.
#![allow(clippy::unwrap_used)]

use std::io::Write;

use super::*;
use crate::{protocol::test_peer, storage::proxies::Routing};

#[derive(Clone, Copy, Debug)]
enum Interruption {
    Headers,
    Body,
    GzipBody,
}

fn exchange(api: &mut Api, action: &str, waits: &mut Vec<u64>) -> Result<Value> {
    let transport = api.transport.clone();
    api.request_with(
        json!({"a": action}),
        &[],
        move |url, headers, body, payload| {
            let reply = transport.send_api(url, headers, body)?;
            read_reply(reply, payload, MAX_RESPONSE_BYTES).map_err(AttemptFailure::after)
        },
        |duration| {
            waits.push(duration.as_secs());
            Ok(())
        },
    )
}

fn route(api: &mut Api, address: std::net::SocketAddr, through_proxy: bool) {
    if through_proxy {
        api.transport.routing = Routing {
            explicit: Some(format!("http://127.0.0.1:{}", address.port())),
            pool: None,
            force: true,
        };
    }
}

fn interrupt(
    stream: &mut rustls::StreamOwned<rustls::ServerConnection, test_peer::DeadlineSocket>,
    interruption: Interruption,
) {
    match interruption {
        Interruption::Headers => (),
        Interruption::Body => stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 10\r\nConnection: close\r\n\r\n[").unwrap(),
        Interruption::GzipBody => stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: 10\r\nConnection: close\r\n\r\n\x1f\x8b").unwrap(),
    }
    stream.flush().unwrap();
}

#[test]
fn interrupted_actual_reads_recover_but_sent_mutations_are_never_replayed() {
    for through_proxy in [false, true] {
        for interruption in [
            Interruption::Headers,
            Interruption::Body,
            Interruption::GzipBody,
        ] {
            for action in ["g", "p"] {
                let mut attempts = 0;
                let mut waits = Vec::new();
                let reply = |request: &test_peer::Request,
                             stream: &mut rustls::StreamOwned<
                    rustls::ServerConnection,
                    test_peer::DeadlineSocket,
                >| {
                    attempts += 1;
                    assert_eq!(request.method, "POST");
                    assert_eq!(request.connect_target.is_some(), through_proxy);
                    assert_eq!(
                        serde_json::from_slice::<Value>(&request.body).unwrap(),
                        json!([{"a":action}])
                    );
                    if attempts == 1 {
                        interrupt(stream, interruption);
                    } else {
                        assert_eq!(action, "g", "a sent mutation was replayed");
                        assert_eq!(attempts, 2);
                        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 10\r\nConnection: close\r\n\r\n[{\"ok\":1}]").unwrap();
                        stream.flush().unwrap();
                    }
                };
                let run = |address| {
                    let mut api = Api::test_peer(address).unwrap();
                    route(&mut api, address, through_proxy);
                    let result = exchange(&mut api, action, &mut waits);
                    assert_eq!(api.sequence, if action == "g" { 2 } else { 1 });
                    result
                };
                let (result, requests) = if through_proxy {
                    test_peer::with_raw_connect_peer(reply, run)
                } else {
                    test_peer::with_raw_peer(reply, run)
                };
                if action == "g" {
                    assert_eq!(result.unwrap(), json!({"ok":1}));
                    assert_eq!(requests.len(), 2);
                    assert_eq!(waits, [2]);
                } else {
                    assert!(matches!(result, Err(Error::AmbiguousMutation(_))));
                    assert_eq!(requests.len(), 1);
                    assert!(waits.is_empty());
                }
            }
        }
    }
}

#[test]
fn actual_read_interruptions_stop_after_five_attempts_without_losing_the_cause() {
    for through_proxy in [false, true] {
        let mut waits = Vec::new();
        let reply = |_: &test_peer::Request,
                     stream: &mut rustls::StreamOwned<
            rustls::ServerConnection,
            test_peer::DeadlineSocket,
        >| {
            interrupt(stream, Interruption::Body);
        };
        let run = |address| {
            let mut api = Api::test_peer(address).unwrap();
            route(&mut api, address, through_proxy);
            let result = exchange(&mut api, "g", &mut waits);
            assert_eq!(api.sequence, 5);
            result
        };
        let (result, requests) = if through_proxy {
            test_peer::with_raw_connect_peer(reply, run)
        } else {
            test_peer::with_raw_peer(reply, run)
        };
        let error = result.unwrap_err();
        assert!(
            matches!(error, Error::Io(_)),
            "body error lost its I/O type"
        );
        assert!(transient(&error));
        assert_eq!(requests.len(), 5);
        assert_eq!(waits, [2, 4, 8, 16]);
    }
}

#[test]
fn malformed_actual_http_and_complete_gzip_bodies_are_final_for_reads() {
    for through_proxy in [false, true] {
        for (gzip, response) in [
            (false, &b"HTTP/1.1 WRONG\r\nContent-Length: 0\r\n\r\n"[..]),
            (
                false,
                &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nwrong\r\n"[..],
            ),
            (
                true,
                &b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 5\r\n\r\nwrong"[..],
            ),
        ] {
            for action in ["g", "p"] {
                let mut waits = Vec::new();
                let reply = |request: &test_peer::Request,
                             stream: &mut rustls::StreamOwned<
                    rustls::ServerConnection,
                    test_peer::DeadlineSocket,
                >| {
                    assert_eq!(
                        serde_json::from_slice::<Value>(&request.body).unwrap(),
                        json!([{"a":action}])
                    );
                    stream.write_all(response).unwrap();
                    stream.flush().unwrap();
                };
                let run = |address| {
                    let mut api = Api::test_peer(address).unwrap();
                    route(&mut api, address, through_proxy);
                    let result = exchange(&mut api, action, &mut waits);
                    assert_eq!(api.sequence, 1);
                    result
                };
                let (result, requests) = if through_proxy {
                    test_peer::with_raw_connect_peer(reply, run)
                } else {
                    test_peer::with_raw_peer(reply, run)
                };
                if action == "p" {
                    assert!(matches!(result, Err(Error::AmbiguousMutation(_))));
                } else {
                    let error = result.unwrap_err();
                    assert!(!transient(&error), "malformed bytes gained a network retry");
                    if gzip {
                        assert!(
                            matches!(error, Error::Protocol(message) if message == "Remote response contains invalid or truncated gzip data")
                        );
                    }
                }
                assert_eq!(requests.len(), 1);
                assert!(waits.is_empty());
            }
        }
    }
}
