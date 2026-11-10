//! Actual API challenges close unread bodies, send verified proofs and preserve mutation fences.
#![allow(clippy::unwrap_used)]

use std::{
    io::{Read, Write},
    sync::mpsc,
};

use super::*;
use crate::{
    protocol::test_peer,
    storage::proxies::{Pool, Routing},
};

#[test]
fn actual_legacy_and_timestamped_challenges_solve_once_then_return_the_exact_result() {
    for through_proxy in [false, true] {
        for timestamped in [false, true] {
            challenged_request(through_proxy, timestamped, "ug", false);
        }
    }
}

#[test]
fn a_challenged_mutation_can_succeed_but_an_uncertain_proof_response_is_never_replayed() {
    for through_proxy in [false, true] {
        for timestamped in [false, true] {
            for interrupted in [false, true] {
                challenged_request(through_proxy, timestamped, "d", interrupted);
            }
        }
    }
}

fn challenged_request(through_proxy: bool, timestamped: bool, action: &str, interrupted: bool) {
    let token = "AgIC".repeat(16);
    let header = if timestamped {
        format!("1:255:1731410499:{token}")
    } else {
        format!("1:255:{token}")
    };
    let proof = if timestamped {
        format!("1:{token}:AAAAAA")
    } else {
        format!("1:255:{token}:AAAAAA")
    };
    let mut count = 0;
    let (closed, closure) = mpsc::sync_channel(2);
    let reply = |request: &test_peer::Request,
                 stream: &mut rustls::StreamOwned<
        rustls::ServerConnection,
        test_peer::DeadlineSocket,
    >| {
        count += 1;
        assert_eq!(request.method, "POST");
        assert_eq!(request.connect_target.is_some(), through_proxy);
        assert_eq!(
            serde_json::from_slice::<Value>(&request.body).unwrap(),
            json!([{"a":action}])
        );
        assert!(!request.headers.contains_key("proxy-authorization"));
        let url = Url::parse(&format!("https://testserver.com{}", request.path)).unwrap();
        assert_eq!(
            url.query_pairs().find(|(key, _)| key == "id").unwrap().1,
            count.to_string()
        );
        if count == 1 {
            assert!(!request.headers.contains_key("x-hashcash"));
            write!(stream, "HTTP/1.1 402 Payment Required\r\nX-Hashcash: {header}\r\nContent-Length: 4096\r\nConnection: keep-alive\r\n\r\n").unwrap();
        } else {
            assert_eq!(count, 2, "confirmed API response was replayed");
            assert_eq!(request.headers["x-hashcash"], proof);
            if interrupted {
                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 13\r\nConnection: close\r\n\r\n[").unwrap();
                stream.flush().unwrap();
                return;
            }
            let body = if action == "d" {
                &b"[0]"[..]
            } else {
                &b"[{\"ok\":true}]"[..]
            };
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n", body.len()).unwrap();
            stream.write_all(body).unwrap();
        }
        stream.flush().unwrap();
        match stream.read(&mut [0]) {
            Ok(0) => (),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted
                ) =>
            {
                ()
            }
            other => panic!("Hashcash response retained its connection: {other:?}"),
        }
        closed.send(()).unwrap();
    };
    let run = |address| {
        let mut api = Api::test_peer(address).unwrap();
        let proxy = format!("http://127.0.0.1:{}", address.port());
        let pool = Pool::new(vec![proxy.clone()], vec![], None).unwrap();
        if through_proxy {
            api.transport.routing = Routing {
                explicit: None,
                pool: Some(pool.clone()),
                force: true,
            };
        }
        let result = api.request(json!({"a":action}), &[]);
        if interrupted {
            let error = result.unwrap_err();
            assert!(matches!(error, Error::AmbiguousMutation(_)));
            assert_eq!(error.exit_code(), 1);
        } else {
            assert_eq!(
                result.unwrap(),
                if action == "d" {
                    json!(0)
                } else {
                    json!({"ok":true})
                }
            );
        }
        for _ in 0..if interrupted { 1 } else { 2 } {
            closure.recv_timeout(Duration::from_secs(2)).unwrap();
        }
        assert_eq!(api.sequence, 2);
        assert_eq!(
            pool.test_health_counts(&proxy).unwrap(),
            Some((
                u64::from(through_proxy && !interrupted),
                u64::from(through_proxy && interrupted)
            ))
        );
    };
    let ((), calls) = if through_proxy {
        test_peer::with_raw_connect_peer(reply, run)
    } else {
        test_peer::with_raw_peer(reply, run)
    };
    assert_eq!(calls.len(), 2);
}
