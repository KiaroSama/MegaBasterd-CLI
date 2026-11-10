//! Actual API responses release their sockets on rejection and successful reads.
#![allow(clippy::unwrap_used)]

use std::{
    io::{Read, Write},
    sync::{Arc, mpsc},
    time::Duration,
};

use super::*;
use crate::{
    protocol::test_peer,
    storage::proxies::{Pool, Routing},
};

#[derive(Clone, Copy)]
enum Case {
    Status(u16),
    ContentType,
    UntrustedContentType,
    HtmlWithJson,
    DeclaredOversize,
    InvalidJson,
    TopLevelObject,
    Success(bool),
}

fn pooled(api: &mut Api, address: std::net::SocketAddr) -> (Arc<Pool>, String) {
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
    (pool, proxy)
}

fn scenario(case: Case, through_proxy: bool) {
    let (closed, closure) = mpsc::sync_channel(1);
    let reply = |request: &test_peer::Request,
                 stream: &mut rustls::StreamOwned<
        rustls::ServerConnection,
        test_peer::DeadlineSocket,
    >| {
        assert_eq!(request.method, "POST");
        let url = Url::parse(&format!("https://testserver.com{}", request.path)).unwrap();
        assert_eq!(url.path(), "/cs");
        assert_eq!(
            url.query_pairs()
                .collect::<std::collections::BTreeMap<_, _>>(),
            std::collections::BTreeMap::from([
                ("ak".into(), "BdARkQSQ".into()),
                ("id".into(), "1".into())
            ])
        );
        assert_eq!(request.headers["content-type"], "application/json");
        assert!(!request.headers.contains_key("proxy-authorization"));
        assert_eq!(request.connect_target.is_some(), through_proxy);
        assert_eq!(
            serde_json::from_slice::<Value>(&request.body).unwrap(),
            json!([{"a":"ug"}])
        );
        // A keep-alive peer never closes first. Rejections deliberately leave a body unread.
        match case {
            Case::Status(status) => write!(stream, "HTTP/1.1 {status} Fixture\r\nContent-Length: 4096\r\nConnection: keep-alive\r\n\r\n").unwrap(),
            Case::ContentType => stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 4096\r\nConnection: keep-alive\r\n\r\n").unwrap(),
            Case::UntrustedContentType => stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/x-private-header-sentinel\r\nContent-Length: 4096\r\nConnection: keep-alive\r\n\r\n").unwrap(),
            Case::HtmlWithJson => stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\nConnection: keep-alive\r\n\r\n[{\"ok\":true}]").unwrap(),
            Case::DeclaredOversize => stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1073741824\r\nConnection: keep-alive\r\n\r\n").unwrap(),
            Case::InvalidJson => stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1\r\nConnection: keep-alive\r\n\r\n[").unwrap(),
            Case::TopLevelObject => {
                let body = br#"{"unexpected":"object"}"#;
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n", body.len()).unwrap();
                stream.write_all(body).unwrap();
            }
            Case::Success(boolean) => {
                let body = if boolean { &b"[{\"ok\":true}]"[..] } else { &b"[{\"ok\":1}]"[..] };
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n", body.len()).unwrap();
                stream.write_all(body).unwrap();
            }
        }
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
            other => panic!("API response socket remained open: {other:?}"),
        }
        closed.try_send(()).unwrap();
    };
    let run = |address| {
        let mut api = Api::test_peer(address).unwrap();
        let route = through_proxy.then(|| pooled(&mut api, address));
        let result = api.request(json!({"a":"ug"}), &[]);
        match case {
            Case::Status(status) => assert!(
                matches!(result, Err(Error::Protocol(message)) if message == format!("MEGA API returned HTTP {status}"))
            ),
            Case::ContentType | Case::HtmlWithJson => assert!(
                matches!(result, Err(Error::Protocol(message)) if message == "MEGA API returned text/html instead of JSON")
            ),
            Case::UntrustedContentType => assert!(
                matches!(result, Err(Error::Protocol(message)) if message == "MEGA API returned a non-JSON content type")
            ),
            Case::DeclaredOversize => assert!(
                matches!(result, Err(Error::Protocol(message)) if message == "Remote response exceeds its size limit")
            ),
            Case::InvalidJson => assert!(
                matches!(result, Err(Error::Protocol(message)) if message == "MEGA API returned invalid JSON")
            ),
            Case::TopLevelObject => assert!(
                matches!(result, Err(Error::Protocol(message)) if message == "MEGA API returned a JSON object where an array of results was expected")
            ),
            Case::Success(boolean) => assert_eq!(
                result.unwrap(),
                if boolean {
                    json!({"ok":true})
                } else {
                    json!({"ok":1})
                }
            ),
        }
        // Keep the API alive: dropping an outer client must not be needed to close this response.
        closure.recv_timeout(Duration::from_secs(2)).unwrap();
        if let Some((pool, proxy)) = route {
            let expected = match case {
                Case::Status(status) if status != 407 => (0, 2),
                Case::Success(_) => (1, 1),
                _ => (0, 3),
            };
            assert_eq!(pool.test_health_counts(&proxy).unwrap(), Some(expected));
            match case {
                Case::Status(status) if status != 407 => {
                    assert!(
                        pool.pick().unwrap().is_some(),
                        "status failure was blamed or retried"
                    );
                    pool.report(&proxy, false).unwrap();
                    assert!(pool.pick().unwrap().is_none(), "error status earned credit");
                }
                Case::Status(_)
                | Case::ContentType
                | Case::UntrustedContentType
                | Case::HtmlWithJson
                | Case::DeclaredOversize
                | Case::InvalidJson
                | Case::TopLevelObject => {
                    assert!(
                        pool.pick().unwrap().is_none(),
                        "unusable body was not blamed"
                    );
                }
                Case::Success(_) => {
                    pool.report(&proxy, false).unwrap();
                    assert!(
                        pool.pick().unwrap().is_some(),
                        "readable API body earned no credit"
                    );
                    pool.report(&proxy, false).unwrap();
                    assert!(
                        pool.pick().unwrap().is_none(),
                        "API body earned more than one credit"
                    );
                }
            }
        }
        assert_eq!(api.sequence, 1);
    };
    let ((), calls) = if through_proxy {
        test_peer::with_raw_connect_peer(reply, run)
    } else {
        test_peer::with_raw_peer(reply, run)
    };
    assert_eq!(calls.len(), 1, "API rejection was replayed");
}

#[test]
fn fork_preserves_timeout_and_sid_but_isolates_sequence_session_and_live_connections() {
    let (closed, closure) = mpsc::sync_channel(4);
    let ((), calls) = test_peer::with_raw_peer(
        |request, stream| {
            assert_eq!(request.method, "POST");
            assert_eq!(
                serde_json::from_slice::<Value>(&request.body).unwrap(),
                json!([{"a":"ug"}])
            );
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 10\r\nConnection: keep-alive\r\n\r\n[{\"ok\":1}]").unwrap();
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
                other => panic!("fork retained a live request connection: {other:?}"),
            }
            closed.try_send(()).unwrap();
        },
        |address| {
            let mut base = Api::test_peer(address).unwrap();
            base.transport.timeout = Duration::from_secs(42);
            base.set_session("synthetic-original-sid");
            assert_eq!(
                base.request(json!({"a":"ug"}), &[]).unwrap(),
                json!({"ok":1})
            );
            closure.recv_timeout(Duration::from_secs(2)).unwrap();
            let mut fork = base.fork().unwrap();
            assert_eq!(fork.transport.timeout, Duration::from_secs(42));
            assert_eq!(fork.transport.user_agent, base.transport.user_agent);
            assert_eq!(fork.base, base.base);
            assert_eq!(fork.sequence, 0);
            assert_eq!(fork.sid.as_deref(), base.sid.as_deref());
            assert_eq!(
                fork.request(json!({"a":"ug"}), &[]).unwrap(),
                json!({"ok":1})
            );
            closure.recv_timeout(Duration::from_secs(2)).unwrap();
            assert_eq!(base.sequence, 1);
            fork.set_session("synthetic-fork-sid");
            assert_eq!(
                fork.request(json!({"a":"ug"}), &[]).unwrap(),
                json!({"ok":1})
            );
            closure.recv_timeout(Duration::from_secs(2)).unwrap();
            fork.clear_session();
            assert!(fork.sid.is_none());
            assert_eq!((base.sequence, fork.sequence), (1, 2));
            drop(fork);
            assert_eq!(
                base.request(json!({"a":"ug"}), &[]).unwrap(),
                json!({"ok":1})
            );
            closure.recv_timeout(Duration::from_secs(2)).unwrap();
            assert_eq!(base.sequence, 2);
        },
    );
    let queries: Vec<_> = calls
        .iter()
        .map(|request| {
            Url::parse(&format!("https://testserver.com{}", request.path))
                .unwrap()
                .query_pairs()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect::<std::collections::BTreeMap<_, _>>()
        })
        .collect();
    assert_eq!(queries.len(), 4);
    for (query, id, sid) in [
        (&queries[0], "1", "synthetic-original-sid"),
        (&queries[1], "1", "synthetic-original-sid"),
        (&queries[2], "2", "synthetic-fork-sid"),
        (&queries[3], "2", "synthetic-original-sid"),
    ] {
        assert_eq!(query["id"], id);
        assert_eq!(query["sid"], sid);
        assert_eq!(query["ak"], "BdARkQSQ");
        assert_eq!(query.len(), 3);
    }
}

#[test]
fn api_closes_error_status_and_unusable_bodies_without_replay_or_success_credit() {
    for through_proxy in [false, true] {
        for case in [
            Case::Status(500),
            Case::Status(503),
            Case::Status(429),
            Case::Status(404),
            Case::Status(407),
            Case::ContentType,
            Case::UntrustedContentType,
            Case::HtmlWithJson,
            Case::DeclaredOversize,
            Case::InvalidJson,
            Case::TopLevelObject,
        ] {
            scenario(case, through_proxy);
        }
    }
}

#[test]
fn api_closes_a_successful_response_before_returning_its_exact_result_and_one_credit() {
    for through_proxy in [false, true] {
        for boolean in [false, true] {
            scenario(Case::Success(boolean), through_proxy);
        }
    }
}

#[test]
fn actual_transport_failures_exhaust_the_selected_pool_without_credit_or_direct_fallback() {
    let ((), calls) = test_peer::with_raw_connect_peer(
        |request, _stream| {
            assert_eq!(request.method, "POST");
            assert!(request.connect_target.is_some());
            assert_eq!(
                serde_json::from_slice::<Value>(&request.body).unwrap(),
                json!([{"a":"ug"}])
            );
            // Returning drops this real connection before any HTTP response headers arrive.
        },
        |address| {
            let mut api = Api::test_peer(address).unwrap();
            let proxy = format!("http://127.0.0.1:{}", address.port());
            let pool = Pool::new(vec![proxy.clone()], vec![], None).unwrap();
            api.transport.routing = Routing {
                explicit: None,
                pool: Some(pool.clone()),
                force: true,
            };
            let transport = api.transport.clone();
            let mut waits = Vec::new();
            let error = api
                .request_with(
                    json!({"a":"ug"}),
                    &[],
                    move |url, headers, body, payload| {
                        let reply = transport.send_api(url, headers, body)?;
                        read_reply(reply, payload, MAX_RESPONSE_BYTES)
                            .map_err(AttemptFailure::after)
                    },
                    |duration| {
                        waits.push(duration.as_secs());
                        Ok(())
                    },
                )
                .unwrap_err();
            assert!(
                matches!(error, Error::Protocol(message) if message == "Force-proxy mode has no usable proxy; direct connection was refused")
            );
            assert_eq!(waits, [2, 4, 8]);
            assert_eq!(api.sequence, 4);
            assert_eq!(pool.test_health_counts(&proxy).unwrap(), Some((0, 3)));
            assert!(pool.pick().unwrap().is_none());
        },
    );
    assert_eq!(
        calls.len(),
        3,
        "failed proxy was credited or direct fallback was attempted"
    );
}
