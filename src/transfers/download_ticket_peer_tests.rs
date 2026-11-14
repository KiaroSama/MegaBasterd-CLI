//! Expired CDN tickets are refreshed before retrying content, without blaming their proxy.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::storage::proxies::{Pool, Routing};
use serde_json::json;
use url::Url;

fn closed(stream: &mut impl Read) {
    match stream.read(&mut [0]) {
        Ok(0) => (),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
            ) => {}
        other => panic!("expired-ticket response remained open: {other:?}"),
    }
}

fn reply(stream: &mut impl Write, status: u16, headers: &[(&str, String)], body: &[u8]) {
    write!(
        stream,
        "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    )
    .unwrap();
    for (name, value) in headers {
        write!(stream, "{name}: {value}\r\n").unwrap();
    }
    stream.write_all(b"\r\n").unwrap();
    stream.write_all(body).unwrap();
    stream.flush().unwrap();
}

#[test]
fn expired_cdn_statuses_refresh_once_through_the_same_route_and_close_the_old_response() {
    for status in [403, 410, 509] {
        for verify in [false, true] {
            let fixture = Fixture::new(17);
            let scratch = scratch();
            let destination = scratch.path().join("refreshed.bin");
            let states = scratch.path().join("private state");
            let mut step = 0;
            let ((), calls) = test_peer::with_raw_connect_peer(
                |request, stream| {
                    assert!(request.connect_target.is_some());
                    assert!(!request.headers.contains_key("proxy-authorization"));
                    match step {
                        0 => {
                            assert_eq!(request.method, "GET");
                            assert_eq!(request.path, "/cdn");
                            assert_eq!(request.headers["range"], "bytes=0-16");
                            write!(stream, "HTTP/1.1 {status} Expired\r\nContent-Length: 4096\r\nConnection: keep-alive\r\n\r\n").unwrap();
                            stream.flush().unwrap();
                            closed(stream);
                        }
                        1 => {
                            assert_eq!(request.method, "POST");
                            let url =
                                Url::parse(&format!("https://testserver.com{}", request.path))
                                    .unwrap();
                            assert_eq!(url.path(), "/cs");
                            assert!(!url.query_pairs().any(|(key, _)| key == "sid" || key == "n"));
                            assert_eq!(
                                serde_json::from_slice::<Value>(&request.body).unwrap(),
                                json!([{"a":"g","g":1,"ssl":2,"p":"fixture"}])
                            );
                            reply(stream, 200, &[("Content-Type", "application/json".into())],
                                &serde_json::to_vec(&json!([{"s":17,"g":format!("https://{}/fresh",request.headers["host"])}])).unwrap());
                        }
                        2 => {
                            assert_eq!(request.method, "GET");
                            assert_eq!(request.path, "/fresh");
                            assert_eq!(request.headers["range"], "bytes=0-16");
                            reply(
                                stream,
                                206,
                                &[("Content-Range", "bytes 0-16/17".into())],
                                fixture.ciphertext,
                            );
                        }
                        _ => panic!("expired ticket was replayed or refreshed more than once"),
                    }
                    step += 1;
                },
                |address| {
                    let mut api = Api::test_peer(address).unwrap();
                    let proxy = format!("http://127.0.0.1:{}", address.port());
                    let pool = Pool::new(vec![proxy.clone()], vec![], None).unwrap();
                    pool.report(&proxy, false).unwrap();
                    pool.report(&proxy, false).unwrap();
                    api.transport.routing = Routing {
                        explicit: None,
                        pool: Some(pool.clone()),
                        force: true,
                    };
                    let control = api.control.clone();
                    let progress = Progress::new(false);
                    let item = progress.add("fixture", fixture.size).unwrap();
                    download(
                        api,
                        fixture.info(address),
                        &destination,
                        &states,
                        &options(verify),
                        &RateLimiter::new(0.0).unwrap(),
                        &progress,
                        item,
                        &control,
                    )
                    .unwrap();
                    fixture.assert_output(&destination);
                    assert!(
                        pool.pick().unwrap().is_some(),
                        "ticket expiry incorrectly cooled the route"
                    );
                    assert!(
                        States::new(state_path(&states, &destination))
                            .load()
                            .unwrap()
                            .is_none()
                    );
                },
            );
            assert_eq!(step, 3);
            assert_eq!(calls.len(), 3);
        }
    }
}

#[test]
fn transient_server_503_retries_the_same_download_window_and_then_publishes_verified_bytes() {
    let fixture = Fixture::new(17);
    let scratch = scratch();
    let destination = scratch.path().join("server-retried.bin");
    let states = scratch.path().join("private state");
    let mut step = 0;
    let ((), calls) = test_peer::with_raw_peer(
        |request, stream| {
            assert_eq!(request.method, "GET");
            assert_eq!(request.path, "/cdn");
            assert_eq!(request.headers["range"], "bytes=0-16");
            assert!(request.body.is_empty());
            match step {
                0 => {
                    reply(stream, 503, &[], b"");
                    closed(stream);
                }
                1 => reply(
                    stream,
                    206,
                    &[("Content-Range", "bytes 0-16/17".into())],
                    fixture.ciphertext,
                ),
                _ => panic!("successful transient retry attempted another request"),
            }
            step += 1;
        },
        |address| {
            let control = Control::new();
            run(&fixture, address, &destination, &states, &control, true).unwrap();
            fixture.assert_output(&destination);
            assert!(
                States::new(state_path(&states, &destination))
                    .load()
                    .unwrap()
                    .is_none()
            );
        },
    );
    assert_eq!(step, 2);
    assert_eq!(
        calls.len(),
        2,
        "503 must retry content, not refresh its valid ticket"
    );
}

#[test]
fn exhausted_ticket_expiry_closes_without_blame_or_an_extra_refresh() {
    for status in [403, 410, 509] {
        let fixture = Fixture::new(17);
        let scratch = scratch();
        let destination = scratch.path().join("expired.bin");
        let states = scratch.path().join("private state");
        let mut content_requests = 0;
        let mut refreshes = 0;
        let ((), calls) = test_peer::with_raw_connect_peer(
            |request, stream| {
                assert!(request.connect_target.is_some());
                if request.method == "GET" {
                    content_requests += 1;
                    assert_eq!(request.path, "/cdn");
                    assert_eq!(request.headers["range"], "bytes=0-16");
                    write!(stream, "HTTP/1.1 {status} Expired\r\nContent-Length: 4096\r\nConnection: keep-alive\r\n\r\n").unwrap();
                    stream.flush().unwrap();
                    closed(stream);
                } else {
                    refreshes += 1;
                    assert_eq!(request.method, "POST");
                    assert_eq!(content_requests, refreshes);
                    assert_eq!(
                        serde_json::from_slice::<Value>(&request.body).unwrap(),
                        json!([{"a":"g","g":1,"ssl":2,"p":"fixture"}])
                    );
                    reply(stream, 200, &[("Content-Type", "application/json".into())],
                        &serde_json::to_vec(&json!([{"s":17,"g":format!("https://{}/cdn",request.headers["host"])}])).unwrap());
                }
                assert!(content_requests <= 5 && refreshes <= 4);
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
                let control = api.control.clone();
                let progress = Progress::new(false);
                let item = progress.add("fixture", fixture.size).unwrap();
                assert!(matches!(
                    download(
                        api,
                        fixture.info(address),
                        &destination,
                        &states,
                        &options(false),
                        &RateLimiter::new(0.0).unwrap(),
                        &progress,
                        item,
                        &control
                    ),
                    Err(Error::Timeout)
                ));
                // Four successful metadata reads bring failures to zero; expiry must not add one.
                pool.report(&proxy, false).unwrap();
                pool.report(&proxy, false).unwrap();
                assert!(
                    pool.pick().unwrap().is_some(),
                    "terminal expiry blamed the proxy"
                );
                pool.report(&proxy, false).unwrap();
                assert!(pool.pick().unwrap().is_none());
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
        assert_eq!(content_requests, 5);
        assert_eq!(refreshes, 4);
        assert_eq!(calls.len(), 9);
    }
}

#[test]
fn ordinary_cdn_not_found_is_not_ticket_expiry_or_permission_to_refresh() {
    let fixture = Fixture::new(17);
    let scratch = scratch();
    let destination = scratch.path().join("missing.bin");
    let states = scratch.path().join("private state");
    let ((), calls) = test_peer::with_peer(
        |request| {
            assert_eq!(request.method, "GET");
            assert_eq!(request.path, "/cdn");
            Some(Response {
                status: 404,
                headers: vec![],
                body: vec![],
            })
        },
        |address| {
            assert!(matches!(
                run(
                    &fixture,
                    address,
                    &destination,
                    &states,
                    &Control::new(),
                    false
                ),
                Err(Error::Protocol(_))
            ));
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
