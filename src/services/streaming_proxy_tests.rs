//! Streaming preserves actual selected proxy routing, including link-service refreshes.
#![allow(clippy::unwrap_used)]

use super::{info, local, local_outcome};
use crate::crypto::wire;
use crate::error::Error;
use crate::protocol::{
    api::Api,
    link_services::Resolver,
    links,
    metadata::{self, FileInfo},
    test_peer::{self, Response},
};
use crate::services::streaming::StreamServer;
use crate::storage::proxies::{Pool, Routing};
use crate::transfers::control::Control;
use serde_json::{Value, json};

fn force_route(api: &mut Api, address: std::net::SocketAddr, pooled: bool) {
    let proxy = format!("http://127.0.0.1:{}", address.port());
    api.transport.routing = Routing {
        explicit: (!pooled).then(|| proxy.clone()),
        pool: pooled.then(|| Pool::new(vec![proxy], vec![], None).unwrap()),
        force: true,
    };
}

#[test]
fn megacrypter_stream_keeps_force_proxy_for_info_download_and_expired_ticket_refresh() {
    let vectors: Value =
        serde_json::from_str(include_str!("../../tests/fixtures/transfers/vectors.json")).unwrap();
    let key = vectors["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vector| vector["size"] == 131089)
        .unwrap()["raw_key"]
        .as_str()
        .unwrap();
    let key = wire::b64_url_encode(&hex::decode(key).unwrap());
    for pooled in [false, true] {
        let mut stage = 0;
        let (_, calls) = test_peer::with_connect_peer(
            |request| {
                let host = &request.headers["host"];
                assert!(!request.headers.contains_key("proxy-authorization"));
                let response = match stage {
                    0 => {
                        assert_eq!(request.method, "POST");
                        assert_eq!(request.path, "/api");
                        assert_eq!(
                            serde_json::from_slice::<Value>(&request.body).unwrap(),
                            json!({"m":"info","link":format!("mc://{host}/token")})
                        );
                        json!({"name":"video.mkv","size":1,"key":key,"expire":"noexpire#fixture-expiry"})
                    }
                    1 | 3 => {
                        assert_eq!(request.method, "POST");
                        assert_eq!(request.path, "/api");
                        assert_eq!(
                            serde_json::from_slice::<Value>(&request.body).unwrap(),
                            json!({"m":"dl","link":format!("mc://{host}/token"),"noexpire":"fixture-expiry"})
                        );
                        json!({"url":format!("https://{host}/{}", if stage == 1 { "expired" } else { "fresh" })})
                    }
                    2 => {
                        assert_eq!(request.method, "GET");
                        assert_eq!(request.path, "/expired");
                        assert_eq!(request.headers["range"], "bytes=0-0");
                        stage += 1;
                        return Some(Response {
                            status: 403,
                            headers: vec![],
                            body: vec![],
                        });
                    }
                    4 => {
                        assert_eq!(request.method, "GET");
                        assert_eq!(request.path, "/fresh");
                        assert_eq!(request.headers["range"], "bytes=0-0");
                        stage += 1;
                        return Some(Response {
                            status: 206,
                            headers: vec![("Content-Range".into(), "bytes 0-0/1".into())],
                            body: include_bytes!(
                                "../../tests/fixtures/transfers/ciphertext-131089.bin"
                            )[..1]
                                .to_vec(),
                        });
                    }
                    _ => panic!("unexpected request or public API fallback"),
                };
                stage += 1;
                Some(Response {
                    status: 200,
                    headers: vec![("Content-Type".into(), "application/json".into())],
                    body: serde_json::to_vec(&response).unwrap(),
                })
            },
            |address| {
                let mut api = Api::test_peer(address).unwrap();
                api.set_session("account-session-must-not-leak");
                force_route(&mut api, address, pooled);
                let link =
                    links::parse_link(&format!("mc://testserver.com:{}/token", address.port()))
                        .unwrap();
                let source = {
                    let resolver = Resolver {
                        transport: &api.transport,
                        password: None,
                        elc_user: None,
                        elc_api_key: None,
                        elc_accounts: &Default::default(),
                    };
                    let metadata = resolver.megacrypter_info(&link).unwrap();
                    let url = resolver
                        .megacrypter_download(&link, &metadata, None)
                        .unwrap();
                    FileInfo::megacrypter(link, metadata, url).unwrap()
                };
                assert_eq!(source.name, "video.mkv");
                assert_eq!(source.size, 1);
                let server = StreamServer::bind("127.0.0.1", 0, api, source, None, false).unwrap();
                let response = local(
                    &server,
                    b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
                    &Control::new(),
                );
                assert_eq!(response.status, 200);
                assert_eq!(response.headers["content-length"], "1");
                assert_eq!(response.body, [7]);
            },
        );
        assert_eq!(stage, 5);
        assert_eq!(calls.len(), 5);
        for request in calls {
            let host = request.headers["host"]
                .strip_prefix("testserver.com:")
                .unwrap();
            assert_eq!(request.connect_target, Some(format!("1.1.1.1:{host}")));
            assert!(!request.path.contains("sid="));
        }
    }
}

#[test]
fn explicit_and_pooled_force_routes_stream_real_ciphertext_only_through_connect() {
    for pooled in [false, true] {
        let (_, calls) = test_peer::with_connect_peer(
            |request| {
                assert_eq!(request.method, "GET");
                assert_eq!(request.path, "/cdn");
                assert_eq!(request.headers["range"], "bytes=0-4095");
                Some(Response {
                    status: 206,
                    headers: vec![("Content-Range".into(), "bytes 0-4095/4096".into())],
                    body: include_bytes!("../../tests/fixtures/transfers/ciphertext-131089.bin")
                        [..4096]
                        .to_vec(),
                })
            },
            |address| {
                let mut api = Api::test_peer(address).unwrap();
                force_route(&mut api, address, pooled);
                let mut source = info(address);
                source.size = 4096;
                let server = StreamServer::bind("127.0.0.1", 0, api, source, None, false).unwrap();
                let response = local(
                    &server,
                    b"GET / HTTP/1.1\r\nHost: localhost\r\nRange: bytes=0-4095\r\n\r\n",
                    &Control::new(),
                );
                assert_eq!(response.status, 206);
                assert_eq!(
                    response.body,
                    (0..4096)
                        .map(|i| ((13 * i + 7) % 256) as u8)
                        .collect::<Vec<_>>()
                );
            },
        );
        assert_eq!(calls.len(), 1);
        assert!(calls[0].connect_target.is_some());
    }
}

#[test]
fn unforced_stream_without_a_proxy_keeps_its_direct_route() {
    let (_, calls) = test_peer::with_peer(
        |request| {
            assert_eq!(request.method, "GET");
            assert_eq!(request.path, "/cdn");
            assert_eq!(request.headers["range"], "bytes=0-4095");
            assert!(request.connect_target.is_none());
            Some(Response {
                status: 206,
                headers: vec![("Content-Range".into(), "bytes 0-4095/4096".into())],
                body: include_bytes!("../../tests/fixtures/transfers/ciphertext-131089.bin")
                    [..4096]
                    .to_vec(),
            })
        },
        |address| {
            let api = Api::test_peer(address).unwrap();
            assert!(!api.transport.routing.force);
            assert_eq!(api.transport.routing.select().unwrap(), (None, None));
            let mut source = info(address);
            source.size = 4096;
            let server = StreamServer::bind("127.0.0.1", 0, api, source, None, false).unwrap();
            let response = local(
                &server,
                b"GET / HTTP/1.1\r\nHost: localhost\r\nRange: bytes=0-4095\r\n\r\n",
                &Control::new(),
            );
            assert_eq!(response.status, 206);
            assert_eq!(
                response.body,
                (0..4096)
                    .map(|i| ((13 * i + 7) % 256) as u8)
                    .collect::<Vec<_>>()
            );
        },
    );
    assert_eq!(calls.len(), 1);
    assert!(calls[0].connect_target.is_none());
}

#[test]
fn failed_force_proxy_never_falls_back_to_direct_or_retries_after_pool_cooldown() {
    for pooled in [false, true] {
        let (_, calls) = test_peer::with_refusing_connect_peer(|address| {
            let mut api = Api::test_peer(address).unwrap();
            force_route(&mut api, address, pooled);
            let server =
                StreamServer::bind("127.0.0.1", 0, api, info(address), None, false).unwrap();
            for _ in 0..4 {
                let (response, handled) = local_outcome(
                    &server,
                    b"GET / HTTP/1.1\r\nHost: localhost\r\nRange: bytes=0-4095\r\n\r\n",
                    &Control::new(),
                );
                assert_eq!(response.status, 502);
                assert_eq!(response.body, b"Upstream stream unavailable");
                assert!(matches!(handled, Err(Error::Protocol(_))));
            }
        });
        // Three pooled failures enter cooldown; an explicit route remains selected.
        assert_eq!(calls.len(), if pooled { 3 } else { 4 });
        assert!(calls.iter().all(|request| request.method == "CONNECT"));
    }
}

#[test]
fn empty_force_pool_refuses_stream_and_metadata_refresh_before_any_socket() {
    let (_, calls) = test_peer::with_peer(
        |_| panic!("force mode contacted direct peer without a proxy"),
        |address| {
            let mut api = Api::test_peer(address).unwrap();
            api.transport.routing = Routing {
                explicit: None,
                pool: Some(Pool::new(vec![], vec![], None).unwrap()),
                force: true,
            };
            assert!(matches!(
                api.transport.routing.select(),
                Err(Error::Protocol(_))
            ));
            let source = info(address);
            assert!(matches!(
                metadata::refresh(&mut api, &source),
                Err(Error::Protocol(_))
            ));
            let server = StreamServer::bind("127.0.0.1", 0, api, source, None, false).unwrap();
            let (response, handled) = local_outcome(
                &server,
                b"GET / HTTP/1.1\r\nHost: localhost\r\nRange: bytes=0-4095\r\n\r\n",
                &Control::new(),
            );
            assert_eq!(response.status, 502);
            assert_eq!(response.body, b"Upstream stream unavailable");
            assert!(matches!(handled, Err(Error::Protocol(_))));
        },
    );
    assert!(calls.is_empty());
}
