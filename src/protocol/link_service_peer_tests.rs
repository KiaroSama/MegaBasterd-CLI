//! Link-service credit follows readable responses, not merely successful headers.
#![allow(clippy::unwrap_used)]

use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::SocketAddr,
    sync::mpsc,
    time::Duration,
};

use super::*;

#[path = "link_service_dlc_peer_tests.rs"]
mod dlc_tests;
#[path = "link_service_redirect_peer_tests.rs"]
mod redirect_tests;
#[path = "megacrypter_resolution_peer_tests.rs"]
mod resolution_tests;
#[path = "link_service_resource_peer_tests.rs"]
mod resource_tests;
#[path = "link_service_vector_peer_tests.rs"]
mod vector_tests;

use crate::{
    crypto::wire,
    protocol::{
        api::Api,
        test_peer::{self, Response},
    },
    storage::proxies::{Pool, Routing},
};

fn elc(address: SocketAddr) -> ParsedLink {
    let vectors: Value =
        serde_json::from_str(include_str!("../../tests/fixtures/link-vectors.json")).unwrap();
    let encrypted = hex::decode(vectors["elc"][0]["encrypted_links"].as_str().unwrap()).unwrap();
    let service = format!("https://testserver.com:{}/api", address.port());
    let token = b"synthetic-token";
    let mut payload = vec![0xb9];
    payload.extend((encrypted.len() as u32).to_le_bytes());
    payload.extend(encrypted);
    payload.extend((service.len() as u16).to_le_bytes());
    payload.extend(service.as_bytes());
    payload.extend((token.len() as u16).to_le_bytes());
    payload.extend(token);
    links::parse_link(&format!("mega://elc?{}", wire::b64_url_encode(&payload))).unwrap()
}

fn call(resolver: &Resolver<'_>, address: SocketAddr, kind: usize) -> Result<()> {
    match kind {
        0 => resolver.elc(&elc(address)).map(drop),
        1 => resolver
            .megacrypter_info(
                &links::parse_link(&format!("mc://testserver.com:{}/token", address.port()))
                    .unwrap(),
            )
            .map(drop),
        2 => resolver
            .dlc_request(
                &"B".repeat(100),
                Url::parse(&format!(
                    "https://testserver.com:{}/dlcrypt/service.php",
                    address.port()
                ))
                .unwrap(),
            )
            .map(drop),
        3 => resolver
            .megacrypter_download(
                &links::parse_link(&format!("mc://testserver.com:{}/token", address.port()))
                    .unwrap(),
                &containers::decrypt_megacrypter_info(&json!({}), None).unwrap(),
                None,
            )
            .map(drop),
        4 => resolver
            .resolve(&format!("mc://testserver.com:{}/token", address.port()))
            .map(drop),
        _ => panic!("unknown link service"),
    }
}

fn route(api: &mut Api, address: SocketAddr, failures: usize) -> (std::sync::Arc<Pool>, String) {
    let proxy = format!("http://127.0.0.1:{}", address.port());
    let pool = Pool::new(vec![proxy.clone()], vec![], None).unwrap();
    // Seeded failures make exact credit/blame observable through the public cooldown policy.
    for _ in 0..failures {
        pool.report(&proxy, false).unwrap();
    }
    api.transport.routing = Routing {
        explicit: None,
        pool: Some(pool.clone()),
        force: true,
    };
    (pool, proxy)
}

fn assert_request(request: &test_peer::Request, kind: usize) {
    assert_eq!(request.method, "POST");
    assert!(!request.headers.contains_key("proxy-authorization"));
    match kind {
        0 => {
            assert_eq!(request.path, "/api");
            let fields: BTreeMap<_, _> = url::form_urlencoded::parse(&request.body)
                .into_owned()
                .collect();
            assert_eq!(
                fields,
                BTreeMap::from([
                    ("OPERATION_TYPE".into(), "D".into()),
                    ("DATA".into(), "synthetic-token".into()),
                    ("USER".into(), "synthetic-user".into()),
                    ("APIKEY".into(), "synthetic-key".into()),
                ])
            );
        }
        1 => {
            assert_eq!(request.path, "/api");
            assert_eq!(
                serde_json::from_slice::<Value>(&request.body).unwrap(),
                json!({
                    "m":"info", "link":format!("mc://{}/token", request.headers["host"])
                })
            );
        }
        2 => {
            assert_eq!(request.path, "/dlcrypt/service.php");
            let fields: BTreeMap<_, _> = url::form_urlencoded::parse(&request.body)
                .into_owned()
                .collect();
            assert_eq!(
                fields,
                BTreeMap::from([
                    ("destType".into(), "jdtc6".into()),
                    ("b".into(), "JD".into()),
                    ("srcType".into(), "dlc".into()),
                    ("data".into(), "B".repeat(88)),
                    ("v".into(), "34065".into()),
                ])
            );
            assert_eq!(request.headers["rev"], "34065");
        }
        _ => panic!("unknown link service"),
    }
}

#[test]
fn each_link_service_refuses_error_status_without_credit_and_closes_the_unread_response() {
    for kind in 0..3 {
        let ((), calls) = test_peer::with_raw_connect_peer(
            |request, stream| {
                assert_request(request, kind);
                stream.write_all(b"HTTP/1.1 503 Unavailable\r\nContent-Length: 4096\r\nConnection: close\r\n\r\n").unwrap();
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
                    other => panic!("failed service response was not closed: {other:?}"),
                }
            },
            |address| {
                let mut api = Api::test_peer(address).unwrap();
                let (pool, proxy) = route(&mut api, address, 2);
                let accounts = BTreeMap::new();
                let resolver = Resolver {
                    transport: &api.transport,
                    password: None,
                    elc_user: Some("synthetic-user"),
                    elc_api_key: Some("synthetic-key"),
                    elc_accounts: &accounts,
                };
                assert!(
                    matches!(call(&resolver, address, kind), Err(Error::Protocol(message)) if message.contains("unsuccessful HTTP status"))
                );
                pool.report(&proxy, false).unwrap();
                assert!(
                    pool.pick().unwrap().is_none(),
                    "an error status credited the proxy"
                );
            },
        );
        assert_eq!(calls.len(), 1);
        assert!(calls[0].connect_target.is_some());
    }
}

#[test]
fn failed_service_send_blames_the_selected_proxy_without_direct_fallback_or_credit() {
    for kind in 0..3 {
        for stalled in [false, true] {
            let (closed, closure) = mpsc::sync_channel(1);
            let ((), calls) = test_peer::with_raw_connect_peer(
                |request, stream| {
                    assert_request(request, kind);
                    if stalled {
                        // Withhold headers until the actual request deadline closes the socket.
                        match stream.read(&mut [0]) {
                            Ok(0) => (),
                            Err(error)
                                if matches!(
                                    error.kind(),
                                    std::io::ErrorKind::UnexpectedEof
                                        | std::io::ErrorKind::ConnectionReset
                                        | std::io::ErrorKind::ConnectionAborted
                                ) => {}
                            other => panic!("timed-out service socket remained open: {other:?}"),
                        }
                        closed.send(()).unwrap();
                    }
                    // Otherwise returning drops the real TLS connection before any response.
                },
                |address| {
                    let mut api = Api::test_peer(address).unwrap();
                    api.transport.timeout = Duration::from_secs(2);
                    let (pool, proxy) = route(&mut api, address, 1);
                    let accounts = BTreeMap::new();
                    let resolver = Resolver {
                        transport: &api.transport,
                        password: None,
                        elc_user: Some("synthetic-user"),
                        elc_api_key: Some("synthetic-key"),
                        elc_accounts: &accounts,
                    };
                    let error = call(&resolver, address, kind).unwrap_err();
                    if stalled {
                        assert!(matches!(error, Error::Timeout));
                        closure.recv_timeout(Duration::from_secs(2)).unwrap();
                    } else {
                        assert!(!matches!(error, Error::Canceled | Error::Timeout));
                    }
                    assert!(
                        pool.pick().unwrap().is_some(),
                        "one failed send blamed its selected proxy more than once"
                    );
                    pool.report(&proxy, false).unwrap();
                    assert!(
                        pool.pick().unwrap().is_none(),
                        "failed send did not blame its proxy or earned success credit"
                    );
                    pool.report(&proxy, true).unwrap();
                    assert!(
                        pool.pick().unwrap().is_none(),
                        "cooldown was reset by an unrelated success"
                    );
                },
            );
            assert_eq!(
                calls.len(),
                1,
                "service retried or bypassed its selected route"
            );
        }
    }
}

#[test]
fn service_redirects_reselect_a_forced_proxy_and_close_each_hop_before_local_decryption() {
    let mut hop = 0;
    let ((), calls) = test_peer::with_raw_connect_peer(
        |request, stream| {
            assert_eq!(request.method, "POST");
            assert!(!request.headers.contains_key("proxy-authorization"));
            let fields: BTreeMap<_, _> = url::form_urlencoded::parse(&request.body)
                .into_owned()
                .collect();
            assert_eq!(
                fields.get("APIKEY").map(String::as_str),
                Some("synthetic-key")
            );
            if hop == 0 {
                assert_eq!(request.path, "/api");
                stream.write_all(b"HTTP/1.1 307 Temporary Redirect\r\nLocation: /mirror\r\nContent-Length: 4096\r\nConnection: close\r\n\r\n").unwrap();
            } else {
                assert_eq!(hop, 1);
                assert_eq!(request.path, "/mirror");
                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\n{\"d\":\"\"}").unwrap();
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
                other => panic!("service hop response was not closed: {other:?}"),
            }
            hop += 1;
        },
        |address| {
            let mut api = Api::test_peer(address).unwrap();
            let (pool, proxy) = route(&mut api, address, 2);
            let accounts = BTreeMap::new();
            let resolver = Resolver {
                transport: &api.transport,
                password: None,
                elc_user: Some("synthetic-user"),
                elc_api_key: Some("synthetic-key"),
                elc_accounts: &accounts,
            };
            assert!(resolver.elc(&elc(address)).is_err());
            pool.report(&proxy, false).unwrap();
            assert!(pool.pick().unwrap().is_some());
            pool.report(&proxy, false).unwrap();
            assert!(pool.pick().unwrap().is_none());
        },
    );
    assert_eq!(hop, 2);
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].body, calls[1].body);
    assert_eq!(calls[0].connect_target, calls[1].connect_target);
    assert!(calls.iter().all(|request| request.connect_target.is_some()));
}

#[test]
fn redirect_rechecks_force_policy_after_the_only_proxy_enters_cooldown() {
    let (selected, selection) = mpsc::sync_channel::<std::sync::Arc<Pool>>(1);
    let ((), calls) = test_peer::with_raw_connect_peer(
        move |request, stream| {
            assert_request(request, 0);
            let pool = selection.recv_timeout(Duration::from_secs(2)).unwrap();
            let proxy = pool.pick().unwrap().unwrap();
            for _ in 0..3 {
                pool.report(&proxy, false).unwrap();
            }
            stream.write_all(b"HTTP/1.1 307 Temporary Redirect\r\nLocation: /mirror\r\nContent-Length: 4096\r\nConnection: keep-alive\r\n\r\n").unwrap();
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
                other => panic!("redirect refusal left its first response open: {other:?}"),
            }
        },
        |address| {
            let mut api = Api::test_peer(address).unwrap();
            let (pool, _) = route(&mut api, address, 0);
            selected.send(pool).unwrap();
            let accounts = BTreeMap::new();
            let resolver = Resolver {
                transport: &api.transport,
                password: None,
                elc_user: Some("synthetic-user"),
                elc_api_key: Some("synthetic-key"),
                elc_accounts: &accounts,
            };
            assert!(
                matches!(resolver.elc(&elc(address)), Err(Error::Protocol(message)) if message.contains("direct connection was refused"))
            );
        },
    );
    assert_eq!(
        calls.len(),
        1,
        "redirect reused a cooled proxy or fell back direct"
    );
}

#[test]
fn every_link_service_refuses_an_empty_forced_pool_before_any_request() {
    let ((), calls) = test_peer::with_peer(
        |request| {
            panic!(
                "forced link service opened a direct request: {}",
                request.path
            )
        },
        |address| {
            let mut api = Api::test_peer(address).unwrap();
            api.transport.routing = Routing {
                explicit: None,
                pool: Some(Pool::new(vec![], vec![], None).unwrap()),
                force: true,
            };
            let accounts = BTreeMap::new();
            let resolver = Resolver {
                transport: &api.transport,
                password: None,
                elc_user: Some("synthetic-user"),
                elc_api_key: Some("synthetic-key"),
                elc_accounts: &accounts,
            };
            for kind in 0..5 {
                assert!(
                    matches!(call(&resolver, address, kind), Err(Error::Protocol(message)) if message.contains("direct connection was refused"))
                );
            }
        },
    );
    assert!(calls.is_empty());
}

#[test]
fn explicit_direct_policy_reaches_the_service_without_a_proxy() {
    let ((), calls) = test_peer::with_peer(
        |request| {
            assert_request(request, 0);
            assert!(request.connect_target.is_none());
            Some(Response {
                status: 200,
                headers: vec![],
                body: b"{\"d\":\"\"}".to_vec(),
            })
        },
        |address| {
            let api = Api::test_peer(address).unwrap();
            assert!(!api.transport.routing.force);
            assert!(api.transport.routing.explicit.is_none());
            assert!(api.transport.routing.pool.is_none());
            let accounts = BTreeMap::new();
            let resolver = Resolver {
                transport: &api.transport,
                password: None,
                elc_user: Some("synthetic-user"),
                elc_api_key: Some("synthetic-key"),
                elc_accounts: &accounts,
            };
            assert!(resolver.elc(&elc(address)).is_err());
        },
    );
    assert_eq!(calls.len(), 1);
    assert!(calls[0].connect_target.is_none());
}

#[test]
fn recursive_megacrypter_resolution_uses_the_selected_proxy_for_its_info_request() {
    let public = "https://mega.nz/file/ABCDEFGH#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let ((), calls) = test_peer::with_connect_peer(
        |request| {
            assert_request(request, 1);
            Some(Response {
                status: 200,
                headers: vec![],
                body: serde_json::to_vec(&json!({"link":public})).unwrap(),
            })
        },
        |address| {
            let mut api = Api::test_peer(address).unwrap();
            let _route = route(&mut api, address, 0);
            let accounts = BTreeMap::new();
            let resolver = Resolver {
                transport: &api.transport,
                password: None,
                elc_user: None,
                elc_api_key: None,
                elc_accounts: &accounts,
            };
            let links = resolver
                .resolve(&format!("mc://testserver.com:{}/token", address.port()))
                .unwrap();
            assert_eq!(links.len(), 1);
            assert_eq!(links[0].public_id, "ABCDEFGH");
            assert_eq!(links[0].kind, LinkType::File);
        },
    );
    assert_eq!(calls.len(), 1);
    assert!(calls[0].connect_target.is_some());
}

#[test]
fn explicit_proxy_routes_a_link_service_without_a_pool_even_in_force_mode() {
    let ((), calls) = test_peer::with_connect_peer(
        |request| {
            assert_request(request, 0);
            Some(Response {
                status: 200,
                headers: vec![],
                body: b"{\"d\":\"\"}".to_vec(),
            })
        },
        |address| {
            let mut api = Api::test_peer(address).unwrap();
            api.transport.routing = Routing {
                explicit: Some(format!("http://127.0.0.1:{}", address.port())),
                pool: None,
                force: true,
            };
            let accounts = BTreeMap::new();
            let resolver = Resolver {
                transport: &api.transport,
                password: None,
                elc_user: Some("synthetic-user"),
                elc_api_key: Some("synthetic-key"),
                elc_accounts: &accounts,
            };
            assert!(resolver.elc(&elc(address)).is_err());
        },
    );
    assert_eq!(calls.len(), 1);
    assert!(calls[0].connect_target.is_some());
}

#[test]
fn megacrypter_download_validates_each_returned_url_before_handing_it_to_a_fetcher() {
    for (answer, allowed) in [
        ("http://127.0.0.1:8931/x", false),
        ("https://127.0.0.1/x", false),
        ("https://169.254.169.254/latest/meta-data", false),
        ("https://192.168.1.5/x", false),
        ("http://cdn.example.com/x", false),
        ("https://gfs.example.com/dl/abc", true),
    ] {
        let mut methods = Vec::new();
        let ((), calls) = test_peer::with_connect_peer(
            |request| {
                assert_eq!(request.method, "POST");
                assert_eq!(request.path, "/api");
                let body: Value = serde_json::from_slice(&request.body).unwrap();
                let method = body["m"].as_str().unwrap();
                assert_eq!(method, if methods.is_empty() { "info" } else { "dl" });
                assert!(methods.len() < 2, "service contacted the returned URL");
                assert_eq!(
                    body,
                    json!({"m":method,"link":format!("mc://{}/token",request.headers["host"])})
                );
                methods.push(method.to_owned());
                Some(Response {
                    status: 200,
                    headers: vec![],
                    body: serde_json::to_vec(&if method == "info" {
                        json!({})
                    } else {
                        json!({"url":answer})
                    })
                    .unwrap(),
                })
            },
            |address| {
                let mut api = Api::test_peer(address).unwrap();
                let _route = route(&mut api, address, 0);
                let accounts = BTreeMap::new();
                let resolver = Resolver {
                    transport: &api.transport,
                    password: None,
                    elc_user: None,
                    elc_api_key: None,
                    elc_accounts: &accounts,
                };
                let link =
                    links::parse_link(&format!("mc://testserver.com:{}/token", address.port()))
                        .unwrap();
                let info = resolver.megacrypter_info(&link).unwrap();
                let result = resolver.megacrypter_download(&link, &info, None);
                if allowed {
                    assert_eq!(result.unwrap(), answer);
                } else {
                    assert!(matches!(result, Err(Error::Invalid(_))));
                }
            },
        );
        assert_eq!(methods, ["info", "dl"]);
        assert_eq!(calls.len(), 2);
        assert!(calls.iter().all(|request| request.connect_target.is_some()));
    }
}

#[test]
fn readable_service_bodies_credit_exactly_once_before_local_semantic_decryption_errors() {
    for kind in 0..3 {
        let ((), calls) = test_peer::with_connect_peer(
            |request| {
                assert_request(request, kind);
                Some(Response {
                    status: 200,
                    headers: vec![],
                    body: if kind == 2 {
                        b"<no-key/>".to_vec()
                    } else if kind == 1 {
                        b"{\"error\":-1}".to_vec()
                    } else {
                        b"{\"d\":\"\"}".to_vec()
                    },
                })
            },
            |address| {
                let mut api = Api::test_peer(address).unwrap();
                let (pool, proxy) = route(&mut api, address, 2);
                let accounts = BTreeMap::new();
                let resolver = Resolver {
                    transport: &api.transport,
                    password: None,
                    elc_user: Some("synthetic-user"),
                    elc_api_key: Some("synthetic-key"),
                    elc_accounts: &accounts,
                };
                assert!(call(&resolver, address, kind).is_err());
                pool.report(&proxy, false).unwrap();
                assert_eq!(
                    pool.pick().unwrap().as_deref(),
                    Some(proxy.as_str()),
                    "readable body did not earn one credit"
                );
                pool.report(&proxy, false).unwrap();
                assert!(
                    pool.pick().unwrap().is_none(),
                    "readable body earned more than one credit"
                );
            },
        );
        assert_eq!(calls.len(), 1);
    }
}
