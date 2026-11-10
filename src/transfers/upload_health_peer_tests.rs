//! Actual CONNECT/TLS upload responses earn exactly one health outcome at their response phase.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::storage::proxies::{Pool, Routing};
use std::sync::{Arc, OnceLock};

fn routed(cloud: &mut Cloud, address: std::net::SocketAddr) -> (Arc<Pool>, String) {
    let proxy = format!("http://127.0.0.1:{}", address.port());
    let pool = Pool::new(vec![proxy.clone()], vec![], None).unwrap();
    cloud.api.transport.routing = Routing {
        explicit: None,
        pool: Some(pool.clone()),
        force: true,
    };
    (pool, proxy)
}

fn seed(pool: &Pool, proxy: &str, failures: usize) {
    for _ in 0..failures {
        pool.report(proxy, false).unwrap();
    }
    assert_eq!(pool.pick().unwrap().as_deref(), Some(proxy));
}

fn require_one_debit_from_one(pool: &Pool, proxy: &str) {
    assert!(
        pool.pick().unwrap().is_some(),
        "response was blamed more than once"
    );
    pool.report(proxy, false).unwrap();
    assert!(
        pool.pick().unwrap().is_none(),
        "response earned credit or no failure debit"
    );
}

fn require_one_credit_from_two(pool: &Pool, proxy: &str) {
    pool.report(proxy, false).unwrap();
    assert!(
        pool.pick().unwrap().is_some(),
        "valid response earned no success credit"
    );
    pool.report(proxy, false).unwrap();
    assert!(
        pool.pick().unwrap().is_none(),
        "valid response earned more than one success credit"
    );
}

#[test]
fn malformed_upload_bodies_and_fixed_400_debit_the_actual_proxy_exactly_once_without_retry() {
    for (size, status, body) in [
        (17, 200, vec![b'A'; 4097]),
        (131089, 200, TOKEN.as_bytes().to_vec()),
        (17, 200, vec![]),
        (131089, 200, b"\0\xff\xfe garbage-token \x01".to_vec()),
        (17, 200, vec![0xff]),
        (17, 400, vec![]),
    ] {
        let scratch = scratch();
        let source = source(scratch.path(), size);
        let states = scratch.path().join("private state");
        let vault = Vault::new("synthetic upload passphrase");
        let route = OnceLock::new();
        let ((), calls) = test_peer::with_connect_peer(
            |request| {
                if request.path.starts_with("/native-peer-upload/") {
                    assert_eq!(request.path, "/native-peer-upload/slot/0");
                    let (pool, proxy): &(Arc<Pool>, String) = route.get().unwrap();
                    seed(pool, proxy, 1);
                    return Some(Response {
                        status,
                        headers: vec![],
                        body: body.clone(),
                    });
                }
                assert_eq!(command(request), json!({"a":"u","s":size}));
                Some(api(json!({"p":SLOT})))
            },
            |address| {
                let mut cloud = cloud(address);
                route.set(routed(&mut cloud, address)).ok().unwrap();
                assert!(matches!(
                    transfer(&mut cloud, &source, &states, &vault),
                    Err(Error::Protocol(_))
                ));
                let (pool, proxy) = route.get().unwrap();
                require_one_debit_from_one(pool, proxy);
                let paths: Vec<_> = std::fs::read_dir(&states)
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
                    .collect();
                assert_eq!(paths.len(), 1);
                let saved = States::new(&paths[0]).load().unwrap().unwrap();
                assert!(saved.completed.is_empty());
                assert!(saved.completion_token.is_none() && !saved.registration_started);
            },
        );
        assert_eq!(
            calls.len(),
            2,
            "deterministic response was retried or registered"
        );
    }
}

#[test]
fn valid_final_and_nonfinal_upload_bodies_credit_the_proxy_once_before_following_api_work() {
    for final_chunk in [false, true] {
        let scratch = scratch();
        let size = if final_chunk { 17 } else { 131089 };
        let source = source(scratch.path(), size);
        let states = scratch.path().join("private state");
        let vault = Vault::new("synthetic upload passphrase");
        let route = OnceLock::new();
        let checked = std::sync::atomic::AtomicBool::new(false);
        let ((), calls) = test_peer::with_connect_peer(
            |request| {
                let (pool, proxy): &(Arc<Pool>, String) = route.get().unwrap();
                if request.path == "/native-peer-upload/slot/0" {
                    seed(pool, proxy, 2);
                    return Some(Response {
                        status: 200,
                        headers: vec![],
                        body: if final_chunk {
                            TOKEN.as_bytes().to_vec()
                        } else {
                            vec![]
                        },
                    });
                }
                if request.path.starts_with("/native-peer-upload/") {
                    assert!(!final_chunk);
                    assert_eq!(request.path, "/native-peer-upload/slot/131072");
                    require_one_credit_from_two(pool, proxy);
                    checked.store(true, std::sync::atomic::Ordering::Release);
                    return Some(Response {
                        status: 400,
                        headers: vec![],
                        body: vec![],
                    });
                }
                Some(match command(request)["a"].as_str().unwrap() {
                    "u" => api(json!({"p":SLOT})),
                    "p" => {
                        assert!(final_chunk);
                        require_one_credit_from_two(pool, proxy);
                        checked.store(true, std::sync::atomic::Ordering::Release);
                        api(json!({"f":[{"h":"AQIDBAUG"}]}))
                    }
                    _ => panic!("credit fixture contacted an unexpected action"),
                })
            },
            |address| {
                let mut cloud = cloud(address);
                route.set(routed(&mut cloud, address)).ok().unwrap();
                let result = transfer(&mut cloud, &source, &states, &vault);
                if final_chunk {
                    let uploaded = result.unwrap();
                    assert_eq!(uploaded.size, 17);
                    uploaded.acknowledge().unwrap();
                } else {
                    assert!(matches!(result, Err(Error::Protocol(_))));
                    let paths: Vec<_> = std::fs::read_dir(&states)
                        .unwrap()
                        .map(|entry| entry.unwrap().path())
                        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
                        .collect();
                    assert_eq!(paths.len(), 1);
                    let saved = States::new(&paths[0]).load().unwrap().unwrap();
                    assert_eq!(saved.completed.keys().copied().collect::<Vec<_>>(), [0]);
                    assert!(saved.completion_token.is_none() && !saved.registration_started);
                }
                assert!(checked.load(std::sync::atomic::Ordering::Acquire));
            },
        );
        assert_eq!(calls.len(), 3);
    }
}

#[test]
fn every_upload_slot_expiry_neither_credits_nor_debits_the_actual_proxy_before_refresh() {
    for status in [403, 404, 410, 509] {
        let scratch = scratch();
        let source = source(scratch.path(), 17);
        let states = scratch.path().join("private state");
        let vault = Vault::new("synthetic upload passphrase");
        let route = OnceLock::new();
        let mut slots = 0;
        let ((), calls) = test_peer::with_connect_peer(
            |request| {
                let (pool, proxy): &(Arc<Pool>, String) = route.get().unwrap();
                if request.path.starts_with("/native-peer-upload/") {
                    assert_eq!(request.path, "/native-peer-upload/slot/0");
                    seed(pool, proxy, 2);
                    return Some(Response {
                        status,
                        headers: vec![],
                        body: vec![],
                    });
                }
                assert_eq!(command(request), json!({"a":"u","s":17}));
                slots += 1;
                if slots == 1 {
                    Some(api(json!({"p":SLOT})))
                } else {
                    assert_eq!(slots, 2);
                    assert!(
                        pool.pick().unwrap().is_some(),
                        "slot expiry blamed the proxy"
                    );
                    pool.report(proxy, false).unwrap();
                    assert!(
                        pool.pick().unwrap().is_none(),
                        "slot expiry credited the proxy"
                    );
                    // Refuse at the refresh boundary, after health inspection and before more work.
                    Some(api(json!({})))
                }
            },
            |address| {
                let mut cloud = cloud(address);
                route.set(routed(&mut cloud, address)).ok().unwrap();
                assert!(matches!(
                    transfer(&mut cloud, &source, &states, &vault),
                    Err(Error::AmbiguousMutation(_))
                ));
            },
        );
        assert_eq!((slots, calls.len()), (2, 3));
    }
}
