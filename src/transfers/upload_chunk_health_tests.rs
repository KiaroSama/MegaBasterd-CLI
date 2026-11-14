//! Real proxy failure accounting on each actual upload retry, without sleeping through cooldowns.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::{
    protocol::test_peer,
    storage::proxies::{Pool, ProxyStore, Routing},
};
use std::{
    io::Write,
    sync::{Arc, OnceLock},
};

#[derive(Clone, Copy, Debug)]
enum Failure {
    Headers,
    Body,
    Timeout,
    Server,
}

fn one_debit(pool: &Pool, proxy: &str) {
    assert!(
        pool.pick().unwrap().is_some(),
        "proxy was debited twice in one attempt"
    );
    pool.report(proxy, false).unwrap();
    assert!(
        pool.pick().unwrap().is_none(),
        "attempt earned credit or no failure debit"
    );
}

fn fresh_route(store: &ProxyStore, pool: &Pool, proxy: &str) {
    store
        .update(|urls| *urls = vec!["http://127.0.0.1:1".into()])
        .unwrap();
    pool.reload().unwrap();
    store.update(|urls| *urls = vec![proxy.into()]).unwrap();
    pool.reload().unwrap();
    assert_eq!(pool.pick().unwrap().as_deref(), Some(proxy));
    pool.report(proxy, false).unwrap();
}

#[test]
fn each_real_connection_body_timeout_and_server_failure_debits_the_proxy_once_per_attempt() {
    for failure in [
        Failure::Headers,
        Failure::Body,
        Failure::Timeout,
        Failure::Server,
    ] {
        let base =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/upload-retry-health");
        std::fs::create_dir_all(&base).unwrap();
        let scratch = crate::test_support::tempdir_in(base).unwrap();
        let store = ProxyStore::new(scratch.path().join("pool.json"));
        let route = OnceLock::new();
        let mut waits = Vec::new();
        let (result, calls) = test_peer::with_raw_connect_peer(
            |request, stream| {
                assert_eq!(request.method, "POST");
                assert_eq!(request.path, "/native-peer-upload/retries/0");
                assert_eq!(request.body, b"ciphertext");
                assert!(request.connect_target.is_some());
                match failure {
                    Failure::Headers => (),
                    Failure::Body => {
                        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nT").unwrap();
                        stream.flush().unwrap();
                    }
                    Failure::Timeout => tests::require_eof(stream),
                    Failure::Server => {
                        stream.write_all(b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                        stream.flush().unwrap();
                    }
                }
            },
            |address| {
                let proxy = format!("http://127.0.0.1:{}", address.port());
                store.update(|urls| urls.push(proxy.clone())).unwrap();
                let pool = Pool::new(
                    vec![proxy.clone()],
                    vec![],
                    Some(scratch.path().join("pool.json")),
                )
                .unwrap();
                pool.report(&proxy, false).unwrap();
                route.set((pool.clone(), proxy.clone())).ok().unwrap();
                let control = Control::new();
                let mut transport = Transport::test_peer(address, control.clone()).unwrap();
                transport.timeout = Duration::from_secs(1);
                transport.routing = Routing {
                    explicit: None,
                    pool: Some(pool.clone()),
                    force: true,
                };
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
                    one_debit(&pool, &proxy);
                    waits.push(duration.as_secs());
                    fresh_route(&store, &pool, &proxy);
                    Ok(())
                })
            },
        );
        let error = result.err().unwrap();
        match failure {
            Failure::Server => assert!(
                matches!(error,Error::Protocol(message) if message == "Upload chunk returned HTTP 503")
            ),
            Failure::Timeout => assert!(matches!(error, Error::Timeout)),
            Failure::Headers | Failure::Body => assert!(error.retryable_network()),
        }
        let (pool, proxy): &(Arc<Pool>, String) = route.get().unwrap();
        one_debit(pool, proxy);
        assert_eq!(calls.len(), 5);
        assert_eq!(waits, [2, 4, 8, 16]);
        assert_eq!(store.list().unwrap(), std::slice::from_ref(proxy));
    }
}
