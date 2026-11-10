//! Decoded service response caps apply while streaming and release the actual TLS connection.
#![allow(clippy::unwrap_used)]

use super::*;
use flate2::{Compression, write::GzEncoder};

#[test]
fn all_link_services_bound_identity_and_gzip_bodies_and_close_before_returning() {
    let limit = containers::MAX_SERVICE_BYTES;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    std::io::copy(
        &mut std::io::repeat(b'x').take(limit as u64 + 1),
        &mut encoder,
    )
    .unwrap();
    let compressed = encoder.finish().unwrap();
    assert!(compressed.len() < 64 * 1024);
    for proxied in [false, true] {
        for gzip in [false, true] {
            for kind in 0..3 {
                let (closed, closure) = mpsc::sync_channel(1);
                let reply = |request: &test_peer::Request,
                             stream: &mut rustls::StreamOwned<
                    rustls::ServerConnection,
                    test_peer::DeadlineSocket,
                >| {
                    assert_request(request, kind);
                    assert_eq!(request.connect_target.is_some(), proxied);
                    // No oversized Content-Length: this must reach the streamed body guard.
                    stream
                        .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n")
                        .unwrap();
                    if gzip {
                        stream.write_all(b"Content-Encoding: gzip\r\n").unwrap();
                    }
                    stream.write_all(b"\r\n").unwrap();
                    if gzip {
                        stream.write_all(&compressed).unwrap();
                    } else {
                        let block = [b'x'; 16 * 1024];
                        let mut remaining = limit + 1;
                        while remaining != 0 {
                            let count = remaining.min(block.len());
                            stream.write_all(&block[..count]).unwrap();
                            remaining -= count;
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
                            ) =>
                        {
                            ()
                        }
                        other => panic!("oversized service body left its socket open: {other:?}"),
                    }
                    closed.send(()).unwrap();
                };
                let run = |address| {
                    let mut api = Api::test_peer(address).unwrap();
                    let selected = proxied.then(|| route(&mut api, address, 2));
                    let accounts = BTreeMap::new();
                    let resolver = Resolver {
                        transport: &api.transport,
                        password: None,
                        elc_user: Some("synthetic-user"),
                        elc_api_key: Some("synthetic-key"),
                        elc_accounts: &accounts,
                    };
                    assert!(matches!(call(&resolver, address, kind),
                        Err(Error::Protocol(message)) if message == "Decoded response exceeds its size limit"));
                    closure.recv_timeout(Duration::from_secs(2)).unwrap();
                    if let Some((pool, proxy)) = selected {
                        pool.report(&proxy, false).unwrap();
                        assert!(
                            pool.pick().unwrap().is_none(),
                            "unreadable body earned proxy credit"
                        );
                    }
                };
                let ((), calls) = if proxied {
                    test_peer::with_raw_connect_peer(reply, run)
                } else {
                    test_peer::with_raw_peer(reply, run)
                };
                assert_eq!(calls.len(), 1, "oversized service response was replayed");
            }
        }
    }
}
