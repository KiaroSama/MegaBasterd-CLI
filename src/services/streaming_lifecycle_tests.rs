//! Actual stalled upstream cancellation and truncated downstream framing.
#![allow(clippy::unwrap_used)]

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    time::Duration,
};

use super::{info, local_outcome};
use crate::{
    error::Error,
    protocol::{api::Api, test_peer},
    services::streaming::StreamServer,
    transfers::control::Control,
};

struct CancelOnDrop(Control);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

#[test]
fn cancel_stalled_cdn_body_reaps_stream_workers_closes_upstream_and_releases_listener() {
    let (waiting, ready) = mpsc::sync_channel(1);
    let (_, calls) = test_peer::with_raw_peer(
        |request, stream| {
            assert_eq!(request.method, "GET");
            assert_eq!(request.path, "/cdn");
            assert_eq!(request.headers["range"], "bytes=0-4095");
            stream.write_all(b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-4095/4096\r\nContent-Length: 4096\r\nConnection: close\r\n\r\n").unwrap();
            stream.flush().unwrap();
            waiting.send(()).unwrap();
            match stream.read(&mut [0; 1]) {
                Ok(0) => (),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::UnexpectedEof
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                    ) => {}
                result => panic!("stream shutdown left its CDN socket open: {result:?}"),
            }
        },
        |address| {
            let mut api = Api::test_peer(address).unwrap();
            api.transport.timeout = Duration::from_secs(60);
            let control = api.control.clone();
            let mut source = info(address);
            source.size = 4096;
            let server = StreamServer::bind("127.0.0.1", 0, api, source, None, false).unwrap();
            let local = server.address().unwrap();
            let (finished, done) = mpsc::sync_channel(1);
            std::thread::scope(|scope| {
                let shutdown = CancelOnDrop(control.clone());
                let server_control = &control;
                let worker = scope.spawn(move || {
                    let result = server.serve(server_control, |_| ());
                    finished.send(()).unwrap();
                    result
                });
                let mut client =
                    TcpStream::connect_timeout(&local, Duration::from_secs(2)).unwrap();
                client
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                client
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                client
                    .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    .unwrap();
                ready.recv_timeout(Duration::from_secs(2)).unwrap();
                // Wait for the actual downstream headers: the handler has opened its stalled CDN body.
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    assert!(head.len() < 8192);
                    let mut byte = [0];
                    client.read_exact(&mut byte).unwrap();
                    head.push(byte[0]);
                }
                assert!(head.starts_with(b"HTTP/1.1 200 OK\r\n"));
                assert!(
                    std::str::from_utf8(&head)
                        .unwrap()
                        .contains("Content-Length: 4096\r\n")
                );
                control.cancel();
                done.recv_timeout(Duration::from_secs(3)).unwrap();
                worker.join().unwrap().unwrap();
                assert_eq!(client.read(&mut [0; 1]).unwrap(), 0);
                drop(client);
                assert!(
                    TcpListener::bind(local).is_ok(),
                    "stream listener survived shutdown"
                );
                drop(shutdown);
            });
        },
    );
    assert_eq!(calls.len(), 1);
}

#[test]
fn short_cdn_body_keeps_promised_length_and_reports_exact_counts_without_a_second_response() {
    let (_, calls) = test_peer::with_raw_peer(
        |request, stream| {
            assert_eq!(request.method, "GET");
            assert_eq!(request.headers["range"], "bytes=0-4095");
            stream.write_all(b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-4095/4096\r\nContent-Length: 4096\r\nConnection: close\r\n\r\n").unwrap();
            stream
                .write_all(
                    &include_bytes!("../../tests/fixtures/transfers/ciphertext-131089.bin")[..1000],
                )
                .unwrap();
            stream.flush().unwrap();
            stream.conn.send_close_notify();
            stream.flush().unwrap();
        },
        |address| {
            let mut source = info(address);
            source.size = 4096;
            let api = Api::test_peer(address).unwrap();
            let control = api.control.clone();
            let server = StreamServer::bind("127.0.0.1", 0, api, source, None, false).unwrap();
            let (reply, handled) = local_outcome(
                &server,
                b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
                &control,
            );
            assert_eq!(reply.status, 200);
            assert_eq!(reply.headers["content-length"], "4096");
            assert_eq!(
                reply.body,
                (0..1000)
                    .map(|i| ((13 * i + 7) % 256) as u8)
                    .collect::<Vec<_>>()
            );
            assert!(
                matches!(handled, Err(Error::Protocol(message)) if message.contains("4096") && message.contains("1000"))
            );
            assert!(!reply.body.windows(5).any(|bytes| bytes == b"HTTP/"));
        },
    );
    assert_eq!(
        calls.len(),
        1,
        "a truncated body must not refresh or replay the stream"
    );
}
