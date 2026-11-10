//! Owned offline TLS peer for native protocol tests, never compiled into production.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[test]
fn an_unscripted_request_preserves_the_original_assertion_after_the_peer_is_joined() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let observed = AtomicUsize::new(0);
    let mut refused = false;
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        with_peer(
            |request| {
                assert_eq!(request.method, "POST");
                assert!(request.path.starts_with("/cs?"));
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(&request.body).unwrap(),
                    serde_json::json!([{"a":"unscripted"}])
                );
                assert_eq!(observed.fetch_add(1, Ordering::SeqCst), 0);
                panic!("unscripted native peer action");
            },
            |peer| {
                let result = crate::protocol::api::Api::test_peer(peer)
                    .unwrap()
                    .request(serde_json::json!({"a":"unscripted"}), &[]);
                refused = matches!(
                    result,
                    Err(crate::error::Error::AmbiguousMutation("unknown"))
                );
            },
        );
    }))
    .unwrap_err();
    assert_eq!(
        panic.downcast_ref::<&str>().copied(),
        Some("unscripted native peer action")
    );
    assert!(refused);
    assert_eq!(observed.load(Ordering::SeqCst), 1);
}

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

const TOTAL: Duration = Duration::from_secs(15);
const IO: Duration = Duration::from_secs(5);
const MAX_HEADERS: usize = 16 * 1024;
const MAX_BODY: usize = 2 * 1024 * 1024;
const MAX_REQUESTS: usize = 32;

#[derive(Debug)]
pub(crate) struct Request {
    pub method: String,
    pub path: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
    pub connect_target: Option<String>,
}

pub(crate) struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

pub(crate) struct DeadlineSocket {
    socket: TcpStream,
    deadline: Instant,
}

impl DeadlineSocket {
    fn remaining(&self) -> io::Result<Duration> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "TLS peer deadline exceeded",
            ))
        } else {
            Ok(remaining)
        }
    }
}

impl Read for DeadlineSocket {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.socket.set_read_timeout(Some(self.remaining()?))?;
        self.socket.read(bytes)
    }
}

impl Write for DeadlineSocket {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.socket.set_write_timeout(Some(self.remaining()?))?;
        self.socket.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.socket.set_write_timeout(Some(self.remaining()?))?;
        self.socket.flush()
    }
}

fn config() -> Arc<rustls::ServerConfig> {
    let key = PrivateKeyDer::from_pem_slice(include_bytes!(
        "../../tests/fixtures/proxy_tls/public-test-key.txt"
    ))
    .unwrap();
    Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![
                CertificateDer::from(
                    include_bytes!("../../tests/fixtures/proxy_tls/server.der").to_vec(),
                ),
                CertificateDer::from(
                    include_bytes!("../../tests/fixtures/proxy_tls/intermediate.der").to_vec(),
                ),
            ],
            key,
        )
        .unwrap(),
    )
}

fn request(stream: &mut impl Read) -> Request {
    let mut raw = Vec::new();
    while !raw.ends_with(b"\r\n\r\n") {
        assert!(raw.len() < MAX_HEADERS, "TLS peer header bound exceeded");
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        raw.push(byte[0]);
    }
    let text = std::str::from_utf8(&raw).unwrap();
    let mut lines = text.split("\r\n");
    let mut start = lines.next().unwrap().split_whitespace();
    let method = start.next().unwrap().to_owned();
    let path = start.next().unwrap().to_owned();
    assert_eq!(start.next(), Some("HTTP/1.1"));
    assert!(start.next().is_none());
    let mut headers = BTreeMap::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (key, value) = line.split_once(':').unwrap();
        assert!(
            headers
                .insert(key.to_ascii_lowercase(), value.trim().to_owned())
                .is_none()
        );
    }
    assert!(
        !headers.contains_key("transfer-encoding"),
        "fixture expects a fixed body length"
    );
    let length = headers
        .get("content-length")
        .map_or(0, |value| value.parse::<usize>().unwrap());
    assert!(length <= MAX_BODY, "TLS peer body bound exceeded");
    let mut body = vec![0; length];
    stream.read_exact(&mut body).unwrap();
    Request {
        method,
        path,
        headers,
        body,
        connect_target: None,
    }
}

pub(crate) fn respond(stream: &mut impl Write, response: Response, keep_alive: bool) {
    assert!((100..=599).contains(&response.status));
    assert!(response.body.len() <= MAX_BODY);
    let mut head = format!(
        "HTTP/1.1 {} Fixture\r\nContent-Length: {}\r\nConnection: {}\r\n",
        response.status,
        response.body.len(),
        if keep_alive { "keep-alive" } else { "close" }
    );
    for (key, value) in response.headers {
        assert!(!key.contains(['\r', '\n', ':']) && !value.contains(['\r', '\n']));
        assert!(!matches!(
            key.to_ascii_lowercase().as_str(),
            "content-length" | "connection"
        ));
        head.push_str(&format!("{key}: {value}\r\n"));
    }
    assert!(head.len() < MAX_HEADERS);
    stream.write_all(head.as_bytes()).unwrap();
    stream.write_all(b"\r\n").unwrap();
    stream.write_all(&response.body).unwrap();
    stream.flush().unwrap();
}

/// Two owned request handlers permit real transfer-overlap assertions without another TLS stack.
pub(crate) fn with_parallel_peer<T>(
    reply: impl Fn(&Request) -> Option<Response> + Send + Sync,
    run: impl FnOnce(SocketAddr) -> T,
) -> (T, Vec<Request>) {
    with_raw_parallel_peer(
        |request, stream| {
            if let Some(response) = reply(request) {
                respond(stream, response, false);
            } else {
                stream.sock.socket.shutdown(Shutdown::Both).unwrap();
            }
        },
        run,
    )
}

pub(crate) fn with_raw_parallel_peer<T>(
    reply: impl Fn(&Request, &mut rustls::StreamOwned<rustls::ServerConnection, DeadlineSocket>)
    + Send
    + Sync,
    run: impl FnOnce(SocketAddr) -> T,
) -> (T, Vec<Request>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let config = config();
    let deadline = Instant::now() + TOTAL;
    let (stop, stopped) = mpsc::channel();
    let reply = &reply;
    std::thread::scope(|scope| {
        let peer = scope.spawn(move || {
            let mut calls = Vec::new();
            let mut workers = Vec::new();
            let (finished, completed) = mpsc::channel();
            let mut active = 0;
            for _ in 0..MAX_REQUESTS {
                while let Ok(request) = completed.try_recv() {
                    calls.push(request);
                    active -= 1;
                }
                if active == 2 {
                    calls.push(
                        completed
                            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                            .unwrap(),
                    );
                    active -= 1;
                }
                let socket = loop {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    assert!(!remaining.is_zero(), "Parallel TLS peer deadline exceeded");
                    match listener.accept() {
                        Ok((socket, _)) => break Some(socket),
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            match stopped.recv_timeout(remaining.min(Duration::from_millis(5))) {
                                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break None,
                                Err(mpsc::RecvTimeoutError::Timeout) => (),
                            }
                        }
                        Err(error) => panic!("Parallel TLS peer accept failed: {error}"),
                    }
                };
                let Some(socket) = socket else { break };
                if stopped.try_recv().is_ok() {
                    break;
                }
                socket.set_nonblocking(false).unwrap();
                let config = config.clone();
                let finished = finished.clone();
                active += 1;
                workers.push(scope.spawn(move || {
                    let mut stream = rustls::StreamOwned::new(
                        rustls::ServerConnection::new(config).unwrap(),
                        DeadlineSocket {
                            socket,
                            deadline: deadline.min(Instant::now() + IO),
                        },
                    );
                    let request = request(&mut stream);
                    reply(&request, &mut stream);
                    drop(stream);
                    finished.send(request).unwrap();
                }));
            }
            for worker in workers {
                worker.join().unwrap();
            }
            calls.extend(completed.try_iter());
            assert!(
                calls.len() < MAX_REQUESTS,
                "Parallel TLS peer request bound exceeded"
            );
            calls
        });
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(address)));
        let _ = stop.send(());
        let calls = peer.join().unwrap();
        match result {
            Ok(result) => {
                assert!(Instant::now() <= deadline);
                (result, calls)
            }
            Err(panic) => std::panic::resume_unwind(panic),
        }
    })
}

/// `None` closes the accepted socket after capturing the complete request body.
/// Bodies are at most 2 MiB, at most32 requests, with15s total and5s per accepted connection.
pub(crate) fn with_peer<T>(
    mut reply: impl FnMut(&Request) -> Option<Response> + Send,
    run: impl FnOnce(SocketAddr) -> T,
) -> (T, Vec<Request>) {
    serial_peer(
        None,
        move |request, stream| {
            if let Some(response) = reply(request) {
                respond(stream, response, false);
            } else {
                stream.sock.socket.shutdown(Shutdown::Both).unwrap();
            }
        },
        run,
    )
}

pub(crate) fn with_raw_peer<T>(
    reply: impl FnMut(&Request, &mut rustls::StreamOwned<rustls::ServerConnection, DeadlineSocket>)
    + Send,
    run: impl FnOnce(SocketAddr) -> T,
) -> (T, Vec<Request>) {
    serial_peer(None, reply, run)
}

/// The same bounded TLS peer behind an actual numeric HTTP CONNECT exchange.
pub(crate) fn with_connect_peer<T>(
    mut reply: impl FnMut(&Request) -> Option<Response> + Send,
    run: impl FnOnce(SocketAddr) -> T,
) -> (T, Vec<Request>) {
    serial_peer(
        Some(true),
        move |request, stream| {
            if let Some(response) = reply(request) {
                respond(stream, response, false);
            } else {
                stream.sock.socket.shutdown(Shutdown::Both).unwrap();
            }
        },
        run,
    )
}

pub(crate) fn with_raw_connect_peer<T>(
    reply: impl FnMut(&Request, &mut rustls::StreamOwned<rustls::ServerConnection, DeadlineSocket>)
    + Send,
    run: impl FnOnce(SocketAddr) -> T,
) -> (T, Vec<Request>) {
    serial_peer(Some(true), reply, run)
}

pub(crate) fn with_refusing_connect_peer<T>(
    run: impl FnOnce(SocketAddr) -> T,
) -> (T, Vec<Request>) {
    serial_peer(
        Some(false),
        |_, _| panic!("refused proxy reached target HTTP"),
        run,
    )
}

fn serial_peer<T>(
    connect: Option<bool>,
    mut reply: impl FnMut(&Request, &mut rustls::StreamOwned<rustls::ServerConnection, DeadlineSocket>)
    + Send,
    run: impl FnOnce(SocketAddr) -> T,
) -> (T, Vec<Request>) {
    let config = config();
    with_socket_peer(
        move |mut socket, address| {
            let connect_target = if let Some(allowed) = connect {
                let tunnel = request(&mut socket);
                assert_eq!(tunnel.method, "CONNECT");
                assert_eq!(tunnel.path, format!("1.1.1.1:{}", address.port()));
                assert_eq!(tunnel.headers["host"], tunnel.path);
                assert_eq!(tunnel.headers.len(), 1, "unexpected proxy credentials");
                assert!(tunnel.body.is_empty());
                if !allowed {
                    respond(
                        &mut socket,
                        Response {
                            status: 502,
                            headers: vec![],
                            body: vec![],
                        },
                        false,
                    );
                    return tunnel;
                }
                socket
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .unwrap();
                socket.flush().unwrap();
                Some(tunnel.path)
            } else {
                None
            };
            let mut stream = rustls::StreamOwned::new(
                rustls::ServerConnection::new(config.clone()).unwrap(),
                socket,
            );
            let mut request = request(&mut stream);
            if connect.is_some() {
                assert_eq!(stream.conn.server_name(), Some("testserver.com"));
            }
            request.connect_target = connect_target;
            reply(&request, &mut stream);
            request
        },
        run,
    )
}

/// Own the same serial accept/deadline/join lifecycle even when TLS itself must fail.
pub(crate) fn with_socket_peer<T, R: Send>(
    mut reply: impl FnMut(DeadlineSocket, SocketAddr) -> R + Send,
    run: impl FnOnce(SocketAddr) -> T,
) -> (T, Vec<R>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + TOTAL;
    let (stop, stopped) = mpsc::channel();
    std::thread::scope(|scope| {
        let peer = scope.spawn(move || {
            let mut calls = Vec::new();
            for _ in 0..MAX_REQUESTS {
                let socket = loop {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    assert!(!remaining.is_zero(), "TLS peer total deadline exceeded");
                    match listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            match stopped.recv_timeout(remaining.min(Duration::from_millis(5))) {
                                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return calls,
                                Err(mpsc::RecvTimeoutError::Timeout) => (),
                            }
                        }
                        Err(error) => panic!("TLS peer accept failed: {error}"),
                    }
                };
                if stopped.try_recv().is_ok() {
                    return calls;
                }
                socket.set_nonblocking(false).unwrap();
                let socket = DeadlineSocket {
                    socket,
                    deadline: deadline.min(Instant::now() + IO),
                };
                calls.push(reply(socket, address));
            }
            panic!("TLS peer request bound exceeded");
        });
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(address)));
        let _ = stop.send(());
        let calls = match peer.join() {
            Ok(calls) => calls,
            Err(panic) => std::panic::resume_unwind(panic),
        };
        match result {
            Ok(result) => {
                assert!(
                    Instant::now() <= deadline,
                    "TLS peer operation exceeded total deadline"
                );
                (result, calls)
            }
            Err(panic) => std::panic::resume_unwind(panic),
        }
    })
}
