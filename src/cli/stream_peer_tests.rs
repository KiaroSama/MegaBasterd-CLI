//! Parsed stream banners, private diagnostics and bounded cancellation at actual HTTP/TLS boundaries.
#![allow(clippy::unwrap_used)]

use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::Path,
    sync::{Arc, mpsc},
    time::{Duration, Instant},
};

use clap::Parser;
use serde_json::{Value, json};

use super::{args::Cli, auto_account_peer_tests::Capture, context::Context, dispatch};
use crate::{
    protocol::{api::Api, test_peer},
    terminal::{logging::Logger, output::Output},
    transfers::control::Control,
};

const LINK: &str = "https://mega.nz/file/FILEID#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const TOKEN: &str = "synthetic-stream-access-token";

struct Notices {
    capture: Capture,
    banner: mpsc::SyncSender<SocketAddr>,
    error: mpsc::SyncSender<()>,
    line: Vec<u8>,
}

impl Write for Notices {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.capture.write_all(bytes)?;
        for byte in bytes {
            self.line.push(*byte);
            if self.line.len() > 16 * 1024 {
                return Err(io::Error::other("stream fixture line exceeds its bound"));
            }
            if *byte == b'\n' {
                let line = std::str::from_utf8(&self.line)
                    .map_err(|_| io::Error::other("stream fixture output is not UTF-8"))?;
                if let Some((_, tail)) = line.split_once("Stream running at ") {
                    let url = tail.split_whitespace().next().unwrap();
                    let url = url::Url::parse(url).unwrap();
                    let host = url.host_str().unwrap().trim_matches(['[', ']']);
                    let address = SocketAddr::new(host.parse().unwrap(), url.port().unwrap());
                    self.banner.try_send(address).unwrap();
                }
                if line.contains("[ERROR]") && line.contains("4096") && line.contains("1000") {
                    self.error.try_send(()).unwrap();
                }
                self.line.clear();
            }
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct CancelOnDrop(Control);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

#[test]
fn parsed_stream_cancellation_closes_upstream_and_downstream_and_releases_the_listener() {
    use super::client_lifecycle_peer_tests::{observe_close, respond_and_observe_close};

    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/stream-cli");
    std::fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    let stdout = Capture::default();
    let stderr = Capture::default();
    let (banner, listening) = mpsc::sync_channel(1);
    let (error, error_seen) = mpsc::sync_channel(1);
    let (waiting, pending) = mpsc::sync_channel(1);
    let (closed, closures) = mpsc::sync_channel(2);
    let ((), calls) = test_peer::with_raw_peer(
        |request, stream| {
            if request.path.starts_with("/cs?") {
                assert_eq!(request.method, "POST");
                assert_eq!(
                    serde_json::from_slice::<Value>(&request.body).unwrap(),
                    json!([{"a":"g","g":1,"ssl":2,"p":"FILEID"}])
                );
                respond_and_observe_close(
                    stream,
                    200,
                    json!({"s":4096,"g":format!("https://{}/stalled", request.headers["host"])}),
                );
                closed.try_send("metadata").unwrap();
            } else {
                assert_eq!(request.method, "GET");
                assert_eq!(request.path, "/stalled");
                assert_eq!(request.headers["range"], "bytes=0-4095");
                stream.write_all(b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-4095/4096\r\nContent-Length: 4096\r\nConnection: keep-alive\r\n\r\n").unwrap();
                stream.flush().unwrap();
                waiting.try_send(()).unwrap();
                observe_close(stream);
                closed.try_send("cdn").unwrap();
            }
        },
        |address| {
            let mut api = Api::test_peer(address).unwrap();
            api.transport.timeout = Duration::from_secs(60);
            let mut context = Context::test_peer(
                scratch.path(),
                api,
                Output::with_writers(
                    false,
                    false,
                    stdout.clone(),
                    Notices {
                        capture: stderr.clone(),
                        banner,
                        error,
                        line: Vec::new(),
                    },
                ),
            );
            let control = context.control.clone();
            let command =
                Cli::try_parse_from(["mb", "stream", LINK, "--host", "127.0.0.1", "--port", "0"])
                    .unwrap()
                    .command
                    .unwrap();
            let (finished, done) = mpsc::sync_channel(1);
            std::thread::scope(|scope| {
                let shutdown = CancelOnDrop(control.clone());
                let command_context = &mut context;
                let worker = scope.spawn(move || {
                    finished.send(dispatch(command_context, command)).unwrap();
                });
                let local = listening.recv_timeout(Duration::from_secs(3)).unwrap();
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
                pending.recv_timeout(Duration::from_secs(2)).unwrap();
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
                let started = Instant::now();
                control.cancel();
                assert_eq!(
                    done.recv_timeout(Duration::from_secs(3)).unwrap().unwrap(),
                    0
                );
                worker.join().unwrap();
                assert!(started.elapsed() < Duration::from_secs(3));
                assert_eq!(client.read(&mut [0; 1]).unwrap(), 0);
                drop(client);
                assert!(TcpListener::bind(local).is_ok());
                assert_eq!(
                    closures.recv_timeout(Duration::from_secs(2)).unwrap(),
                    "metadata"
                );
                assert_eq!(
                    closures.recv_timeout(Duration::from_secs(2)).unwrap(),
                    "cdn"
                );
                assert!(closures.try_recv().is_err());
                drop(shutdown);
            });
            // Closure was observed before the parent Context and its API template are dropped.
            assert!(context.control.is_canceled());
            assert!(!context.paths.user.exists() && !context.paths.output.exists());
            assert!(!context.paths.logs.exists());
        },
    );
    assert_eq!(calls.len(), 2);
    assert!(stdout.0.lock().unwrap().is_empty());
    let messages = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
    assert_eq!(messages.lines().count(), 1);
    assert!(messages.starts_with("[INFO] Stream running at http://127.0.0.1:"));
    assert!(!messages.contains("[ERROR]") && !messages.contains(LINK));
    assert!(error_seen.try_recv().is_err());
    assert_eq!(std::fs::read_dir(scratch.path()).unwrap().count(), 0);
}

#[test]
fn parsed_stream_banners_are_dialable_tokens_stay_private_and_short_bodies_log_error_counts() {
    for (host, advertised, truncated, query_token) in [
        ("::1", "[::1]", false, false),
        ("0.0.0.0", "127.0.0.1", false, false),
        ("::", "[::1]", false, false),
        ("127.0.0.1", "127.0.0.1", true, false),
        ("127.0.0.1", "127.0.0.1", true, true),
    ] {
        let token = if query_token { "leaky-token" } else { TOKEN };
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/stream-cli");
        std::fs::create_dir_all(&base).unwrap();
        let scratch = tempfile::tempdir_in(base).unwrap();
        let stdout = Capture::default();
        let stderr = Capture::default();
        let (banner, listening) = mpsc::sync_channel(1);
        let (error, error_seen) = mpsc::sync_channel(1);
        let logger = Arc::new(Logger::start(&scratch.path().join("private logs")).unwrap());
        let log_path = scratch.path().join("private logs").join(logger.name());
        let (_, calls) = test_peer::with_raw_peer(
            |request, stream| {
                if request.path.starts_with("/cs?") {
                    let action: Value = serde_json::from_slice(&request.body).unwrap();
                    assert_eq!(action, json!([{"a":"g","g":1,"ssl":2,"p":"FILEID"}]));
                    let body = serde_json::to_vec(&json!([{"s":4096,"g":format!("https://{}/short", request.headers["host"])}])).unwrap();
                    write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
                    stream.write_all(&body).unwrap();
                } else {
                    assert!(truncated, "HEAD must never contact the CDN body");
                    assert_eq!(request.method, "GET");
                    assert_eq!(request.path, "/short");
                    assert_eq!(request.headers["range"], "bytes=0-4095");
                    stream.write_all(b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-4095/4096\r\nContent-Length: 4096\r\nConnection: close\r\n\r\n").unwrap();
                    stream.write_all(&[0; 1000]).unwrap();
                }
                stream.flush().unwrap();
                stream.conn.send_close_notify();
                stream.flush().unwrap();
            },
            |address| {
                let api = Api::test_peer(address).unwrap();
                let output = Output::with_writers(
                    false,
                    false,
                    stdout.clone(),
                    Notices {
                        capture: stderr.clone(),
                        banner,
                        error,
                        line: Vec::new(),
                    },
                );
                let mut context = Context::test_peer(scratch.path(), api, output);
                context.output.attach_logger(logger.clone()).unwrap();
                context.logger = Some(logger.clone());
                let control = context.control.clone();
                let mut arguments = vec![
                    "mb", "stream", LINK, "-H", host, "--port", "0", "--token", token,
                ];
                if query_token {
                    arguments.push("--allow-query-token");
                }
                let command = Cli::try_parse_from(arguments).unwrap().command.unwrap();
                let (finished, done) = mpsc::sync_channel(1);
                std::thread::scope(|scope| {
                    let shutdown = CancelOnDrop(control.clone());
                    let worker = scope.spawn(move || {
                        let result = dispatch(&mut context, command);
                        finished.send(result).unwrap();
                    });
                    let local = listening.recv_timeout(Duration::from_secs(3)).unwrap();
                    assert!(local.ip().is_loopback());
                    assert_eq!(local.ip().to_string(), advertised.trim_matches(['[', ']']));
                    let methods = if query_token {
                        vec!["HEAD", "GET"]
                    } else {
                        vec![if truncated { "GET" } else { "HEAD" }]
                    };
                    for method in methods {
                        let mut client =
                            TcpStream::connect_timeout(&local, Duration::from_secs(2)).unwrap();
                        client
                            .set_read_timeout(Some(Duration::from_secs(3)))
                            .unwrap();
                        client
                            .set_write_timeout(Some(Duration::from_secs(3)))
                            .unwrap();
                        if query_token {
                            write!(
                                client,
                                "{method} /?token={token} HTTP/1.1\r\nHost: localhost\r\n\r\n"
                            )
                            .unwrap();
                        } else {
                            write!(
                                client,
                                "{method} / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {TOKEN}\r\n\r\n"
                            )
                            .unwrap();
                        }
                        client.shutdown(std::net::Shutdown::Write).unwrap();
                        let mut raw = Vec::new();
                        client.take(8193).read_to_end(&mut raw).unwrap();
                        assert!(raw.len() <= 8192);
                        let boundary = raw
                            .windows(4)
                            .position(|bytes| bytes == b"\r\n\r\n")
                            .unwrap()
                            + 4;
                        assert!(raw.starts_with(b"HTTP/1.1 200 OK\r\n"));
                        assert!(
                            std::str::from_utf8(&raw[..boundary])
                                .unwrap()
                                .contains("Content-Length: 4096\r\n")
                        );
                        assert_eq!(raw.len() - boundary, if method == "GET" { 1000 } else { 0 });
                        if query_token {
                            assert!(!String::from_utf8_lossy(&raw).contains(token));
                        }
                        if method == "GET" {
                            error_seen.recv_timeout(Duration::from_secs(2)).unwrap();
                        }
                    }
                    let started = Instant::now();
                    control.cancel();
                    assert_eq!(
                        done.recv_timeout(Duration::from_secs(3)).unwrap().unwrap(),
                        0
                    );
                    worker.join().unwrap();
                    assert!(started.elapsed() < Duration::from_secs(3));
                    assert!(
                        TcpListener::bind((host.trim_matches(['[', ']']), local.port())).is_ok()
                    );
                    drop(shutdown);
                });
            },
        );
        assert_eq!(calls.len(), if truncated { 2 } else { 1 });
        let log = std::fs::read_to_string(log_path).unwrap();
        if truncated {
            assert!(log.lines().any(|line| line.contains("[ERROR] [STREAM]")
                && line.contains("4096")
                && line.contains("1000")));
        }
        let diagnostic = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
        assert!(diagnostic.contains(&format!("http://{advertised}:")));
        assert!(!diagnostic.contains("http://0.0.0.0:") && !diagnostic.contains("http://::"));
        assert!(stdout.0.lock().unwrap().is_empty());
        if query_token {
            assert!(
                log.lines().any(|line| line.contains("[INFO] [STREAM]")
                    && line.contains("Local listener started"))
            );
            assert!(diagnostic.lines().any(|line| line.contains("[ERROR]")
                && line.contains("4096")
                && line.contains("1000")));
        }
        for text in [&log, &diagnostic] {
            for secret in [TOKEN, LINK, "Authorization: Bearer synthetic", token] {
                assert!(!text.contains(secret));
            }
        }
    }
}
