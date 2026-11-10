//! Actual local stream HTTP bytes through the same TLS CDN boundary as a transfer.
#![allow(clippy::unwrap_used)]

use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::time::Duration;

use serde_json::Value;
use zeroize::Zeroizing;

use super::StreamServer;
use crate::protocol::{
    api::Api,
    metadata::{DownloadSource, FileInfo},
    test_peer::{self, Request, Response},
};
use crate::transfers::control::Control;

fn info(address: std::net::SocketAddr) -> FileInfo {
    let vectors: Value =
        serde_json::from_str(include_str!("../../tests/fixtures/transfers/vectors.json")).unwrap();
    let vector = vectors["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["size"] == 131089)
        .unwrap();
    FileInfo {
        name: "OAD -  09v2.mkv".into(),
        size: 131089,
        raw_key: Zeroizing::new(hex::decode(vector["raw_key"].as_str().unwrap()).unwrap()),
        url: format!("https://testserver.com:{}/cdn", address.port()),
        handle: "fixture".into(),
        public_id: "fixture".into(),
        source: DownloadSource::Public,
    }
}

fn upstream(request: &Request) -> Response {
    assert_eq!(request.method, "GET");
    assert_eq!(request.path, "/cdn");
    let range = request.headers["range"].strip_prefix("bytes=").unwrap();
    let (start, end) = range.split_once('-').unwrap();
    let (start, end) = (
        start.parse::<usize>().unwrap(),
        end.parse::<usize>().unwrap(),
    );
    let ciphertext = include_bytes!("../../tests/fixtures/transfers/ciphertext-131089.bin");
    assert!(start <= end && end < ciphertext.len());
    Response {
        status: 206,
        headers: vec![(
            "Content-Range".into(),
            format!("bytes {start}-{end}/{}", ciphertext.len()),
        )],
        body: ciphertext[start..=end].to_vec(),
    }
}

struct LocalReply {
    status: u16,
    headers: std::collections::BTreeMap<String, String>,
    body: Vec<u8>,
}

fn local(server: &StreamServer, request: &[u8], control: &Control) -> LocalReply {
    let (reply, handled) = local_outcome(server, request, control);
    handled.unwrap();
    reply
}

fn local_outcome(
    server: &StreamServer,
    request: &[u8],
    control: &Control,
) -> (LocalReply, crate::error::Result<()>) {
    let (response, handled) =
        local_raw_outcome(server, request, |stream| server.handle(stream, control));
    let index = response
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .unwrap();
    let header = std::str::from_utf8(&response[..index]).unwrap();
    let mut lines = header.split("\r\n");
    let status = lines
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers = lines
        .map(|line| {
            let (key, value) = line.split_once(':').unwrap();
            (key.to_ascii_lowercase(), value.trim().to_owned())
        })
        .collect();
    (
        LocalReply {
            status,
            headers,
            body: response[index + 4..].to_vec(),
        },
        handled,
    )
}

fn local_raw_outcome(
    server: &StreamServer,
    request: &[u8],
    handle: impl FnOnce(&mut TcpStream) -> crate::error::Result<()> + Send,
) -> (Vec<u8>, crate::error::Result<()>) {
    let address = server.address().unwrap();
    let mut socket = TcpStream::connect_timeout(&address, Duration::from_secs(3)).unwrap();
    server.listener.set_nonblocking(true).unwrap();
    let (mut accepted, _) = server.listener.accept().unwrap();
    accepted.set_nonblocking(false).unwrap();
    accepted
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    std::thread::scope(|scope| {
        let handler = scope.spawn(move || {
            let result = handle(&mut accepted);
            let _ = accepted.shutdown(Shutdown::Both);
            result
        });
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket.write_all(request).unwrap();
        socket.shutdown(Shutdown::Write).unwrap();
        let mut response = Vec::new();
        socket.take(256 * 1024).read_to_end(&mut response).unwrap();
        (response, handler.join().unwrap())
    })
}

#[test]
fn real_full_midblock_suffix_and_head_responses_preserve_source_bytes_and_headers() {
    let (_, calls) = test_peer::with_peer(
        |request| Some(upstream(request)),
        |address| {
            let api = Api::test_peer(address).unwrap();
            let server =
                StreamServer::bind("127.0.0.1", 0, api, info(address), None, false).unwrap();
            let control = Control::new();
            for (header, start, end, status) in [
                ("", 0, 131088, 200),
                ("Range: bytes=7-31\r\n", 7, 31, 206),
                ("Range: bytes=-17\r\n", 131072, 131088, 206),
                ("Range: bytes=131071-\r\n", 131071, 131088, 206),
            ] {
                let request = format!("GET / HTTP/1.1\r\nHost: localhost\r\n{header}\r\n");
                let response = local(&server, request.as_bytes(), &control);
                assert_eq!(response.status, status);
                let expected = (start..=end)
                    .map(|i| ((13 * i + 7) % 256) as u8)
                    .collect::<Vec<_>>();
                assert_eq!(response.body, expected);
                assert_eq!(
                    response.headers["content-length"],
                    expected.len().to_string()
                );
                assert_eq!(response.headers["content-type"], "video/x-matroska");
                assert!(response.headers["content-disposition"].contains("OAD%20-%20%2009v2.mkv"));
                if status == 206 {
                    assert_eq!(
                        response.headers["content-range"],
                        format!("bytes {start}-{end}/131089")
                    );
                } else {
                    assert!(!response.headers.contains_key("content-range"));
                }
            }
            let response = local(
                &server,
                b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n",
                &control,
            );
            assert_eq!(response.status, 200);
            assert_eq!(response.headers["content-length"], "131089");
            assert!(response.body.is_empty());
        },
    );
    assert_eq!(calls.len(), 4, "HEAD must not contact the encrypted CDN");
}

#[test]
fn public_stream_without_filename_attributes_keeps_handle_name_and_serves_head_without_content_request()
 {
    let (_, calls) = test_peer::with_peer(
        |request| {
            let command: Value = serde_json::from_slice(&request.body).unwrap();
            assert_eq!(
                command,
                serde_json::json!([{"a":"g","g":1,"ssl":2,"p":"FILEID"}])
            );
            Some(Response {
                status: 200,
                headers: vec![("Content-Type".into(), "application/json".into())],
                body: serde_json::to_vec(
                    &serde_json::json!([{"g":"https://example.invalid/file","s":1}]),
                )
                .unwrap(),
            })
        },
        |address| {
            let mut api = Api::test_peer(address).unwrap();
            let link = crate::protocol::links::parse_link(
                "https://mega.nz/file/FILEID#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            )
            .unwrap();
            let info = crate::protocol::metadata::file(&mut api, &link).unwrap();
            assert_eq!(info.name, "FILEID");
            assert_eq!(info.size, 1);
            let server = StreamServer::bind("127.0.0.1", 0, api, info, None, false).unwrap();
            let reply = local(
                &server,
                b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n",
                &Control::new(),
            );
            assert_eq!(reply.status, 200);
            assert_eq!(reply.headers["content-length"], "1");
            assert!(reply.headers["content-disposition"].contains("filename=\"FILEID\""));
            assert!(reply.body.is_empty());
        },
    );
    assert_eq!(
        calls.len(),
        1,
        "HEAD fallback must only inspect metadata, never download bytes"
    );
}

#[test]
fn authentication_and_bad_local_ranges_refuse_before_any_upstream_request() {
    let (_, calls) = test_peer::with_peer(
        |_| panic!("refused local request reached CDN"),
        |address| {
            let server = StreamServer::bind(
                "127.0.0.1",
                0,
                Api::test_peer(address).unwrap(),
                info(address),
                Some("synthetic-token".into()),
                false,
            )
            .unwrap();
            let control = Control::new();
            for (request, status) in [
                ("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", 401),
                (
                    "GET /?token=synthetic-token HTTP/1.1\r\nHost: localhost\r\n\r\n",
                    401,
                ),
                (
                    "GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer wrong\r\n\r\n",
                    401,
                ),
                (
                    "POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer synthetic-token\r\n\r\n",
                    405,
                ),
                (
                    "GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer synthetic-token\r\nRange: bits=1-3\r\n\r\n",
                    400,
                ),
                (
                    "GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer synthetic-token\r\nRange: bytes=131089-\r\n\r\n",
                    416,
                ),
            ] {
                let response = local(&server, request.as_bytes(), &control);
                assert_eq!(response.status, status);
                assert!(response.body.is_empty());
                if status == 416 {
                    assert_eq!(response.headers["content-range"], "bytes */131089");
                }
            }
        },
    );
    assert!(calls.is_empty());
}

#[test]
fn blank_public_tokens_refuse_before_bind_and_leave_the_selected_port_available() {
    use crate::error::Error;
    let (_, calls) = test_peer::with_peer(
        |_| panic!("listener authentication policy reached upstream"),
        |address| {
            for host in ["0.0.0.0", "::", "192.168.1.10", "example.com"] {
                for token in [None, Some(""), Some("   ")] {
                    let error = StreamServer::bind(
                        host,
                        0,
                        Api::test_peer(address).unwrap(),
                        info(address),
                        token.map(str::to_owned),
                        false,
                    )
                    .err()
                    .unwrap();
                    assert!(matches!(&error, Error::Invalid(message) if message.contains("token")));
                }
            }
            let probe = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
            let port = probe.local_addr().unwrap().port();
            drop(probe);
            assert!(
                StreamServer::bind(
                    "0.0.0.0",
                    port,
                    Api::test_peer(address).unwrap(),
                    info(address),
                    None,
                    false,
                )
                .is_err()
            );
            let rebound =
                std::net::TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, port)).unwrap();
            drop(rebound);
            let server = StreamServer::bind(
                "0.0.0.0",
                0,
                Api::test_peer(address).unwrap(),
                info(address),
                Some("a-real-token".into()),
                false,
            )
            .unwrap();
            assert_eq!(
                server.token.as_deref().map(String::as_str),
                Some("a-real-token")
            );
            // A real token is not silently trimmed or changed by the blank-token guard.
            let spaced = StreamServer::bind(
                "127.0.0.1",
                0,
                Api::test_peer(address).unwrap(),
                info(address),
                Some(" a-real-token ".into()),
                false,
            )
            .unwrap();
            assert_eq!(
                spaced.token.as_deref().map(String::as_str),
                Some(" a-real-token ")
            );
            let oversized = "x".repeat(8193);
            for token in ["bad\r\ntoken", "bad\0token", "\t", &oversized] {
                assert!(
                    StreamServer::bind(
                        "127.0.0.1",
                        0,
                        Api::test_peer(address).unwrap(),
                        info(address),
                        Some(token.into()),
                        false,
                    )
                    .is_err()
                );
            }
        },
    );
    assert!(calls.is_empty());
}

#[test]
fn exact_source_head_authentication_and_query_opt_in_are_enforced_before_upstream() {
    let (_, calls) = test_peer::with_peer(
        |_| panic!("HEAD or refused authentication contacted upstream"),
        |address| {
            for (token, query_allowed) in [
                (None, false),
                (Some("s3cret-token"), false),
                (Some("   "), false),
                (Some("qtok"), true),
            ] {
                let server = StreamServer::bind(
                    "127.0.0.1",
                    0,
                    Api::test_peer(address).unwrap(),
                    info(address),
                    token.map(str::to_owned),
                    query_allowed,
                )
                .unwrap();
                assert_eq!(server.token.as_deref().map(String::as_str), token);
                for (path, auth, status) in match token {
                    None => vec![("/", "", 200)],
                    Some("   ") => vec![("/", "", 401)],
                    Some("s3cret-token") => vec![
                        ("/", "", 401),
                        ("/", "Authorization: Bearer s3cret-token\r\n", 200),
                        ("/", "Authorization: Bearer nope\r\n", 401),
                        ("/", "Authorization: Basic s3cret-token\r\n", 401),
                        ("/?token=s3cret-token", "", 401),
                        ("/?access_token=s3cret-token", "", 401),
                    ],
                    _ => vec![
                        ("/?token=qtok", "", 200),
                        ("/?token=wrong", "", 401),
                        ("/", "Authorization: Bearer qtok\r\n", 200),
                    ],
                } {
                    let request = format!("HEAD {path} HTTP/1.1\r\nHost: localhost\r\n{auth}\r\n");
                    let response = local(&server, request.as_bytes(), &Control::new());
                    assert_eq!(response.status, status);
                    assert!(response.body.is_empty());
                    if status == 200 {
                        assert_eq!(response.headers["content-length"], "131089");
                    } else {
                        assert!(response.headers["www-authenticate"].starts_with("Bearer "));
                    }
                }
            }
            let server = StreamServer::bind(
                "127.0.0.1",
                0,
                Api::test_peer(address).unwrap(),
                info(address),
                Some("rtok".into()),
                false,
            )
            .unwrap();
            assert_eq!(
                local(
                    &server,
                    b"GET / HTTP/1.1\r\nHost: localhost\r\nRange: bytes=0-3\r\n\r\n",
                    &Control::new()
                )
                .status,
                401
            );
        },
    );
    assert!(calls.is_empty());
}

#[test]
fn empty_stream_get_head_and_unsatisfiable_range_never_fetch_upstream() {
    let (_, calls) = test_peer::with_peer(
        |_| panic!("zero-byte stream fetched upstream"),
        |address| {
            let mut empty = info(address);
            empty.name = "empty.txt".into();
            empty.size = 0;
            let server = StreamServer::bind(
                "127.0.0.1",
                0,
                Api::test_peer(address).unwrap(),
                empty,
                None,
                false,
            )
            .unwrap();
            for (method, range, status) in [
                ("GET", "", 200),
                ("HEAD", "", 200),
                ("GET", "Range: bytes=0-\r\n", 416),
            ] {
                let request = format!("{method} / HTTP/1.1\r\nHost: localhost\r\n{range}\r\n");
                let response = local(&server, request.as_bytes(), &Control::new());
                assert_eq!(response.status, status);
                assert_eq!(response.headers["content-length"], "0");
                assert!(response.body.is_empty());
                if status == 416 {
                    assert_eq!(response.headers["content-range"], "bytes */0");
                }
            }
        },
    );
    assert!(calls.is_empty());
}

#[test]
fn ipv6_plain_and_bracketed_hosts_bind_and_serve_head() {
    let (_, calls) = test_peer::with_peer(
        |_| panic!("IPv6 HEAD fetched upstream"),
        |address| {
            for host in ["::1", "[::1]"] {
                let server = StreamServer::bind(
                    host,
                    0,
                    Api::test_peer(address).unwrap(),
                    info(address),
                    None,
                    false,
                )
                .unwrap();
                assert!(server.address().unwrap().is_ipv6());
                let response = local(
                    &server,
                    b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n",
                    &Control::new(),
                );
                assert_eq!(response.status, 200);
                assert_eq!(response.headers["content-length"], "131089");
                assert!(response.body.is_empty());
            }
        },
    );
    assert!(calls.is_empty());
}

#[path = "streaming_failure_tests.rs"]
mod failure_contract;
#[path = "streaming_lifecycle_tests.rs"]
mod lifecycle_contract;
#[path = "streaming_proxy_tests.rs"]
mod proxy_contract;
#[path = "streaming_upstream_tests.rs"]
mod upstream_contract;

#[test]
fn explicit_query_token_and_authorization_allow_only_the_expected_plaintext_range() {
    let (_, calls) = test_peer::with_peer(
        |request| Some(upstream(request)),
        |address| {
            let server = StreamServer::bind(
                "127.0.0.1",
                0,
                Api::test_peer(address).unwrap(),
                info(address),
                Some("synthetic-token".into()),
                true,
            )
            .unwrap();
            for request in [
                "GET /?token=synthetic-token HTTP/1.1\r\nHost: localhost\r\nRange: bytes=1-1\r\n\r\n",
                "GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer synthetic-token\r\nRange: bytes=1-1\r\n\r\n",
            ] {
                let response = local(&server, request.as_bytes(), &Control::new());
                assert_eq!(response.status, 206);
                assert_eq!(response.body, [20]);
            }
        },
    );
    assert_eq!(calls.len(), 2);
}
