//! Upstream diagnostic causes never become HTTP response bodies or headers.
#![allow(clippy::unwrap_used)]

use super::{info, local_raw_outcome};
use crate::{
    error::Error,
    protocol::{
        api::Api,
        test_peer::{self, Response},
    },
    services::streaming::StreamServer,
    transfers::control::Control,
};
use reqwest::Method;

const LEAKY: &str = "HTTPSConnectionPool(host='cdn.invalid', port=443): Max retries exceeded with url: /dl/CDNSECRET (Caused by ProxyError('Cannot connect to proxy', NewConnectionError('http://spy:hunter2@proxy.invalid:8080')))";
const SECRETS: [&str; 3] = ["hunter2", "CDNSECRET", "spy:hunter2"];

#[test]
fn request_and_refresh_errors_keep_the_original_cause_but_send_only_fixed_502_bytes() {
    for mode in ["routing", "send", "refresh", "success"] {
        let ((), calls) = test_peer::with_peer(
            |request| {
                assert_eq!(request.method, "GET");
                assert_eq!(request.path, "/cdn");
                assert_eq!(request.headers["range"], "bytes=0-16");
                assert!(
                    matches!(mode, "refresh" | "success"),
                    "injected pre-request failure reached the network"
                );
                Some(if mode == "refresh" {
                    Response {
                        status: 403,
                        headers: vec![],
                        body: vec![],
                    }
                } else {
                    Response {
                        status: 206,
                        headers: vec![("Content-Range".into(), "bytes 0-16/17".into())],
                        body: include_bytes!(
                            "../../tests/fixtures/transfers/ciphertext-131089.bin"
                        )[..17]
                            .to_vec(),
                    }
                })
            },
            |address| {
                let mut source = info(address);
                source.size = 17;
                let original_url = source.url.clone();
                let server = StreamServer::bind(
                    "127.0.0.1",
                    0,
                    Api::test_peer(address).unwrap(),
                    source,
                    None,
                    false,
                )
                .unwrap();
                let control = Control::new();
                let (raw, result) = local_raw_outcome(
                    &server,
                    b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
                    |socket| {
                        let mut sends = 0;
                        let mut refreshes = 0;
                        let outcome = server.handle_with(socket, &control, |range| {
                            if mode == "routing" {
                                return Err(Error::protocol(LEAKY));
                            }
                            server.open_with(
                                range,
                                &control,
                                |transport, url, headers| {
                                    sends += 1;
                                    assert_eq!(url.as_str(), original_url);
                                    assert_eq!(headers[reqwest::header::RANGE], "bytes=0-16");
                                    if mode == "send" {
                                        Err(std::io::Error::new(
                                            std::io::ErrorKind::ConnectionAborted,
                                            LEAKY,
                                        )
                                        .into())
                                    } else {
                                        transport.send(Method::GET, url, headers, None, false)
                                    }
                                },
                                |_, current| {
                                    refreshes += 1;
                                    assert_eq!(mode, "refresh");
                                    assert_eq!(current.url, original_url);
                                    Err(Error::protocol(LEAKY))
                                },
                            )
                        });
                        assert_eq!(sends, usize::from(mode != "routing"));
                        assert_eq!(refreshes, usize::from(mode == "refresh"));
                        outcome
                    },
                );
                let boundary = raw
                    .windows(4)
                    .position(|bytes| bytes == b"\r\n\r\n")
                    .unwrap()
                    + 4;
                if mode == "success" {
                    result.unwrap();
                    assert!(raw.starts_with(b"HTTP/1.1 200 OK\r\n"));
                    assert_eq!(
                        raw[boundary..],
                        (0..17)
                            .map(|index| ((13 * index + 7) % 256) as u8)
                            .collect::<Vec<_>>()
                    );
                } else {
                    let error = result.unwrap_err();
                    assert!(matches!(
                        (&error, mode),
                        (Error::Io(_), "send") | (Error::Protocol(_), "routing" | "refresh")
                    ));
                    for secret in SECRETS {
                        assert!(
                            error.to_string().contains(secret),
                            "missing positive diagnostic control"
                        );
                    }
                    let expected = b"Upstream stream unavailable";
                    assert!(raw.starts_with(b"HTTP/1.1 502 Bad Gateway\r\n"));
                    assert!(
                        std::str::from_utf8(&raw[..boundary])
                            .unwrap()
                            .contains(&format!("Content-Length: {}\r\n", expected.len()))
                    );
                    assert_eq!(&raw[boundary..], expected);
                }
                for secret in SECRETS {
                    assert!(
                        !raw.windows(secret.len())
                            .any(|bytes| bytes == secret.as_bytes())
                    );
                }
                let current = server.source.lock().unwrap();
                assert_eq!(current.info.url, original_url);
                assert_eq!(current.generation, 0);
            },
        );
        assert_eq!(
            calls.len(),
            usize::from(matches!(mode, "refresh" | "success"))
        );
    }
}
