#![allow(clippy::unwrap_used)]

use megabasterd_cli::services::http::{Request, bearer_matches, proxy_password_matches};

#[test]
fn malformed_or_ambiguous_headers_are_not_accepted() {
    for request in [
        b"GET / HTTP/1.1\r\nRange: bytes=0-1\r\nRange: bytes=2-3\r\n\r\n".as_slice(),
        b"GET / HTTP/1.1\r\n folded\r\n\r\n",
        b"GET / HTTP/1.1\r\nBad\r\n\r\n",
        b"GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
    ] {
        assert!(Request::parse(request).is_err());
    }
    let request = Request::parse(b"GET /file?token=synthetic-token HTTP/1.1\r\nAuthorization: Bearer synthetic-token\r\n\r\n").unwrap();
    assert!(bearer_matches(&request, Some("synthetic-token"), false));
    assert!(!bearer_matches(&request, Some("other"), true));
    let query = Request::parse(b"GET /file?token=synthetic-token HTTP/1.1\r\n\r\n").unwrap();
    assert!(!bearer_matches(&query, Some("synthetic-token"), false));
    assert!(bearer_matches(&query, Some("synthetic-token"), true));
}

#[test]
fn exact_source_loopback_classification_preserves_ipv4_ipv6_and_hostname_boundaries() {
    use megabasterd_cli::services::streaming::loopback_host;
    for (host, expected) in [
        ("127.0.0.1", true),
        ("127.0.0.5", true),
        ("::1", true),
        ("[::1]", true),
        ("localhost", true),
        ("0.0.0.0", false),
        ("::", false),
        ("192.168.1.10", false),
        ("example.com", false),
        ("", false),
    ] {
        assert_eq!(loopback_host(host), expected, "host={host:?}");
    }
}

#[test]
fn proxy_password_requires_basic_auth_and_never_uses_the_query_token() {
    let request = Request::parse(
        b"CONNECT mega.nz:443 HTTP/1.1\r\nProxy-Authorization: Basic dXNlcjpmaXh0dXJl\r\n\r\n",
    )
    .unwrap();
    assert!(proxy_password_matches(&request, "fixture"));
    assert!(!proxy_password_matches(&request, "different"));
    let request = Request::parse(
        b"CONNECT mega.nz:443 HTTP/1.1\r\nAuthorization: Basic dXNlcjpmaXh0dXJl\r\n\r\n",
    )
    .unwrap();
    assert!(!proxy_password_matches(&request, "fixture"));
}
