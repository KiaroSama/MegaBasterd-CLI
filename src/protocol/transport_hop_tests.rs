//! The real redirect loop observes canonical DLC destinations without DNS or TLS exceptions.
#![allow(clippy::unwrap_used)]

use std::{
    io::Cursor,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use super::*;

struct UnreadBody(Arc<AtomicBool>);
impl Read for UnreadBody {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        panic!("redirect response body must be dropped, not consumed")
    }
}
impl Drop for UnreadBody {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

fn transport() -> Transport {
    Transport::new(
        Routing {
            explicit: None,
            pool: None,
            force: false,
        },
        Duration::from_secs(5),
        "native-test".into(),
        Control::new(),
    )
    .unwrap()
}

#[test]
fn approved_trailing_dot_redirect_is_followed_by_the_actual_hop_loop_and_drops_the_previous_body() {
    let transport = transport();
    let initial = Url::parse(super::super::super::containers::DLC_SERVICE_URL).unwrap();
    let dropped = Arc::new(AtomicBool::new(false));
    let mut seen = Vec::new();
    let mut reply = transport
        .send_hops(
            Method::POST,
            initial,
            Redirects::Service { same_origin: true },
            |method, url, proxy, pinned| {
                assert_eq!(method, &Method::POST);
                assert!(proxy.is_none());
                assert!(!pinned);
                seen.push(url.as_str().to_owned());
                let mut headers = reqwest::header::HeaderMap::new();
                if seen.len() == 1 {
                    headers.insert(
                        reqwest::header::LOCATION,
                        reqwest::header::HeaderValue::from_static(
                            "https://service.jdownloader.org./mirror",
                        ),
                    );
                    Ok(HttpResponse::streamed(
                        reqwest::StatusCode::FOUND,
                        headers,
                        UnreadBody(dropped.clone()),
                    ))
                } else {
                    assert_eq!(seen.len(), 2);
                    assert!(dropped.load(Ordering::SeqCst));
                    Ok(HttpResponse::streamed(
                        reqwest::StatusCode::OK,
                        headers,
                        Cursor::new(b"<rc>x</rc>"),
                    ))
                }
            },
        )
        .unwrap_or_else(|failure| panic!("approved redirect failed: {}", failure.error));
    assert_eq!(
        seen,
        [
            "https://service.jdownloader.org/dlcrypt/service.php",
            "https://service.jdownloader.org./mirror",
        ]
    );
    assert_eq!(reply.bytes(1024).unwrap(), b"<rc>x</rc>");
    assert!(dropped.load(Ordering::SeqCst));
}

#[test]
fn elc_public_cross_host_redirect_reaches_the_exact_mirror_through_the_same_hop_loop() {
    let transport = transport();
    let dropped = Arc::new(AtomicBool::new(false));
    let mut seen = Vec::new();
    let mut reply = transport
        .send_hops(
            Method::POST,
            Url::parse("https://elc.example.com/api").unwrap(),
            Redirects::Service { same_origin: false },
            |method, url, proxy, pinned| {
                assert_eq!(method, &Method::POST);
                assert!(proxy.is_none());
                assert!(!pinned);
                seen.push(url.as_str().to_owned());
                let mut headers = reqwest::header::HeaderMap::new();
                if seen.len() == 1 {
                    headers.insert(
                        reqwest::header::LOCATION,
                        reqwest::header::HeaderValue::from_static("https://mirror.example.com/api"),
                    );
                    Ok(HttpResponse::streamed(
                        reqwest::StatusCode::TEMPORARY_REDIRECT,
                        headers,
                        UnreadBody(dropped.clone()),
                    ))
                } else {
                    assert_eq!(seen.len(), 2);
                    assert!(dropped.load(Ordering::SeqCst));
                    Ok(HttpResponse::streamed(
                        reqwest::StatusCode::OK,
                        headers,
                        Cursor::new(b"{\"d\":\"\"}"),
                    ))
                }
            },
        )
        .unwrap_or_else(|failure| panic!("public redirect failed: {}", failure.error));
    assert_eq!(
        seen,
        [
            "https://elc.example.com/api",
            "https://mirror.example.com/api"
        ]
    );
    assert_eq!(reply.bytes(1024).unwrap(), b"{\"d\":\"\"}");
    assert!(dropped.load(Ordering::SeqCst));
}

#[test]
fn rejected_redirects_and_cancellation_stop_the_shared_loop_before_another_external_attempt() {
    let transport = transport();
    for location in [
        "https://evil.example./mirror",
        "https://service.jdownloader.org:8443/mirror",
        "http://service.jdownloader.org/mirror",
    ] {
        let dropped = Arc::new(AtomicBool::new(false));
        let mut calls = 0;
        let failure = transport
            .send_hops(
                Method::POST,
                Url::parse(super::super::super::containers::DLC_SERVICE_URL).unwrap(),
                Redirects::Service { same_origin: true },
                |_, _, _, _| {
                    calls += 1;
                    let mut headers = reqwest::header::HeaderMap::new();
                    headers.insert(
                        reqwest::header::LOCATION,
                        reqwest::header::HeaderValue::from_str(location).unwrap(),
                    );
                    Ok(HttpResponse::streamed(
                        reqwest::StatusCode::FOUND,
                        headers,
                        UnreadBody(dropped.clone()),
                    ))
                },
            )
            .err()
            .unwrap();
        assert!(matches!(
            failure.error,
            Error::Invalid(_) | Error::Protocol(_)
        ));
        assert!(failure.sent);
        assert_eq!(calls, 1);
        assert!(dropped.load(Ordering::SeqCst));
    }
    transport.control.cancel();
    let failure = transport
        .send_hops(
            Method::POST,
            Url::parse(super::super::super::containers::DLC_SERVICE_URL).unwrap(),
            Redirects::Service { same_origin: true },
            |_, _, _, _| panic!("canceled request reached the external adapter"),
        )
        .err()
        .unwrap();
    assert!(matches!(failure.error, Error::Canceled));
    assert!(!failure.sent);
}
