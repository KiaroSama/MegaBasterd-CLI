//! DLC initial trust is narrower than generic public HTTPS link services.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::protocol::{api::Api, test_peer};

#[test]
fn only_the_normalized_builtin_dlc_host_and_default_https_port_are_approved() {
    assert_eq!(
        containers::DLC_SERVICE_URL,
        "https://service.jdownloader.org/dlcrypt/service.php"
    );
    for endpoint in [
        containers::DLC_SERVICE_URL,
        "https://Service.JDownloader.ORG/dlcrypt/service.php",
        "https://service.jdownloader.org./mirror",
        "https://service.jdownloader.org:443/mirror",
    ] {
        validate_dlc_endpoint(&Url::parse(endpoint).unwrap()).unwrap();
    }
    for endpoint in [
        "https://evil.example/dlcrypt",
        "https://ѕervice.jdownloader.org/dlcrypt",
        "https://evil.example./dlcrypt",
        "https://service.jdownloader.org:8443/dlcrypt",
        "https://service.jdownloader.org.evil.example/dlcrypt",
    ] {
        assert!(
            matches!(validate_dlc_endpoint(&Url::parse(endpoint).unwrap()),
            Err(Error::Invalid(message)) if message.contains("unapproved service endpoint"))
        );
    }
}

#[test]
fn default_and_normalized_approved_dlc_endpoints_reach_one_external_post_with_the_exact_form() {
    use crate::{
        protocol::{http_response::HttpResponse, transport::Reply},
        storage::proxies::Routing,
        transfers::control::Control,
    };
    use std::{io::Cursor, time::Duration};

    let transport = Transport::new(
        Routing {
            explicit: None,
            pool: None,
            force: false,
        },
        Duration::from_secs(5),
        "native-test".into(),
        Control::new(),
    )
    .unwrap();
    let accounts = BTreeMap::new();
    let resolver = Resolver {
        transport: &transport,
        password: None,
        elc_user: None,
        elc_api_key: None,
        elc_accounts: &accounts,
    };
    for endpoint in [
        None,
        Some(containers::DLC_SERVICE_URL),
        Some("https://Service.JDownloader.ORG/dlcrypt/service.php"),
    ] {
        let mut calls = 0;
        let error = resolver
            .dlc_with(
                &"B".repeat(100),
                endpoint.map(|value| Url::parse(value).unwrap()),
                |url, headers, body| {
                    calls += 1;
                    assert_eq!(
                        url.as_str(),
                        "https://service.jdownloader.org/dlcrypt/service.php"
                    );
                    assert_eq!(headers.len(), 2);
                    assert_eq!(headers[CONTENT_TYPE], "application/x-www-form-urlencoded");
                    assert_eq!(headers["rev"], "34065");
                    assert_eq!(
                        body,
                        format!(
                            "destType=jdtc6&b=JD&srcType=dlc&data={}&v=34065",
                            "B".repeat(88)
                        )
                        .as_bytes()
                    );
                    Ok(Reply::test_response(HttpResponse::streamed(
                        reqwest::StatusCode::OK,
                        HeaderMap::new(),
                        Cursor::new(b"<rc>x</rc>"),
                    )))
                },
            )
            .unwrap_err();
        assert!(
            matches!(error, Error::Invalid(message) if message == "Malformed container base64")
        );
        assert_eq!(calls, 1);
    }
}

#[test]
fn rejected_dlc_initial_endpoints_never_reach_the_transport_or_peer() {
    let ((), calls) = test_peer::with_peer(
        |_| panic!("an unapproved DLC endpoint reached a network peer"),
        |address| {
            let api = Api::test_peer(address).unwrap();
            let accounts = BTreeMap::new();
            let resolver = Resolver {
                transport: &api.transport,
                password: None,
                elc_user: None,
                elc_api_key: None,
                elc_accounts: &accounts,
            };
            for (endpoint, reason) in [
                (
                    "http://service.jdownloader.org/dlcrypt",
                    "HTTPS without embedded credentials",
                ),
                (
                    "http://insecure.example/dlcrypt",
                    "HTTPS without embedded credentials",
                ),
                (
                    "https://user:secret@service.jdownloader.org/dlcrypt",
                    "HTTPS without embedded credentials",
                ),
                ("https://localhost/dlcrypt", "endpoint is local"),
                ("https://127.0.0.1/dlcrypt", "nonpublic address"),
                ("https://[::1]/dlcrypt", "nonpublic address"),
                ("https://169.254.169.254/dlcrypt", "nonpublic address"),
                (
                    "https://evil.example/dlcrypt",
                    "unapproved service endpoint",
                ),
                (
                    "https://ѕervice.jdownloader.org/dlcrypt",
                    "unapproved service endpoint",
                ),
                (
                    "https://evil.example./dlcrypt",
                    "unapproved service endpoint",
                ),
                (
                    "https://service.jdownloader.org:8443/dlcrypt",
                    "unapproved service endpoint",
                ),
            ] {
                let error = resolver
                    .dlc_at(&"B".repeat(100), Url::parse(endpoint).unwrap())
                    .unwrap_err();
                assert!(matches!(&error, Error::Invalid(message) if message.contains(reason)));
                assert!(!error.to_string().contains("secret"));
            }
        },
    );
    assert!(calls.is_empty());
}
