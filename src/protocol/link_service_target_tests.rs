//! Untrusted initial service targets are checked before credential-bearing external I/O.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::{
    crypto::wire,
    protocol::{api::Api, test_peer},
    storage::proxies::Routing,
    transfers::control::Control,
};
use std::time::Duration;

const UNSAFE: [&str; 13] = [
    "http://service.example/api",
    "https://127.0.0.1/api",
    "https://127.9.9.9/api",
    "https://[::1]/api",
    "https://169.254.169.254/latest/meta-data",
    "https://[fe80::1]/api",
    "https://10.0.0.5/api",
    "https://192.168.1.5/api",
    "https://172.16.0.5/api",
    "https://[fd00::1]/api",
    "https://0.0.0.0/api",
    "https://user:pass@service.example/api",
    "https:///api",
];

fn envelope(service: &str) -> ParsedLink {
    let mut bytes = vec![0xb9];
    bytes.extend(16u32.to_le_bytes());
    bytes.extend([b'x'; 16]);
    bytes.extend((service.len() as u16).to_le_bytes());
    bytes.extend(service.as_bytes());
    bytes.extend(3u16.to_le_bytes());
    bytes.extend(b"tok");
    links::parse_link(&format!("mega://elc?{}", wire::b64_url_encode(&bytes))).unwrap()
}

#[test]
fn elc_initial_targets_refuse_every_source_unsafe_form_before_the_external_post() {
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
    let accounts = BTreeMap::from([(
        "127.0.0.1".into(),
        BTreeMap::from([
            ("user".into(), "elc-sentinel-user".into()),
            ("api_key".into(), "elc-sentinel-apikey".into()),
        ]),
    )]);
    for explicit in [false, true] {
        let resolver = Resolver {
            transport: &transport,
            password: None,
            elc_user: explicit.then_some("elc-sentinel-user"),
            elc_api_key: explicit.then_some("elc-sentinel-apikey"),
            elc_accounts: &accounts,
        };
        for endpoint in UNSAFE {
            let mut posts = 0;
            let error = resolver
                .elc_with(&envelope(endpoint), |_, _, _| {
                    posts += 1;
                    panic!("Unsafe ELC endpoint reached the external POST");
                })
                .unwrap_err();
            assert!(matches!(&error, Error::Invalid(_)), "{endpoint}: {error}");
            assert_eq!(posts, 0);
            for secret in ["elc-sentinel-user", "elc-sentinel-apikey", "user:pass"] {
                assert!(!error.to_string().contains(secret));
            }
        }
    }
}

#[test]
fn an_ordinary_public_elc_endpoint_reaches_one_post_with_the_exact_source_credentials() {
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
        elc_user: Some("elc-sentinel-user"),
        elc_api_key: Some("elc-sentinel-apikey"),
        elc_accounts: &accounts,
    };
    let mut posts = 0;
    let error = resolver
        .elc_with(
            &envelope("https://elc.example.com/api"),
            |url, body, content_type| {
                posts += 1;
                assert_eq!(url.as_str(), "https://elc.example.com/api");
                assert_eq!(content_type, "application/x-www-form-urlencoded");
                assert_eq!(
                    body,
                    b"OPERATION_TYPE=D&DATA=tok&USER=elc-sentinel-user&APIKEY=elc-sentinel-apikey"
                );
                Ok(ServiceResponse::Body(json!({})))
            },
        )
        .unwrap_err();
    assert!(matches!(error, Error::Protocol(message) if message == "MEGA response is missing d"));
    assert_eq!(posts, 1);
}

#[test]
fn dangerous_megacrypter_servers_refuse_info_and_recursive_resolution_without_a_request() {
    let ((), calls) = test_peer::with_peer(
        |_| panic!("A dangerous MegaCrypter server received a request"),
        |address| {
            let api = Api::test_peer(address).unwrap();
            let accounts = BTreeMap::new();
            let resolver = Resolver {
                transport: &api.transport,
                password: Some("link-password-sentinel"),
                elc_user: None,
                elc_api_key: None,
                elc_accounts: &accounts,
            };
            for server in [
                "127.0.0.1",
                "169.254.169.254",
                "10.0.0.5",
                "[::1]",
                "192.168.0.9",
            ] {
                let input = format!("mc://{server}/sometoken");
                let parsed = links::parse_link(&input).unwrap();
                for error in [
                    resolver.megacrypter_info(&parsed).err().unwrap(),
                    resolver.resolve(&input).err().unwrap(),
                ] {
                    assert!(
                        matches!(&error, Error::Invalid(message) if message.contains("nonpublic address"))
                    );
                    assert!(!error.to_string().contains("link-password-sentinel"));
                }
            }
        },
    );
    assert!(calls.is_empty());
}
