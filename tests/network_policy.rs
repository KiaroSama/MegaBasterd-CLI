#![allow(clippy::unwrap_used)]
use megabasterd_cli::protocol::{
    dns::is_public,
    transport::{Transport, safe_target},
};
use megabasterd_cli::{error::Error, storage::proxies::Routing, transfers::control::Control};
use reqwest::{Method, header::HeaderMap};
use std::net::IpAddr;
use std::time::Duration;
use url::Url;

#[test]
fn nonpublic_addresses_are_rejected_before_a_socket_is_opened() {
    for blocked in [
        "127.0.0.1",
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.1.1",
        "192.0.2.1",
        "198.18.1.1",
        "203.0.113.1",
        "224.0.0.1",
        "0.0.0.0",
        "::",
        "::1",
        "fe80::1",
        "fc00::1",
        "2001:db8::1",
        "::ffff:127.0.0.1",
        "2001:2::1",
        "2001:1::4",
        "2001:1ff::1",
        "2001:10::1",
        "2001::1",
        "2002::1",
        "3fff::1",
        "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff",
    ] {
        assert!(!is_public(blocked.parse::<IpAddr>().unwrap()), "{blocked}");
    }
    for valid in [
        "1.1.1.1",
        "8.8.8.8",
        "2606:4700:4700::1111",
        "2001:1::1",
        "2001:1::2",
        "2001:1::3",
        "2001:3::1",
        "2001:4:112::1",
        "2001:20::1",
        "2001:2f:ffff::1",
        "2001:30::1",
        "2001:40::1",
        "2001:200::1",
        "3ffe:ffff::1",
        "3fff:1000::1",
    ] {
        assert!(is_public(valid.parse::<IpAddr>().unwrap()));
    }
}

#[test]
fn literal_special_purpose_targets_fail_validation() {
    for target in [
        "https://[2001:2::1]/api",
        "https://[3fff::1]/api",
        "https://127.0.0.1/api",
    ] {
        assert!(safe_target(&Url::parse(target).unwrap()).is_err());
    }
}

#[test]
fn unsafe_targets_are_refused_before_contacting_even_a_configured_local_proxy() {
    for proxy in [
        "http://127.0.0.1:9",
        "https://127.0.0.1:9",
        "socks5h://127.0.0.1:9",
    ] {
        let transport = Transport::new(
            Routing {
                explicit: Some(proxy.into()),
                pool: None,
                force: true,
            },
            Duration::from_millis(100),
            "contract".into(),
            Control::new(),
        )
        .unwrap();
        for target in [
            "https://127.0.0.1/api",
            "https://[::1]/api",
            "https://192.168.1.1/api",
        ] {
            let url = Url::parse(target).unwrap();
            assert!(matches!(
                transport.send(Method::GET, url.clone(), HeaderMap::new(), None, false),
                Err(Error::Invalid(_))
            ));
            assert!(matches!(
                transport.post_link_service(
                    url,
                    HeaderMap::new(),
                    b"credential-sentinel".to_vec(),
                    false
                ),
                Err(Error::Invalid(_))
            ));
        }
    }
}
