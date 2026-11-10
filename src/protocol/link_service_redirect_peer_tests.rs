//! Service redirects validate every destination before resending credential-bearing POSTs.
#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn rejected_redirects_never_receive_elc_credentials_or_megacrypter_requests() {
    for kind in [0, 1] {
        for location in [
            "http://127.0.0.1:8931/",
            "https://127.0.0.1:8931/",
            if kind == 0 {
                "https://169.254.169.254/latest"
            } else {
                "https://10.0.0.5/api"
            },
        ] {
            let ((), calls) = test_peer::with_connect_peer(
                |request| {
                    assert_request(request, kind);
                    Some(Response {
                        status: 307,
                        headers: vec![("Location".into(), location.into())],
                        body: vec![],
                    })
                },
                |address| {
                    let mut api = Api::test_peer(address).unwrap();
                    let _route = route(&mut api, address, 0);
                    let accounts = BTreeMap::new();
                    let resolver = Resolver {
                        transport: &api.transport,
                        password: Some("link-password-sentinel"),
                        elc_user: Some("synthetic-user"),
                        elc_api_key: Some("synthetic-key"),
                        elc_accounts: &accounts,
                    };
                    assert!(matches!(
                        call(&resolver, address, kind),
                        Err(Error::Invalid(_))
                    ));
                },
            );
            assert_eq!(
                calls.len(),
                1,
                "rejected redirect received a second request"
            );
            assert!(calls[0].connect_target.is_some());
            let body = std::str::from_utf8(&calls[0].body).unwrap();
            assert!(!body.contains("link-password-sentinel"));
        }
    }
}

#[test]
fn all_service_redirect_statuses_preserve_post_body_and_resolve_relative_locations() {
    for status in [301, 302, 303, 307, 308] {
        let mut hop = 0;
        let ((), calls) = test_peer::with_connect_peer(
            |request| {
                assert_eq!(request.method, "POST");
                assert!(request.connect_target.is_some());
                assert!(!request.headers.contains_key("proxy-authorization"));
                let response = if hop == 0 {
                    assert_request(request, 0);
                    Response {
                        status,
                        headers: vec![("Location".into(), "/v2/api".into())],
                        body: vec![],
                    }
                } else {
                    assert_eq!(hop, 1);
                    assert_eq!(request.path, "/v2/api");
                    Response {
                        status: 200,
                        headers: vec![],
                        body: b"{\"d\":\"\"}".to_vec(),
                    }
                };
                hop += 1;
                Some(response)
            },
            |address| {
                let mut api = Api::test_peer(address).unwrap();
                let _route = route(&mut api, address, 0);
                let accounts = BTreeMap::new();
                let resolver = Resolver {
                    transport: &api.transport,
                    password: None,
                    elc_user: Some("synthetic-user"),
                    elc_api_key: Some("synthetic-key"),
                    elc_accounts: &accounts,
                };
                assert!(resolver.elc(&elc(address)).is_err());
            },
        );
        assert_eq!(hop, 2);
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].body, calls[1].body);
        assert_eq!(
            calls[0].headers["content-type"],
            calls[1].headers["content-type"]
        );
    }
}

#[test]
fn service_redirect_loops_stop_after_exactly_five_hops_without_credit_or_extra_contact() {
    let ((), calls) = test_peer::with_connect_peer(
        |request| {
            assert_request(request, 0);
            Some(Response {
                status: 302,
                headers: vec![("Location".into(), "/api".into())],
                body: vec![],
            })
        },
        |address| {
            let mut api = Api::test_peer(address).unwrap();
            let (pool, proxy) = route(&mut api, address, 2);
            let accounts = BTreeMap::new();
            let resolver = Resolver {
                transport: &api.transport,
                password: None,
                elc_user: Some("synthetic-user"),
                elc_api_key: Some("synthetic-key"),
                elc_accounts: &accounts,
            };
            assert!(
                matches!(resolver.elc(&elc(address)), Err(Error::Protocol(message)) if message == "Remote endpoint exceeded five redirects")
            );
            pool.report(&proxy, false).unwrap();
            assert!(
                pool.pick().unwrap().is_none(),
                "redirects earned success credit"
            );
        },
    );
    assert_eq!(calls.len(), 6);
    assert!(calls.iter().all(|request| request.connect_target.is_some()));
    assert!(calls.windows(2).all(|pair| pair[0].body == pair[1].body));
}
