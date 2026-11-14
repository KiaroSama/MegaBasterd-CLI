//! Actual DLC request/redirect loop at the existing isolated synthetic TLS origin.
#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn dlc_redirects_keep_post_body_and_revision_through_relative_and_absolute_hops() {
    for (status, absolute) in [(302, false), (307, false), (302, true)] {
        let mut hop = 0;
        let ((), calls) = test_peer::with_peer(
            |request| {
                assert_eq!(request.method, "POST");
                let response = if hop == 0 {
                    assert_request(request, 2);
                    Response {
                        status,
                        headers: vec![(
                            "Location".into(),
                            if absolute {
                                format!("https://{}/mirror", request.headers["host"])
                            } else {
                                "/elsewhere/service.php".into()
                            },
                        )],
                        body: vec![],
                    }
                } else {
                    assert_eq!(hop, 1);
                    assert_eq!(
                        request.path,
                        if absolute {
                            "/mirror"
                        } else {
                            "/elsewhere/service.php"
                        }
                    );
                    Response {
                        status: 200,
                        headers: vec![],
                        body: b"<html>no key here</html>".to_vec(),
                    }
                };
                hop += 1;
                Some(response)
            },
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
                assert!(matches!(call(&resolver, address, 2),
                    Err(Error::Protocol(message)) if message == "DLC service did not return a key"));
            },
        );
        assert_eq!(hop, 2);
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].body, calls[1].body);
        for header in ["host", "content-type", "rev"] {
            assert_eq!(calls[0].headers[header], calls[1].headers[header]);
        }
        assert!(calls.iter().all(|request| request.connect_target.is_none()));
    }
}

#[test]
fn dlc_rejected_redirects_stop_after_one_real_request_and_preserve_useful_categories() {
    let cases = [
        (Some("https://evil.example/dlcrypt"), "cross-origin"),
        (Some("//evil.example/x"), "cross-origin"),
        (
            Some("https://service.jdownloader.org:8443/x"),
            "cross-origin",
        ),
        (
            Some("https://user:pass@service.jdownloader.org/x"),
            "HTTPS without embedded credentials",
        ),
        (Some("https://localhost/x"), "endpoint is local"),
        (Some("https://127.0.0.1/x"), "nonpublic address"),
        (Some("https://[::1]/x"), "nonpublic address"),
        (Some("https://10.0.0.1/x"), "nonpublic address"),
        (Some("https://192.168.1.5/x"), "nonpublic address"),
        (Some("https://169.254.0.1/x"), "nonpublic address"),
        (Some("https://[fd00::1]/x"), "nonpublic address"),
        (Some("https://[fe80::1]/x"), "nonpublic address"),
        (
            Some("http://evil.example/dlcrypt"),
            "HTTPS without embedded credentials",
        ),
        (
            Some("data:text/plain,x"),
            "HTTPS without embedded credentials",
        ),
        (
            Some("ftp://evil.example/x"),
            "HTTPS without embedded credentials",
        ),
        (None, "Redirect has no valid Location"),
    ];
    let requests = std::sync::atomic::AtomicUsize::new(0);
    let ((), calls) = test_peer::with_peer(
        |request| {
            assert_request(request, 2);
            let index = requests.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let location = cases[index].0;
            Some(Response {
                status: 302,
                headers: location
                    .map(|value| vec![("Location".into(), value.into())])
                    .unwrap_or_default(),
                body: vec![],
            })
        },
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
            for (index, (_, category)) in cases.iter().enumerate() {
                assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), index);
                let error = call(&resolver, address, 2).unwrap_err();
                assert!(matches!(&error, Error::Invalid(_) | Error::Protocol(_)));
                assert!(error.to_string().contains(*category));
                assert!(!error.to_string().contains("user:pass"));
                assert_eq!(
                    requests.load(std::sync::atomic::Ordering::SeqCst),
                    index + 1
                );
            }
        },
    );
    assert_eq!(
        requests.load(std::sync::atomic::Ordering::SeqCst),
        cases.len()
    );
    assert_eq!(
        calls.len(),
        cases.len(),
        "a rejected redirect received another request"
    );
    assert!(
        calls
            .iter()
            .all(|request| request.path == "/dlcrypt/service.php")
    );
}

#[test]
fn dlc_loop_stops_after_exactly_five_redirects_and_missing_key_fails_after_one_response() {
    for looping in [false, true] {
        let ((), calls) = test_peer::with_peer(
            |request| {
                assert_request(request, 2);
                Some(Response {
                    status: if looping { 302 } else { 200 },
                    headers: if looping {
                        vec![("Location".into(), "/dlcrypt/service.php".into())]
                    } else {
                        vec![]
                    },
                    body: if looping {
                        vec![]
                    } else {
                        b"<html>no key here</html>".to_vec()
                    },
                })
            },
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
                let expected = if looping {
                    "Remote endpoint exceeded five redirects"
                } else {
                    "DLC service did not return a key"
                };
                assert!(matches!(call(&resolver, address, 2),
                    Err(Error::Protocol(message)) if message == expected));
            },
        );
        assert_eq!(calls.len(), if looping { 6 } else { 1 });
        assert!(calls.windows(2).all(|pair| pair[0].body == pair[1].body));
    }
}
