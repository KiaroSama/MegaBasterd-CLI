//! Underlying-link resolution uses bounded service methods without exporting local secrets.
#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn underlying_links_accept_each_source_inline_and_file_key_alias_without_an_extra_request() {
    let public = "https://mega.nz/file/ABC#KEY";
    let mut bodies: Vec<Value> = ["url", "link", "mega_url", "megaurl", "mega_link"]
        .into_iter()
        .map(|field| json!({(field):public}))
        .collect();
    for id in ["file_id", "id"] {
        for key in ["file_key", "key"] {
            bodies.push(json!({(id):"ABC",(key):"KEY"}));
        }
    }
    bodies.push(json!({"mega_url":public,"pass":"download-iv-not-a-metadata-descriptor"}));
    for body in bodies {
        let ((), calls) = test_peer::with_connect_peer(
            |request| {
                assert_request(request, 1);
                Some(Response {
                    status: 200,
                    headers: vec![],
                    body: serde_json::to_vec(&body).unwrap(),
                })
            },
            |address| {
                let mut api = Api::test_peer(address).unwrap();
                let _route = route(&mut api, address, 0);
                let accounts = BTreeMap::new();
                let resolver = Resolver {
                    transport: &api.transport,
                    password: Some("local-password-sentinel"),
                    elc_user: None,
                    elc_api_key: None,
                    elc_accounts: &accounts,
                };
                let links = resolver
                    .resolve(&format!("mc://testserver.com:{}/token", address.port()))
                    .unwrap();
                assert_eq!(links.len(), 1);
                assert_eq!(links[0].kind, LinkType::File);
                assert_eq!(links[0].public_id, "ABC");
                assert_eq!(links[0].key.as_deref(), Some("KEY"));
            },
        );
        assert_eq!(calls.len(), 1);
        assert!(calls[0].connect_target.is_some());
    }
}

#[test]
fn underlying_resolution_advances_only_through_three_service_methods_and_keeps_failures_private() {
    for available_at in [1, 2, 3] {
        let mut attempts = 0;
        let ((), calls) = test_peer::with_connect_peer(
            |request| {
                assert_eq!(request.method, "POST");
                assert_eq!(request.path, "/api");
                assert!(request.connect_target.is_some());
                assert!(!request.headers.contains_key("proxy-authorization"));
                let method = ["info", "openlink", "dl"][attempts];
                assert_eq!(
                    serde_json::from_slice::<Value>(&request.body).unwrap(),
                    json!({"m":method,"link":format!("mc://{}/token",request.headers["host"])})
                );
                let body = if attempts == available_at {
                    json!({"mega_url":"https://mega.nz/file/ABC#KEY", "pass":"download-iv-not-a-metadata-descriptor"})
                } else if attempts == 0 {
                    json!({"error":-1,"private":"service-body-sentinel"})
                } else {
                    json!({"url":"https://cdn.example/not-a-public-mega-link","private":"service-body-sentinel"})
                };
                attempts += 1;
                Some(Response {
                    status: 200,
                    headers: vec![],
                    body: serde_json::to_vec(&body).unwrap(),
                })
            },
            |address| {
                let mut api = Api::test_peer(address).unwrap();
                let _route = route(&mut api, address, 0);
                let accounts = BTreeMap::new();
                let resolver = Resolver {
                    transport: &api.transport,
                    password: Some("local-password-sentinel"),
                    elc_user: None,
                    elc_api_key: None,
                    elc_accounts: &accounts,
                };
                let link =
                    links::parse_link(&format!("mc://testserver.com:{}/token", address.port()))
                        .unwrap();
                let result = resolver.megacrypter_resolve(&link);
                if available_at < 3 {
                    assert_eq!(result.unwrap(), "https://mega.nz/file/ABC#KEY");
                } else {
                    let error = result.unwrap_err();
                    assert!(
                        matches!(&error,Error::Protocol(message) if message == "MegaCrypter service did not expose an underlying MEGA link")
                    );
                    assert!(!error.to_string().contains("service-body-sentinel"));
                    assert!(!error.to_string().contains("local-password-sentinel"));
                }
            },
        );
        assert_eq!(attempts, (available_at + 1).min(3));
        assert_eq!(calls.len(), attempts);
    }
}

#[test]
fn encrypted_underlying_metadata_is_decrypted_locally_before_constructing_the_public_link() {
    let data: Value =
        serde_json::from_str(include_str!("../../tests/fixtures/link-vectors.json")).unwrap();
    let vector = &data["megacrypter"];
    let mut body = vector["body"].clone();
    body["file_id"] = json!("ABC");
    let ((), calls) = test_peer::with_connect_peer(
        |request| {
            assert_request(request, 1);
            Some(Response {
                status: 200,
                headers: vec![],
                body: serde_json::to_vec(&body).unwrap(),
            })
        },
        |address| {
            let mut api = Api::test_peer(address).unwrap();
            let _route = route(&mut api, address, 0);
            let accounts = BTreeMap::new();
            let resolver = Resolver {
                transport: &api.transport,
                password: vector["password"].as_str(),
                elc_user: None,
                elc_api_key: None,
                elc_accounts: &accounts,
            };
            let link = links::parse_link(&format!("mc://testserver.com:{}/token", address.port()))
                .unwrap();
            assert_eq!(
                resolver.megacrypter_resolve(&link).unwrap(),
                format!(
                    "https://mega.nz/file/ABC#{}",
                    vector["decrypted"]["key"].as_str().unwrap()
                )
            );
        },
    );
    assert_eq!(calls.len(), 1);
}

#[test]
fn direct_encrypted_download_retains_metadata_and_reuses_the_validated_dl_answer() {
    let data: Value =
        serde_json::from_str(include_str!("../../tests/fixtures/link-vectors.json")).unwrap();
    let vector = &data["megacrypter"];
    for unsupported_status in [200, 404, 405, 501] {
        let mut methods = Vec::new();
        let ((), calls) = test_peer::with_connect_peer(
            |request| {
                let method = ["info", "openlink", "dl"][methods.len()];
                assert_eq!(request.method, "POST");
                assert_eq!(request.path, "/api");
                assert!(request.connect_target.is_some());
                let mut expected =
                    json!({"m":method,"link":format!("mc://{}/token",request.headers["host"])});
                if method == "dl" {
                    expected["noexpire"] = json!("synthetic-token");
                }
                assert_eq!(
                    serde_json::from_slice::<Value>(&request.body).unwrap(),
                    expected
                );
                methods.push(method);
                Some(Response {
                    status: if method == "openlink" {
                        unsupported_status
                    } else {
                        200
                    },
                    headers: vec![],
                    body: serde_json::to_vec(&match method {
                        "info" => vector["body"].clone(),
                        "openlink" => json!({"error":-1}),
                        "dl" => vector["download_response"].clone(),
                        _ => unreachable!(),
                    })
                    .unwrap(),
                })
            },
            |address| {
                let mut api = Api::test_peer(address).unwrap();
                let _route = route(&mut api, address, 0);
                let accounts = BTreeMap::new();
                let resolver = Resolver {
                    transport: &api.transport,
                    password: vector["password"].as_str(),
                    elc_user: None,
                    elc_api_key: None,
                    elc_accounts: &accounts,
                };
                let link =
                    links::parse_link(&format!("mc://testserver.com:{}/token", address.port()))
                        .unwrap();
                match resolver.megacrypter_source(&link).unwrap() {
                    MegaCrypterResolution::Metadata { info, download_url } => {
                        assert_eq!(info.raw, vector["decrypted"]);
                        assert_eq!(download_url.as_deref(), vector["download_url"].as_str());
                        let file = crate::protocol::metadata::FileInfo::megacrypter(
                            link,
                            *info,
                            download_url.unwrap(),
                        )
                        .unwrap();
                        assert_eq!(file.name, "folder/نام.mkv");
                        assert_eq!(file.size, 1234);
                        assert_eq!(file.raw_key.as_slice(), &(0..32).collect::<Vec<u8>>());
                    }
                    MegaCrypterResolution::Link(_) => {
                        panic!("temporary CDN answer became an underlying link")
                    }
                }
            },
        );
        assert_eq!(methods, ["info", "openlink", "dl"]);
        assert_eq!(calls.len(), 3);
    }
}

#[test]
fn transport_policy_cancellation_and_bad_password_never_advance_to_another_service_method() {
    for case in 0..5 {
        let data: Value =
            serde_json::from_str(include_str!("../../tests/fixtures/link-vectors.json")).unwrap();
        let ((), calls) = test_peer::with_connect_peer(
            |request| {
                assert_request(request, 1);
                assert!(case >= 2, "refused resolution contacted a service");
                Some(match case {
                    2 => Response {
                        status: 503,
                        headers: vec![],
                        body: vec![],
                    },
                    3 => Response {
                        status: 307,
                        headers: vec![("Location".into(), "https://127.0.0.1/api".into())],
                        body: vec![],
                    },
                    4 => Response {
                        status: 200,
                        headers: vec![],
                        body: serde_json::to_vec(&data["megacrypter"]["body"]).unwrap(),
                    },
                    _ => unreachable!(),
                })
            },
            |address| {
                let mut api = Api::test_peer(address).unwrap();
                let _route = route(&mut api, address, 0);
                if case == 0 {
                    api.control.cancel();
                }
                if case == 1 {
                    api.transport.routing.pool = Some(Pool::new(vec![], vec![], None).unwrap());
                }
                let accounts = BTreeMap::new();
                let resolver = Resolver {
                    transport: &api.transport,
                    password: Some("wrong"),
                    elc_user: None,
                    elc_api_key: None,
                    elc_accounts: &accounts,
                };
                let link =
                    links::parse_link(&format!("mc://testserver.com:{}/token", address.port()))
                        .unwrap();
                let error = resolver.megacrypter_resolve(&link).unwrap_err();
                match case {
                    0 => assert!(matches!(error, Error::Canceled)),
                    1 => assert!(
                        matches!(error,Error::Protocol(message) if message.contains("direct connection was refused"))
                    ),
                    2 => assert!(
                        matches!(error,Error::Protocol(message) if message.contains("unsuccessful HTTP status"))
                    ),
                    3 => assert!(matches!(error, Error::Invalid(_))),
                    4 => assert!(
                        matches!(error,Error::Integrity(message) if message == "Wrong MegaCrypter password")
                    ),
                    _ => unreachable!(),
                }
            },
        );
        assert_eq!(calls.len(), usize::from(case >= 2));
    }
}
