//! Actual service requests consume independently source-produced encrypted response vectors.
#![allow(clippy::unwrap_used)]

use super::*;

fn vectors() -> Value {
    serde_json::from_str(include_str!("../../tests/fixtures/link-vectors.json")).unwrap()
}

#[test]
fn elc_service_decrypts_source_ciphertext_with_configured_credentials_and_explicit_precedence() {
    let data = vectors();
    let vector = &data["elc"][0];
    for explicit in [false, true] {
        let ((), calls) = test_peer::with_connect_peer(
            |request| {
                assert_request(request, 0);
                Some(Response {
                    status: 200,
                    headers: vec![],
                    body: serde_json::to_vec(&json!({"d":vector["decrypt_key"]})).unwrap(),
                })
            },
            |address| {
                let mut api = Api::test_peer(address).unwrap();
                let _route = route(&mut api, address, 0);
                let accounts = BTreeMap::from([(
                    "testserver.com".into(),
                    BTreeMap::from([
                        (
                            "user".into(),
                            if explicit {
                                "unused-user"
                            } else {
                                "synthetic-user"
                            }
                            .into(),
                        ),
                        (
                            "api_key".into(),
                            if explicit {
                                "unused-key"
                            } else {
                                "synthetic-key"
                            }
                            .into(),
                        ),
                    ]),
                )]);
                let resolver = Resolver {
                    transport: &api.transport,
                    password: None,
                    elc_user: explicit.then_some("synthetic-user"),
                    elc_api_key: explicit.then_some("synthetic-key"),
                    elc_accounts: &accounts,
                };
                assert_eq!(
                    serde_json::to_value(resolver.elc(&elc(address)).unwrap()).unwrap(),
                    vector["links"]
                );
            },
        );
        assert_eq!(calls.len(), 1);
        assert!(calls[0].connect_target.is_some());
    }
    let ((), calls) = test_peer::with_peer(
        |_| panic!("ELC without credentials contacted a service"),
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
            assert!(
                matches!(resolver.elc(&elc(address)), Err(Error::Auth(message)) if message.contains("configured user"))
            );
        },
    );
    assert!(calls.is_empty());
}

#[test]
fn dlc_service_unwraps_source_key_reply_and_returns_the_source_urls() {
    let data = vectors();
    let vector = &data["dlc"];
    let input = vector["data"].as_str().unwrap();
    let ((), calls) = test_peer::with_connect_peer(
        |request| {
            assert_eq!(request.method, "POST");
            assert_eq!(request.path, "/dlcrypt/service.php");
            assert_eq!(request.headers["rev"], "34065");
            assert!(!request.headers.contains_key("proxy-authorization"));
            let form: BTreeMap<_, _> = url::form_urlencoded::parse(&request.body)
                .into_owned()
                .collect();
            assert_eq!(
                form,
                BTreeMap::from([
                    ("destType".into(), "jdtc6".into()),
                    ("b".into(), "JD".into()),
                    ("srcType".into(), "dlc".into()),
                    ("data".into(), "A".repeat(88)),
                    ("v".into(), "34065".into()),
                ])
            );
            Some(Response {
                status: 200,
                headers: vec![],
                body: vector["key_response"].as_str().unwrap().as_bytes().to_vec(),
            })
        },
        |address| {
            let mut api = Api::test_peer(address).unwrap();
            let _route = route(&mut api, address, 0);
            let accounts = BTreeMap::new();
            let resolver = Resolver {
                transport: &api.transport,
                password: None,
                elc_user: None,
                elc_api_key: None,
                elc_accounts: &accounts,
            };
            let endpoint = Url::parse(&format!(
                "https://testserver.com:{}/dlcrypt/service.php",
                address.port()
            ))
            .unwrap();
            assert_eq!(
                serde_json::to_value(resolver.dlc_request(input, endpoint).unwrap()).unwrap(),
                vector["links"]
            );
        },
    );
    assert_eq!(calls.len(), 1);
    assert!(calls[0].connect_target.is_some());
}

#[test]
fn explicit_nonforced_megacrypter_resolution_succeeds_with_one_direct_service_request() {
    let public = "https://mega.nz/file/ABCDEFGH#key";
    let ((), calls) = test_peer::with_peer(
        |request| {
            assert_request(request, 1);
            assert!(request.connect_target.is_none());
            Some(Response {
                status: 200,
                headers: vec![],
                body: serde_json::to_vec(&json!({"link":public})).unwrap(),
            })
        },
        |address| {
            let api = Api::test_peer(address).unwrap();
            assert!(!api.transport.routing.force);
            assert!(
                api.transport.routing.explicit.is_none() && api.transport.routing.pool.is_none()
            );
            let accounts = BTreeMap::new();
            let resolver = Resolver {
                transport: &api.transport,
                password: None,
                elc_user: None,
                elc_api_key: None,
                elc_accounts: &accounts,
            };
            let resolved = resolver
                .resolve(&format!("mc://testserver.com:{}/token", address.port()))
                .unwrap();
            assert_eq!(resolved.len(), 1);
            assert_eq!(resolved[0].kind, LinkType::File);
            assert_eq!(resolved[0].public_id, "ABCDEFGH");
            assert_eq!(resolved[0].key.as_deref(), Some("key"));
        },
    );
    assert_eq!(calls.len(), 1);
    assert!(calls[0].connect_target.is_none());
}

#[test]
fn encrypted_megacrypter_service_metadata_and_download_match_source_without_exporting_local_keys() {
    let data = vectors();
    let vector = &data["megacrypter"];
    let mut methods = Vec::new();
    let ((), calls) = test_peer::with_connect_peer(
        |request| {
            assert_eq!(request.method, "POST");
            assert_eq!(request.path, "/api");
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            let method = body["m"].as_str().unwrap();
            assert_eq!(method, if methods.is_empty() { "info" } else { "dl" });
            let mut expected =
                json!({"m":method,"link":format!("mc://{}/token",request.headers["host"])});
            if method == "dl" {
                expected["noexpire"] = json!("synthetic-token");
                expected["sid"] = json!("synthetic-service-session");
            }
            assert_eq!(body, expected);
            let raw = std::str::from_utf8(&request.body).unwrap();
            for forbidden in [
                vector["password"].as_str().unwrap(),
                vector["pass_hash"].as_str().unwrap(),
                vector["decrypted"]["key"].as_str().unwrap(),
            ] {
                assert!(!raw.contains(forbidden));
            }
            assert!(!request.headers.contains_key("proxy-authorization"));
            methods.push(method.to_owned());
            Some(Response {
                status: 200,
                headers: vec![],
                body: serde_json::to_vec(
                    &vector[if method == "info" {
                        "body"
                    } else {
                        "download_response"
                    }],
                )
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
            let link = links::parse_link(&format!("mc://testserver.com:{}/token", address.port()))
                .unwrap();
            let info = resolver.megacrypter_info(&link).unwrap();
            assert_eq!(info.raw, vector["decrypted"]);
            assert_eq!(info.name.as_deref(), Some("folder/نام.mkv"));
            assert_eq!(info.size, Some(1234));
            assert_eq!(info.key.as_deref(), vector["decrypted"]["key"].as_str());
            assert_eq!(info.noexpire_token.as_deref(), Some("synthetic-token"));
            assert_eq!(info.pass_hash.as_deref(), vector["pass_hash"].as_str());
            assert_eq!(
                resolver
                    .megacrypter_download(&link, &info, Some("synthetic-service-session"))
                    .unwrap(),
                vector["download_url"].as_str().unwrap()
            );
        },
    );
    assert_eq!(methods, ["info", "dl"]);
    assert_eq!(calls.len(), 2);
    assert!(calls.iter().all(|request| request.connect_target.is_some()));
}
