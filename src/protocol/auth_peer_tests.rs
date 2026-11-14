//! Actual login/MFA/probe and encrypted session reuse over the bounded TLS peer.
#![allow(clippy::unwrap_used)]

use serde_json::{Value, json};
use std::path::Path;

use super::{Session, login};
use crate::crypto::wire;
use crate::error::Error;
use crate::protocol::{
    api::Api,
    test_peer::{self, Request, Response},
};
use crate::storage::{sessions::Sessions, vault::Vault};

const EMAIL: &str = "fixture@example.invalid";
const USER: &str = "AQIDBAUGBwg";

fn fixture() -> Value {
    serde_json::from_str(include_str!("../../tests/fixtures/crypto-vectors.json")).unwrap()
}

fn command(request: &Request) -> Value {
    assert_eq!(request.method, "POST");
    let value: Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(value.as_array().unwrap().len(), 1);
    value[0].clone()
}

fn response(value: Value) -> Response {
    Response {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: serde_json::to_vec(&json!([value])).unwrap(),
    }
}

fn login_response(data: &Value) -> Value {
    let derived = hex::decode(data["kdf_v2"][2]["derived"].as_str().unwrap()).unwrap();
    login_response_with_key(data, &derived[..16])
}

fn login_response_with_key(data: &Value, login_key: &[u8]) -> Value {
    let rsa = &data["rsa"];
    let master = hex::decode(rsa["master_key"].as_str().unwrap()).unwrap();
    json!({"u":USER,"k":wire::b64_url_encode(&wire::aes_key_wrap_encrypt(&master,login_key).unwrap()),
        "privk":wire::b64_url_encode(&hex::decode(rsa["wrapped_private"].as_str().unwrap()).unwrap()),
        "csid":wire::b64_url_encode(&hex::decode(rsa["csid"].as_str().unwrap()).unwrap())})
}

fn session(data: &Value) -> Session {
    Session {
        sid: data["rsa"]["sid"].as_str().unwrap().into(),
        master_key: hex::decode(data["rsa"]["master_key"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
        rsa_private_key: None,
        user_handle: USER.into(),
        email: EMAIL.into(),
    }
}

#[test]
fn real_v2_mfa_login_uses_source_kdf_then_proves_sid_before_success() {
    let data = fixture();
    let mut logins = 0;
    let (_, calls) = test_peer::with_peer(
        |request| {
            let command = command(request);
            let url = url::Url::parse(&format!("https://testserver.com{}", request.path)).unwrap();
            match command["a"].as_str().unwrap() {
                "us0" => {
                    assert_eq!(command["user"], EMAIL);
                    assert!(!url.query_pairs().any(|(key, _)| key == "sid"));
                    Some(response(
                        json!({"v":2,"s":wire::b64_url_encode(&hex::decode(data["kdf_v2"][2]["salt"].as_str().unwrap()).unwrap())}),
                    ))
                }
                "us" => {
                    logins += 1;
                    let derived =
                        hex::decode(data["kdf_v2"][2]["derived"].as_str().unwrap()).unwrap();
                    assert_eq!(command["uh"], wire::b64_url_encode(&derived[16..]));
                    assert_eq!(command["user"], EMAIL);
                    assert!(!url.query_pairs().any(|(key, _)| key == "sid"));
                    if logins == 1 {
                        assert!(command.get("mfa").is_none());
                        Some(response(json!(-26)))
                    } else {
                        assert_eq!(command["mfa"], "123456");
                        Some(response(login_response(&data)))
                    }
                }
                "ug" => {
                    assert!(url.query_pairs().any(|(key, value)| key == "sid"
                        && value == data["rsa"]["sid"].as_str().unwrap()));
                    Some(response(json!({"u":USER})))
                }
                _ => panic!("unexpected authentication action"),
            }
        },
        |address| {
            let mut api = Api::test_peer(address).unwrap();
            let mut prompted = 0;
            let session = login(
                &mut api,
                "Fixture@Example.Invalid",
                "source-fixture",
                None,
                || {
                    prompted += 1;
                    Ok("123456".into())
                },
            )
            .unwrap();
            assert_eq!(prompted, 1);
            assert_eq!(session.sid, data["rsa"]["sid"].as_str().unwrap());
            assert_eq!(session.email, EMAIL);
            assert_eq!(session.user_handle, USER);
            assert!(session.rsa_private_key.is_some());
        },
    );
    let actions = calls
        .iter()
        .map(|r| command(r)["a"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(actions, ["us0", "us", "us", "ug"]);
}

#[test]
fn real_legacy_login_accepts_independent_rsa_material_but_refuses_chained_wrapping() {
    let data = fixture();
    let login_key = hex::decode(data["legacy"][1]["derived"].as_str().unwrap()).unwrap();
    for (prelogin, chained) in [
        (json!({"v":1,"s":""}), false),
        (json!({}), false),
        (json!({"v":1}), true),
    ] {
        let mut reply = login_response_with_key(&data, &login_key);
        if chained {
            reply["privk"] = json!(wire::b64_url_encode(
                &hex::decode(data["rsa"]["wrongly_chained_private"].as_str().unwrap()).unwrap()
            ));
        }
        let (_, calls) = test_peer::with_peer(
            |request| {
                let command = command(request);
                let url =
                    url::Url::parse(&format!("https://testserver.com{}", request.path)).unwrap();
                match command["a"].as_str().unwrap() {
                    "us0" => {
                        assert_eq!(command["user"], EMAIL);
                        assert!(!url.query_pairs().any(|(key, _)| key == "sid"));
                        Some(response(prelogin.clone()))
                    }
                    "us" => {
                        assert_eq!(command["user"], EMAIL);
                        assert!(!command["uh"].as_str().unwrap().is_empty());
                        assert!(!url.query_pairs().any(|(key, _)| key == "sid"));
                        Some(response(reply.clone()))
                    }
                    "ug" => {
                        let sid = url
                            .query_pairs()
                            .find(|(key, _)| key == "sid")
                            .map(|(_, value)| value.into_owned());
                        assert_eq!(
                            sid.as_deref(),
                            (!chained).then(|| data["rsa"]["sid"].as_str().unwrap())
                        );
                        Some(response(json!({"u":USER})))
                    }
                    _ => panic!("unexpected legacy login action"),
                }
            },
            |address| {
                let mut api = Api::test_peer(address).unwrap();
                let result = login(
                    &mut api,
                    "Fixture@Example.Invalid",
                    "source-fixture",
                    None,
                    || panic!("unexpected MFA prompt"),
                );
                if chained {
                    assert!(
                        matches!(result, Err(Error::Protocol(message)) if message.contains("MPI") || message.contains("RSA"))
                    );
                    api.request(json!({"a":"ug"}), &[]).unwrap();
                } else {
                    let session = result.unwrap();
                    assert_eq!(
                        session.master_key.as_slice(),
                        hex::decode(data["rsa"]["master_key"].as_str().unwrap()).unwrap()
                    );
                    assert_eq!(session.sid, data["rsa"]["sid"].as_str().unwrap());
                    assert_eq!(session.email, EMAIL);
                    assert_eq!(session.user_handle, USER);
                    assert_eq!(
                        session.rsa_private_key.as_deref().unwrap(),
                        hex::decode(data["rsa"]["private_blob"].as_str().unwrap()).unwrap()
                    );
                }
            },
        );
        assert_eq!(
            calls
                .iter()
                .map(|request| command(request)["a"].as_str().unwrap().to_owned())
                .collect::<Vec<_>>(),
            ["us0", "us", "ug"]
        );
    }
}

#[test]
fn malformed_prelogin_fields_are_refused_before_any_login_request() {
    for prelogin in [
        json!([1, 2, 3]),
        json!("surprise"),
        json!({"v":true}),
        json!({"v":null}),
        json!({"v":"2"}),
        json!({"v":-1}),
        json!({"v":0}),
        json!({"v":3}),
        json!({"v":1.5}),
        json!({"v":1,"s":17}),
        json!({"v":2}),
        json!({"v":2,"s":null}),
        json!({"v":2,"s":""}),
    ] {
        let (_, calls) = test_peer::with_peer(
            |request| {
                assert_eq!(command(request)["a"], "us0");
                Some(response(prelogin.clone()))
            },
            |address| {
                let mut api = Api::test_peer(address).unwrap();
                assert!(matches!(
                    login(&mut api, EMAIL, "source-fixture", None, || panic!(
                        "unexpected prompt"
                    )),
                    Err(Error::Protocol(_))
                ));
            },
        );
        assert_eq!(calls.len(), 1, "{prelogin}");
    }
}

#[test]
fn malformed_login_fields_never_attach_a_session_or_reach_the_probe() {
    let data = fixture();
    let login_key = hex::decode(data["legacy"][1]["derived"].as_str().unwrap()).unwrap();
    let mut malformed_user = login_response_with_key(&data, &login_key);
    malformed_user["u"] = json!(17);
    for reply in [
        json!({"tsid":"x"}),
        json!({"k":1234,"tsid":"x"}),
        json!({"k":"not-block-aligned","tsid":"x"}),
        json!({"k":"AAAAAAAAAAAAAAAAAAAAAA","privk":1}),
        json!({"k":"AAAAAAAAAAAAAAAAAAAAAA","privk":"AAAAAAAAAAAAAAAAAAAAAA","csid":null}),
        malformed_user,
    ] {
        let (_, calls) = test_peer::with_peer(
            |request| {
                let action = command(request);
                match action["a"].as_str().unwrap() {
                    "us0" => Some(response(json!({"v":1,"s":""}))),
                    "us" => Some(response(reply.clone())),
                    _ => panic!("invalid login must never attach a SID or probe"),
                }
            },
            |address| {
                let mut api = Api::test_peer(address).unwrap();
                assert!(
                    login(&mut api, EMAIL, "source-fixture", None, || panic!(
                        "unexpected prompt"
                    ))
                    .is_err()
                );
            },
        );
        assert_eq!(calls.len(), 2);
        assert!(calls.iter().all(|request| {
            !url::Url::parse(&format!("https://testserver.com{}", request.path))
                .unwrap()
                .query_pairs()
                .any(|(key, _)| key == "sid")
        }));
    }
}

#[test]
fn rejected_mfa_explains_expiry_and_survives_redaction_without_exposing_the_code() {
    let data = fixture();
    for rejection in [-5, -9, -26, -11] {
        let mut attempts = 0;
        let (_, calls) = test_peer::with_peer(
            |request| {
                let action = command(request);
                assert!(!request.path.contains("sid="));
                match action["a"].as_str().unwrap() {
                    "us0" => Some(response(
                        json!({"v":2,"s":wire::b64_url_encode(&hex::decode(data["kdf_v2"][2]["salt"].as_str().unwrap()).unwrap())}),
                    )),
                    "us" => {
                        attempts += 1;
                        if attempts == 1 {
                            assert!(action.get("mfa").is_none());
                            Some(response(json!(-26)))
                        } else {
                            assert_eq!(action["mfa"], "000000");
                            Some(response(json!(rejection)))
                        }
                    }
                    _ => panic!("rejected MFA must not reach the probe"),
                }
            },
            |address| {
                let mut api = Api::test_peer(address).unwrap();
                let error = match login(&mut api, EMAIL, "source-fixture", Some("000000"), || {
                    panic!("explicit code must not prompt")
                }) {
                    Err(error) => error,
                    Ok(_) => panic!("MFA rejection must fail"),
                };
                if rejection == -11 {
                    assert!(matches!(error, Error::Mega { code: -11, .. }));
                } else {
                    assert!(matches!(&error, Error::Auth(_)));
                    let message = error.to_string();
                    assert!(message.contains("rejected that 2FA code"));
                    assert!(message.contains("expire every 30 seconds"));
                    assert!(!message.contains("Transfer failed") && !message.contains("000000"));
                    assert_eq!(crate::terminal::redaction::text(&message), message);
                }
            },
        );
        assert_eq!(calls.len(), 3);
        assert_eq!(attempts, 2);
    }
}

#[test]
fn invalid_or_canceled_mfa_input_is_never_submitted_and_ordinary_rejections_do_not_prompt() {
    let data = fixture();
    for supplied in [
        Some(""),
        Some("12345"),
        Some("1234567"),
        Some("abcdef"),
        Some("۱۲۳۴۵۶"),
        None,
    ] {
        let mut attempts = 0;
        let mut prompted = 0;
        let (_, calls) = test_peer::with_peer(
            |request| {
                let action = command(request);
                match action["a"].as_str().unwrap() {
                    "us0" => Some(response(
                        json!({"v":2,"s":wire::b64_url_encode(&hex::decode(data["kdf_v2"][2]["salt"].as_str().unwrap()).unwrap())}),
                    )),
                    "us" => {
                        attempts += 1;
                        assert!(action.get("mfa").is_none());
                        Some(response(json!(-26)))
                    }
                    _ => panic!("invalid or canceled MFA must not reach the probe"),
                }
            },
            |address| {
                let mut api = Api::test_peer(address).unwrap();
                let result = login(&mut api, EMAIL, "source-fixture", supplied, || {
                    prompted += 1;
                    Err(Error::Canceled)
                });
                if supplied.is_none() {
                    assert!(matches!(result, Err(Error::Canceled)));
                } else {
                    assert!(matches!(result, Err(Error::Invalid(_))));
                }
            },
        );
        assert_eq!(prompted, usize::from(supplied.is_none()));
        assert_eq!(attempts, 1);
        assert_eq!(calls.len(), 2);
    }
    let mut prompted = false;
    let (_, calls) = test_peer::with_peer(
        |request| {
            let action = command(request);
            match action["a"].as_str().unwrap() {
                "us0" => Some(response(
                    json!({"v":2,"s":wire::b64_url_encode(&hex::decode(data["kdf_v2"][2]["salt"].as_str().unwrap()).unwrap())}),
                )),
                "us" => Some(response(json!(-9))),
                _ => panic!("ordinary login refusal must stop authentication"),
            }
        },
        |address| {
            let mut api = Api::test_peer(address).unwrap();
            assert!(matches!(
                login(&mut api, EMAIL, "source-fixture", None, || {
                    prompted = true;
                    Ok("123456".into())
                }),
                Err(Error::Mega { code: -9, .. })
            ));
        },
    );
    assert!(!prompted);
    assert_eq!(calls.len(), 2);
}

#[test]
fn suspicious_postlogin_identity_clears_api_sid_and_never_reports_authenticated() {
    let data = fixture();
    let mut probes = 0;
    let (_, calls) = test_peer::with_peer(
        |request| match command(request)["a"].as_str().unwrap() {
            "us0" => Some(response(
                json!({"v":2,"s":wire::b64_url_encode(&hex::decode(data["kdf_v2"][2]["salt"].as_str().unwrap()).unwrap())}),
            )),
            "us" => Some(response(login_response(&data))),
            "ug" => {
                probes += 1;
                let url =
                    url::Url::parse(&format!("https://testserver.com{}", request.path)).unwrap();
                assert_eq!(url.query_pairs().any(|(key, _)| key == "sid"), probes == 1);
                Some(response(
                    json!({"u":if probes==1 {"other-user"} else {USER}}),
                ))
            }
            _ => panic!("unexpected action"),
        },
        |address| {
            let mut api = Api::test_peer(address).unwrap();
            assert!(matches!(
                login(&mut api, EMAIL, "source-fixture", None, || panic!(
                    "unexpected MFA prompt"
                )),
                Err(Error::Auth(_))
            ));
            api.request(json!({"a":"ug"}), &[]).unwrap();
        },
    );
    assert_eq!(calls.len(), 4);
}

#[test]
fn session_probe_preserves_uncertain_or_suspicious_state_but_forgets_only_definitive_esid() {
    let data = fixture();
    for outcome in [
        json!({"u":USER}),
        json!({"u":"other-user"}),
        json!({}),
        json!(-15),
    ] {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/session-peers");
        std::fs::create_dir_all(&root).unwrap();
        let scratch = crate::test_support::tempdir_in(root).unwrap();
        let path = scratch.path().join("private/session.json");
        let store = Sessions::new(&path);
        let vault = Vault::new("synthetic session passphrase");
        store.remember(&session(&data), &vault).unwrap();
        let before = std::fs::read(&path).unwrap();
        assert!(
            !String::from_utf8(before.clone())
                .unwrap()
                .contains(data["rsa"]["sid"].as_str().unwrap())
        );
        let mut probes = 0;
        let (_, calls) = test_peer::with_peer(
            |request| {
                assert_eq!(command(request)["a"], "ug");
                probes += 1;
                let url =
                    url::Url::parse(&format!("https://testserver.com{}", request.path)).unwrap();
                assert_eq!(url.query_pairs().any(|(key, _)| key == "sid"), probes == 1);
                Some(response(if probes == 1 {
                    outcome.clone()
                } else {
                    json!({"u":USER})
                }))
            },
            |address| {
                let mut api = Api::test_peer(address).unwrap();
                let restored = store.restore(EMAIL, &vault, &mut api);
                if outcome == json!({"u":USER}) {
                    assert_eq!(
                        restored.unwrap().unwrap().sid,
                        data["rsa"]["sid"].as_str().unwrap()
                    );
                    assert_eq!(std::fs::read(&path).unwrap(), before);
                } else {
                    if outcome == json!(-15) {
                        assert!(restored.unwrap().is_none());
                        assert!(!path.exists());
                    } else {
                        assert!(restored.is_err());
                        assert_eq!(std::fs::read(&path).unwrap(), before);
                    }
                    api.request(json!({"a":"ug"}), &[]).unwrap();
                }
            },
        );
        assert_eq!(
            calls.len(),
            if outcome == json!({"u":USER}) { 1 } else { 2 }
        );
    }
}
