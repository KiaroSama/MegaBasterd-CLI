//! Cached-session reuse and fallback through the shared production account entry point.
#![allow(clippy::unwrap_used)]

use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    path::Path,
    sync::mpsc,
    time::Duration,
};

use super::{
    auto_account_peer_tests::Capture,
    client_lifecycle_peer_tests::{observe_close, respond_and_observe_close},
    context::Context,
};
use crate::{
    crypto::wire,
    protocol::{
        api::Api,
        auth::Session,
        test_peer::{self, Response},
    },
    storage::{sessions::Sessions, vault::Vault},
    terminal::output::Output,
};

const EMAIL: &str = "fixture@example.invalid";
const PASS: &str = "synthetic reuse vault";
const USER: &str = "AQIDBAUGBwg";

#[test]
fn corrupt_or_future_session_reads_are_refused_without_requests_or_saved_byte_changes() {
    use crate::{error::Error, storage::files::Store};

    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/session-reuse");
    fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(&base).unwrap();
    let path = scratch.path().join("private/session.json");
    let store = Store::new(&path);
    let sessions = Sessions::new(&path);
    let vault = Vault::new(PASS);
    let (_, calls) = test_peer::with_peer(
        |_| panic!("unusable saved session must never reach the network"),
        |address| {
            let mut api = Api::test_peer(address).unwrap();
            for raw in [
                br#""encrypted""#.as_slice(),
                br#"["encrypted"]"#,
                b"123",
                b"null",
                b"true",
                br#""anything""#,
                b"[]",
                br#"{"version":2,"encrypted":42}"#,
                b"not json at all",
                br#"{"version":99,"data":{"encrypted":"unused"}}"#,
                br#"{"version":2,"data":{"encrypted":42}}"#,
                br#"{"version":2,"data":{"encrypted":"malformed"}}"#,
            ] {
                store.lock().unwrap().write_bytes(raw).unwrap();
                assert!(matches!(
                    sessions.restore(EMAIL, &vault, &mut api),
                    Err(Error::Corrupt(_))
                ));
                assert_eq!(fs::read(&path).unwrap(), raw);
            }
            let data = json!({"encrypted":vault.seal(b"[1,2,3]", b"session:fixture@example.invalid").unwrap()});
            store.lock().unwrap().save(&data).unwrap();
            let original = fs::read(&path).unwrap();
            assert!(matches!(
                sessions.restore(EMAIL, &vault, &mut api),
                Err(Error::Corrupt(_))
            ));
            assert_eq!(fs::read(&path).unwrap(), original);
        },
    );
    assert!(calls.is_empty());
}

#[test]
fn uncertain_session_probe_preserves_bytes_clears_sid_and_prevents_fresh_authentication() {
    use crate::error::Error;

    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/session-reuse");
    fs::create_dir_all(&base).unwrap();
    for malformed in [false, true] {
        let scratch = tempfile::tempdir_in(&base).unwrap();
        let paths = Context::test_context(scratch.path()).paths;
        let vault = Vault::new(PASS);
        let accounts = crate::storage::accounts::Accounts::new(paths.accounts());
        accounts
            .add(EMAIL, "source-fixture", None, true, &vault)
            .unwrap();
        let account = accounts.find(Some(EMAIL)).unwrap();
        let sessions = Sessions::new(paths.session(EMAIL));
        sessions
            .remember(
                &Session {
                    sid: "unproven-session-sid".into(),
                    master_key: [9; 16],
                    rsa_private_key: None,
                    user_handle: USER.into(),
                    email: EMAIL.into(),
                },
                &vault,
            )
            .unwrap();
        let before_session = fs::read(paths.session(EMAIL)).unwrap();
        let before_accounts = fs::read(paths.accounts()).unwrap();
        let mut requests = 0;
        let (_, calls) = test_peer::with_peer(
            |request| {
                let command: Value = serde_json::from_slice(&request.body).unwrap();
                assert_eq!(command, json!([{"a":"ug"}]));
                requests += 1;
                let url =
                    url::Url::parse(&format!("https://testserver.com{}", request.path)).unwrap();
                let sid = url
                    .query_pairs()
                    .find(|(key, _)| key == "sid")
                    .map(|(_, value)| value.into_owned());
                if requests <= 2 {
                    assert_eq!(sid.as_deref(), Some("unproven-session-sid"));
                    Some(Response {
                        status: if malformed { 200 } else { 500 },
                        headers: vec![],
                        body: b"[{}]".to_vec(),
                    })
                } else {
                    assert_eq!(requests, 3);
                    assert!(
                        sid.is_none(),
                        "unproven SID stayed on transport after restore failed"
                    );
                    Some(Response {
                        status: 200,
                        headers: vec![],
                        body: serde_json::to_vec(&json!([{"u":USER}])).unwrap(),
                    })
                }
            },
            |address| {
                let api = Api::test_peer(address).unwrap();
                let mut context = Context::test_peer(
                    scratch.path(),
                    api,
                    Output::with_writers(false, false, Capture::default(), Capture::default()),
                );
                match context.session(&account, &vault, None, None) {
                    Err(Error::Protocol(_)) => (),
                    _ => panic!(
                        "uncertain or invalid session proof must not authenticate or log in again"
                    ),
                }
                let mut api = context.api(None).unwrap();
                assert!(sessions.restore(EMAIL, &vault, &mut api).is_err());
                api.request(json!({"a":"ug"}), &[]).unwrap();
                assert_eq!(fs::read(paths.session(EMAIL)).unwrap(), before_session);
                assert_eq!(fs::read(paths.accounts()).unwrap(), before_accounts);
            },
        );
        assert_eq!(calls.len(), 3);
    }
}

#[test]
fn actual_connection_timeout_tls_and_proxy_failures_preserve_cache_and_clear_unproven_sid() {
    use crate::{error::Error, storage::files::Store};

    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/session-reuse");
    fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(&base).unwrap();
    let paths = Context::test_context(scratch.path()).paths;
    let vault = Vault::new(PASS);
    let accounts = crate::storage::accounts::Accounts::new(paths.accounts());
    accounts
        .add(EMAIL, "source-fixture", None, true, &vault)
        .unwrap();
    let sessions = Sessions::new(paths.session(EMAIL));
    sessions
        .remember(
            &Session {
                sid: "unproven-session-sid".into(),
                master_key: [9; 16],
                rsa_private_key: None,
                user_handle: USER.into(),
                email: EMAIL.into(),
            },
            &vault,
        )
        .unwrap();
    let before_session = fs::read(paths.session(EMAIL)).unwrap();
    let before_accounts = fs::read(paths.accounts()).unwrap();

    for fault in ["connection", "timeout", "tls", "proxy"] {
        let (backoff, waits) = mpsc::sync_channel(4);
        let run = |address| {
            let mut api = Api::test_peer(address).unwrap();
            api.observe_backoffs(backoff);
            if fault == "timeout" {
                api.transport.timeout = Duration::from_secs(1);
            }
            if fault == "proxy" {
                api.transport.routing.explicit =
                    Some(format!("http://127.0.0.1:{}", address.port()));
                api.transport.routing.force = true;
            }
            let error = match sessions.restore(EMAIL, &vault, &mut api) {
                Err(error) => error,
                _ => panic!("transport uncertainty produced a usable or missing session"),
            };
            match fault {
                "timeout" => assert!(
                    matches!(&error, Error::Timeout)
                        || matches!(&error, Error::Http(cause) if cause.is_timeout())
                ),
                "tls" => assert!(matches!(&error, Error::Http(cause)
                    if cause.is_connect() && !cause.is_timeout())),
                "proxy" => assert!(matches!(&error, Error::Protocol(message)
                    if message == "CONNECT proxy refused the tunnel")),
                _ => assert!(error.retryable_network() && !matches!(&error, Error::Timeout)),
            }
            assert_eq!(error.exit_code(), 1);
            assert!(!api.control.is_canceled());
            assert_eq!(fs::read(paths.session(EMAIL)).unwrap(), before_session);
            assert_eq!(fs::read(paths.accounts()).unwrap(), before_accounts);
            let fence = Store::new(paths.session(EMAIL))
                .with_timeout(Duration::ZERO)
                .lock()
                .unwrap();
            drop(fence);
            assert_eq!(
                waits
                    .try_iter()
                    .map(|duration| duration.as_secs())
                    .collect::<Vec<_>>(),
                if fault == "proxy" {
                    vec![]
                } else {
                    vec![2, 4, 8, 16]
                },
            );
            if matches!(fault, "connection" | "timeout") {
                // The same API, not a new anonymous client, must have discarded the unproven SID.
                assert_eq!(
                    api.request(json!({"a":"ug"}), &[]).unwrap(),
                    json!({"u":USER})
                );
            }
            assert_eq!(fs::read(paths.session(EMAIL)).unwrap(), before_session);
            assert!(!paths.output.exists() && !paths.logs.exists());
        };
        match fault {
            "proxy" => {
                let ((), calls) = test_peer::with_refusing_connect_peer(run);
                assert_eq!(calls.len(), 1);
                assert_eq!(calls[0].method, "CONNECT");
                assert!(calls[0].body.is_empty());
            }
            "tls" => {
                let ((), handshakes) = test_peer::with_socket_peer(
                    |mut socket, _| {
                        let mut header = [0; 5];
                        socket.read_exact(&mut header).unwrap();
                        assert_eq!(header[0], 0x16, "expected a TLS handshake record");
                        assert_eq!(header[1], 3);
                        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
                        assert!((1..=16 * 1024).contains(&length));
                        let mut hello = vec![0; length];
                        socket.read_exact(&mut hello).unwrap();
                        assert_eq!(hello[0], 1, "expected ClientHello before any HTTP");
                        // TLS fatal handshake_failure; no trust bypass or application request.
                        socket.write_all(b"\x15\x03\x03\x00\x02\x02\x28").unwrap();
                        socket.flush().unwrap();
                    },
                    run,
                );
                assert_eq!(handshakes.len(), 5);
            }
            _ => {
                let mut attempts = 0;
                let ((), calls) = test_peer::with_raw_peer(
                    |request, stream| {
                        attempts += 1;
                        assert_eq!(request.method, "POST");
                        assert_eq!(
                            serde_json::from_slice::<Value>(&request.body).unwrap(),
                            json!([{"a":"ug"}])
                        );
                        let url =
                            url::Url::parse(&format!("https://testserver.com{}", request.path))
                                .unwrap();
                        assert_eq!(
                            url.query_pairs().find(|(key, _)| key == "id").unwrap().1,
                            attempts.to_string()
                        );
                        if attempts <= 5 {
                            assert!(url.query_pairs().any(
                                |(key, value)| key == "sid" && value == "unproven-session-sid"
                            ));
                            if fault == "timeout" {
                                observe_close(stream);
                            }
                            // Connection case drops each actual socket before response headers.
                        } else {
                            assert_eq!(attempts, 6, "unexpected login or extra retry");
                            assert!(!url.query_pairs().any(|(key, _)| key == "sid"));
                            respond_and_observe_close(stream, 200, json!({"u":USER}));
                        }
                    },
                    run,
                );
                assert_eq!(calls.len(), 6);
            }
        }
    }
}

#[test]
fn shared_account_session_reuses_valid_cache_and_logs_in_only_for_missing_expired_or_wrong_vault() {
    let data: Value =
        serde_json::from_str(include_str!("../../tests/fixtures/crypto-vectors.json")).unwrap();
    let master = hex::decode(data["rsa"]["master_key"].as_str().unwrap()).unwrap();
    let derived = hex::decode(data["kdf_v2"][2]["derived"].as_str().unwrap()).unwrap();
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/session-reuse");
    fs::create_dir_all(&base).unwrap();
    for mode in ["valid", "missing", "expired", "wrong-vault"] {
        let scratch = tempfile::tempdir_in(&base).unwrap();
        let paths = Context::test_context(scratch.path()).paths;
        let vault = Vault::new(PASS);
        let accounts = crate::storage::accounts::Accounts::new(paths.accounts());
        accounts
            .add(EMAIL, "source-fixture", None, true, &vault)
            .unwrap();
        let account = accounts.find(Some(EMAIL)).unwrap();
        if mode != "missing" {
            Sessions::new(paths.session(EMAIL))
                .remember(
                    &Session {
                        sid: "cached-session-sid".into(),
                        master_key: master.as_slice().try_into().unwrap(),
                        rsa_private_key: None,
                        user_handle: USER.into(),
                        email: EMAIL.into(),
                    },
                    &Vault::new(if mode == "wrong-vault" {
                        "different cache passphrase"
                    } else {
                        PASS
                    }),
                )
                .unwrap();
        }
        let before_accounts = fs::read(paths.accounts()).unwrap();
        let before_session = fs::read(paths.session(EMAIL)).ok();
        let stdout = Capture::default();
        let stderr = Capture::default();
        let mut actions = Vec::new();
        let (_, calls) = test_peer::with_peer(
            |request| {
                let payload: Value = serde_json::from_slice(&request.body).unwrap();
                assert_eq!(payload.as_array().unwrap().len(), 1);
                let command = &payload[0];
                let action = command["a"].as_str().unwrap();
                let url =
                    url::Url::parse(&format!("https://testserver.com{}", request.path)).unwrap();
                let sid = url
                    .query_pairs()
                    .find(|(key, _)| key == "sid")
                    .map(|(_, value)| value.into_owned());
                actions.push(action.to_owned());
                let result = match action {
                    "ug" if sid.as_deref() == Some("cached-session-sid") => {
                        assert!(matches!(mode, "valid" | "expired"));
                        if mode == "expired" {
                            json!(-15)
                        } else {
                            json!({"u":USER})
                        }
                    }
                    "us0" => {
                        assert!(sid.is_none(), "fallback carried an unproven cached SID");
                        assert_eq!(command["user"], EMAIL);
                        json!({"v":2,"s":wire::b64_url_encode(&hex::decode(data["kdf_v2"][2]["salt"].as_str().unwrap()).unwrap())})
                    }
                    "us" => {
                        assert!(sid.is_none());
                        assert_eq!(command["user"], EMAIL);
                        assert_eq!(command["uh"], wire::b64_url_encode(&derived[16..]));
                        assert!(command.get("mfa").is_none());
                        json!({"u":USER,"k":wire::b64_url_encode(&wire::aes_key_wrap_encrypt(&master,&derived[..16]).unwrap()),
                            "privk":wire::b64_url_encode(&hex::decode(data["rsa"]["wrapped_private"].as_str().unwrap()).unwrap()),
                            "csid":wire::b64_url_encode(&hex::decode(data["rsa"]["csid"].as_str().unwrap()).unwrap())})
                    }
                    "ug" => {
                        assert_eq!(sid.as_deref(), data["rsa"]["sid"].as_str());
                        json!({"u":USER})
                    }
                    _ => panic!("session reuse must not log out or mutate remote data"),
                };
                Some(Response {
                    status: 200,
                    headers: vec![],
                    body: serde_json::to_vec(&json!([result])).unwrap(),
                })
            },
            |address| {
                let output = Output::with_writers(false, false, stdout.clone(), stderr.clone());
                let mut context =
                    Context::test_peer(scratch.path(), Api::test_peer(address).unwrap(), output);
                let (mut api, session) = context.session(&account, &vault, None, None).unwrap();
                if mode == "valid" {
                    api.request(json!({"a":"ug"}), &[]).unwrap();
                }
                assert_eq!(session.email, EMAIL);
                assert_eq!(session.master_key.as_slice(), master);
                assert_eq!(
                    session.sid,
                    if mode == "valid" {
                        "cached-session-sid"
                    } else {
                        data["rsa"]["sid"].as_str().unwrap()
                    }
                );
                assert_eq!(fs::read(paths.accounts()).unwrap(), before_accounts);
                let saved = fs::read(paths.session(EMAIL)).unwrap();
                let sealed: Value = serde_json::from_slice(&saved).unwrap();
                let cache_vault = Vault::new(if mode == "wrong-vault" {
                    "different cache passphrase"
                } else {
                    PASS
                });
                let plaintext = cache_vault
                    .open(
                        sealed["data"]["encrypted"].as_str().unwrap(),
                        b"session:fixture@example.invalid",
                    )
                    .unwrap();
                let persisted: Session = serde_json::from_slice(&plaintext).unwrap();
                assert_eq!(
                    persisted.sid,
                    if matches!(mode, "valid" | "wrong-vault") {
                        "cached-session-sid"
                    } else {
                        data["rsa"]["sid"].as_str().unwrap()
                    }
                );
                assert_eq!(persisted.master_key.as_slice(), master);
                if matches!(mode, "valid" | "wrong-vault") {
                    assert_eq!(saved, before_session.unwrap());
                } else {
                    assert_ne!(Some(&saved), before_session.as_ref());
                }
                for secret in [
                    EMAIL,
                    "cached-session-sid",
                    data["rsa"]["sid"].as_str().unwrap(),
                ] {
                    assert!(!String::from_utf8(saved.clone()).unwrap().contains(secret));
                }
                assert!(stdout.0.lock().unwrap().is_empty());
                let diagnostics = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
                assert_eq!(
                    diagnostics.contains("could not be cached"),
                    mode == "wrong-vault"
                );
                for secret in [PASS, "source-fixture", "cached-session-sid"] {
                    assert!(!diagnostics.contains(secret));
                }
            },
        );
        assert_eq!(
            actions,
            match mode {
                "valid" => vec!["ug", "ug"],
                "expired" => vec!["ug", "us0", "us", "ug"],
                _ => vec!["us0", "us", "ug"],
            }
        );
        assert_eq!(calls.len(), actions.len());
    }
}
