#![allow(clippy::unwrap_used)]

use megabasterd_cli::{
    crypto::{keys, wire},
    error::Error,
    protocol::auth::{decode_login_response, probe_user},
};
use serde_json::{Value, json};
use std::sync::OnceLock;

#[test]
fn wrapped_rsa_login_decodes_independent_source_oracle_and_refuses_bad_wire_material() {
    static FIXTURE: OnceLock<Value> = OnceLock::new();
    let fixture = FIXTURE.get_or_init(|| {
        serde_json::from_str(include_str!("fixtures/crypto-vectors.json")).unwrap()
    });
    let rsa = &fixture["rsa"];
    let master = hex::decode(rsa["master_key"].as_str().unwrap()).unwrap();
    let login = [7; 16];
    let response = json!({"u":"AQIDBAUGBwg", "k":wire::b64_url_encode(&wire::aes_key_wrap_encrypt(&master, &login).unwrap()),
        "privk":wire::b64_url_encode(&hex::decode(rsa["wrapped_private"].as_str().unwrap()).unwrap()),
        "csid":wire::b64_url_encode(&hex::decode(rsa["csid"].as_str().unwrap()).unwrap())});
    let session = decode_login_response(&response, "fixture@example.invalid", &login).unwrap();
    assert_eq!(session.sid, rsa["sid"].as_str().unwrap());
    assert_eq!(session.master_key.as_slice(), master);
    assert!(session.rsa_private_key.is_some());
    assert_eq!(
        probe_user(&json!({"u":"AQIDBAUGBwg"}), Some(&session.user_handle)).unwrap(),
        "AQIDBAUGBwg"
    );
    assert!(probe_user(&json!({"u":"different"}), Some(&session.user_handle)).is_err());
    assert!(probe_user(&json!({}), None).is_err());
    let mut broken = response.clone();
    broken["csid"] = json!("broken!");
    assert!(decode_login_response(&broken, "fixture@example.invalid", &login).is_err());
    broken = response;
    broken["k"] = json!(wire::b64_url_encode(&[0; 15]));
    assert!(decode_login_response(&broken, "fixture@example.invalid", &login).is_err());
}

#[test]
fn short_rsa_session_plaintext_is_refused_before_a_session_can_be_created() {
    let original_private = [0, 8, 3, 0, 8, 5, 0, 8, 1, 0, 8, 1];
    let original_error = keys::decode_session_id(&[1], &original_private).unwrap_err();
    assert!(matches!(&original_error, Error::Protocol(_)));
    assert_eq!(original_error.exit_code(), 1);

    // Valid native factors reach RSA: 1^3 mod (3*5) is only one plaintext byte.
    let private = [0, 8, 3, 0, 8, 5, 0, 8, 3, 0, 8, 1];
    let error = keys::decode_session_id(&[0, 8, 1], &private).unwrap_err();
    assert!(matches!(&error, Error::Protocol(message)
        if message == "RSA session plaintext is shorter than 43 bytes"));
    assert_eq!(error.exit_code(), 1);
    assert_eq!(error.code(), "protocol_error");
    assert!(!error.retryable_network());
}

#[test]
fn temporary_login_verifies_symmetric_challenge_before_accepting_the_sid() {
    // AES-128 NIST SP800-38A first ECB vector, independent of this implementation.
    let master = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let mut challenge = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
    challenge.extend([0; 11]);
    challenge.extend(hex::decode("3ad77bb40d7a3660a89ecaf32466ef97").unwrap());
    let login = [3; 16];
    let mut response = json!({"k":wire::b64_url_encode(&wire::aes_key_wrap_encrypt(&master, &login).unwrap()),
        "tsid":wire::b64_url_encode(&challenge)});
    let session = decode_login_response(&response, "fixture@example.invalid", &login).unwrap();
    assert!(session.rsa_private_key.is_none());
    assert_eq!(session.sid, response["tsid"]);
    challenge[42] ^= 1;
    response["tsid"] = json!(wire::b64_url_encode(&challenge));
    assert!(decode_login_response(&response, "fixture@example.invalid", &login).is_err());
    response["tsid"] = json!(wire::b64_url_encode(&challenge[..42]));
    assert!(decode_login_response(&response, "fixture@example.invalid", &login).is_err());
}
