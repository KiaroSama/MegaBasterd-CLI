#![allow(clippy::unwrap_used)]

use megabasterd_cli::{
    crypto::{chunks::Chunk, wire},
    error::Error,
    protocol::uploads::{completion_token, registration_request, validate_token},
    storage::transfer_state::TransferState,
};
use serde_json::json;

// Preserved source regression: the upload endpoint already encoded these bytes.
const TOKEN: &str = "FCCyf3QV62uAsbARFKbVd8zWyqOQXPFgEL9i";

#[test]
fn completion_token_preserves_source_width_bytes_and_final_chunk_boundary() {
    assert_eq!(
        completion_token(TOKEN.as_bytes(), true).unwrap().as_deref(),
        Some(TOKEN)
    );
    assert!(completion_token(TOKEN.as_bytes(), false).is_err());
    assert!(completion_token(b"", true).is_err());
    assert_eq!(completion_token(b"", false).unwrap(), None);
    for index in 0..3 {
        let chunk = Chunk {
            index,
            offset: index as u64 * 1024,
            size: 1024,
        };
        let final_chunk = chunk.end().unwrap() == 3072;
        assert_eq!(final_chunk, index == 2);
        if final_chunk {
            assert_eq!(
                completion_token(b"REALTOKEN", final_chunk)
                    .unwrap()
                    .as_deref(),
                Some("REALTOKEN")
            );
        } else {
            assert!(completion_token(b"REALTOKEN", final_chunk).is_err());
            assert_eq!(completion_token(b"", final_chunk).unwrap(), None);
        }
    }
    for invalid in ["white space", "token\r\n", "nonascii-é", "=padding", "-9"] {
        assert!(validate_token(invalid).is_err());
    }
    assert!(validate_token(&"A".repeat(4097)).is_err());
    assert!(matches!(
        completion_token(b"-17", true),
        Err(Error::Mega { code: -17, .. })
    ));
    let mut state = TransferState::new(
        "upload",
        "source",
        std::path::Path::new("file.bin"),
        1,
        &[1; 16],
    )
    .unwrap();
    state.completion_token = Some(TOKEN.into());
    assert!(state.validate().is_ok());
    let reopened: TransferState =
        serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
    assert_eq!(reopened.completion_token.as_deref(), Some(TOKEN));
}

#[test]
fn registration_sends_original_token_but_encrypts_attributes_and_full_file_key() {
    let aes_key = [0x11; 16];
    let master_key = [0x22; 16];
    let raw_key = [0x33; 32];
    let request = registration_request(
        "ROOTHNDL",
        "OAD -  09v2.mkv",
        TOKEN,
        &aes_key,
        &raw_key,
        &master_key,
    )
    .unwrap();
    let node = &request["n"][0];
    assert_eq!(request["a"], "p");
    assert_eq!(request["t"], "ROOTHNDL");
    assert_eq!(node["h"], TOKEN);
    assert_ne!(node["h"], wire::b64_url_encode(TOKEN.as_bytes()));
    let attributes = wire::b64_url_decode(node["a"].as_str().unwrap()).unwrap();
    assert_eq!(
        wire::decrypt_attributes(&attributes, &aes_key).unwrap(),
        json!({"n":"OAD -  09v2.mkv"})
    );
    let wrapped = wire::b64_url_decode(node["k"].as_str().unwrap()).unwrap();
    assert_eq!(
        &*wire::aes_key_wrap_decrypt(&wrapped, &master_key).unwrap(),
        &raw_key
    );
    assert!(registration_request("", "name", TOKEN, &aes_key, &raw_key, &master_key).is_err());
    assert!(
        registration_request("ROOTHNDL", "name", TOKEN, &aes_key, &[0; 16], &master_key).is_err()
    );
}
