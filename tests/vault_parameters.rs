//! Native envelopes honor authenticated, bounded KDF parameters without legacy-store support.
#![allow(clippy::unwrap_used)]

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use megabasterd_cli::{
    crypto::wire::{b64_url_decode, b64_url_encode},
    error::Error,
    storage::vault::Vault,
};
use zeroize::Zeroizing;

const CONTEXT: &[u8] = b"account:fixture@example.invalid";
const PASSWORD: &str = "invented native vault passphrase";

fn alternate_cost_envelope() -> String {
    // Independent writer follows the documented MBV2 layout, not Vault::seal.
    let mut header = b"MBV2\x0c\x08\x01".to_vec();
    header.extend_from_slice(&[3; 16]);
    header.extend_from_slice(&[5; 12]);
    let mut key = Zeroizing::new([0; 32]);
    scrypt::scrypt(
        PASSWORD.as_bytes(),
        &[3; 16],
        &scrypt::Params::new(12, 8, 1).unwrap(),
        &mut *key,
    )
    .unwrap();
    let cipher = Aes256Gcm::new_from_slice(&*key).unwrap();
    let mut aad = header.clone();
    aad.extend_from_slice(CONTEXT);
    let encrypted = cipher
        .encrypt(
            &Nonce::from([5; 12]),
            Payload {
                msg: b"credential at a different cost",
                aad: &aad,
            },
        )
        .unwrap();
    header.extend_from_slice(&encrypted);
    b64_url_encode(&header)
}

#[test]
fn native_vault_records_default_parameters_and_opens_a_different_authenticated_cost() {
    let vault = Vault::new(PASSWORD);
    let sealed = vault.seal(b"native credential", CONTEXT).unwrap();
    let bytes = b64_url_decode(&sealed).unwrap();
    assert_eq!(&bytes[..7], b"MBV2\x0f\x08\x01");
    assert_eq!(
        &*vault.open(&sealed, CONTEXT).unwrap(),
        b"native credential"
    );
    let alternate = alternate_cost_envelope();
    for _ in 0..2 {
        assert_eq!(
            &*vault.open(&alternate, CONTEXT).unwrap(),
            b"credential at a different cost"
        );
    }
    assert!(matches!(
        Vault::new("wrong").open(&alternate, CONTEXT),
        Err(Error::Auth(_))
    ));
    assert!(matches!(
        vault.open(&alternate, b"account:other"),
        Err(Error::Auth(_))
    ));
    let mut tampered = b64_url_decode(&alternate).unwrap();
    tampered[4] = 13; // Still an allowed cost: authenticated header must reject this change.
    assert!(matches!(
        vault.open(&b64_url_encode(&tampered), CONTEXT),
        Err(Error::Auth(_))
    ));
}

#[test]
fn hostile_native_vault_parameters_and_unsupported_formats_fail_before_key_derivation() {
    let vault = Vault::new(PASSWORD);
    for parameters in [
        [0, 8, 1],
        [9, 8, 1],
        [23, 8, 1],
        [64, 8, 1],
        [255, 8, 1],
        [15, 0, 1],
        [15, 33, 1],
        [15, 8, 0],
        [15, 8, 17],
        [22, 32, 16], // Individual fields are bounded but their combined cost is hostile.
    ] {
        let mut raw = b"MBV2".to_vec();
        raw.extend_from_slice(&parameters);
        raw.extend_from_slice(&[0; 44]);
        let error = vault.open(&b64_url_encode(&raw), CONTEXT).unwrap_err();
        assert!(matches!(&error, Error::Corrupt(message) if message.contains("work factor")));
        assert!(!error.to_string().contains("passphrase"));
    }
    let mut legacy = vec![2, 15, 8, 1, 15, 8, 1];
    legacy.extend_from_slice(&[0x71; 9]); // Remaining salt: its first byte collides with old v2.
    legacy.extend_from_slice(&[0x52; 12]); // Old salt || nonce || opaque ciphertext/tag layout.
    legacy.extend_from_slice(&[0x63; 32]);
    assert_eq!(legacy[0], 2);
    assert_eq!(&legacy[4..7], &[15, 8, 1]);
    let mut unsupported = b"MBV1\x0f\x08\x01".to_vec();
    unsupported.extend_from_slice(&[0; 44]);
    for raw in [legacy, unsupported] {
        assert!(
            raw.len() >= 35 + 16,
            "format refusal must not depend on short input"
        );
        let error = vault.open(&b64_url_encode(&raw), CONTEXT).unwrap_err();
        assert!(matches!(&error, Error::Corrupt(message) if message.contains("format")));
        assert!(!error.to_string().contains("passphrase"));
        assert!(!error.to_string().contains("(v"));
    }
}
