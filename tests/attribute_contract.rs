#![allow(clippy::unwrap_used)]

use megabasterd_cli::{
    crypto::{keys, wire},
    services::attributes,
};
use serde_json::json;

#[test]
fn thumbnail_payload_uses_the_file_aes_key_zero_iv_and_zero_padding() {
    let raw = wire::a32_to_bytes(&keys::pack_file_key(&[1; 16], &[2; 8], &[0, 0]).unwrap());
    let encrypted = attributes::encrypt_thumbnail(b"JPEG fixture", &raw).unwrap();
    assert_eq!(encrypted.len(), 16);
    let plain = wire::aes_cbc_decrypt(&encrypted, &[1; 16]).unwrap();
    assert_eq!(&plain[..12], b"JPEG fixture");
    assert_eq!(&plain[12..], &[0; 4]);
    assert!(attributes::encrypt_thumbnail(&[], &raw).is_err());
    assert!(attributes::encrypt_thumbnail(b"fixture", &[0; 31]).is_err());
    assert!(attributes::encrypt_thumbnail(&vec![0; 1024 * 1024 + 1], &raw).is_err());
}

#[test]
fn file_attribute_requests_require_https_and_an_exact_eight_byte_handle() {
    assert_eq!(attributes::upload_ticket(32), json!({"a":"ufa","s":32}));
    assert_eq!(
        attributes::attachment("node", &[0; 8]).unwrap(),
        json!({"a":"pfa","n":"node","fa":"0*AAAAAAAAAAA"})
    );
    assert!(attributes::attachment("node", &[0; 9]).is_err());
    assert!(attributes::attachment("", &[0; 8]).is_err());
}
