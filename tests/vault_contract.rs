#![allow(clippy::unwrap_used)]
use megabasterd_cli::storage::vault::Vault;

#[test]
fn sealed_secrets_authenticate_passphrase_context_and_header() {
    let vault = Vault::new("invented fixture passphrase");
    let sealed = vault
        .seal(b"invented password", b"account:test@example.invalid")
        .unwrap();
    assert_eq!(
        &*vault
            .open(&sealed, b"account:test@example.invalid")
            .unwrap(),
        b"invented password"
    );
    assert!(
        vault
            .open(&sealed, b"account:other@example.invalid")
            .is_err()
    );
    assert!(
        Vault::new("different fixture passphrase")
            .open(&sealed, b"account:test@example.invalid")
            .is_err()
    );
    assert!(vault.open("not base64!", b"account").is_err());
    let mut damaged = megabasterd_cli::crypto::wire::b64_url_decode(&sealed).unwrap();
    damaged[4] = 255;
    assert!(
        vault
            .open(
                &megabasterd_cli::crypto::wire::b64_url_encode(&damaged),
                b"account"
            )
            .is_err()
    );
    let mut damaged = megabasterd_cli::crypto::wire::b64_url_decode(&sealed).unwrap();
    let last = damaged.len() - 1;
    damaged[last] ^= 1;
    assert!(
        vault
            .open(
                &megabasterd_cli::crypto::wire::b64_url_encode(&damaged),
                b"account:test@example.invalid"
            )
            .is_err()
    );
}
