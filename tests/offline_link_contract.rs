// SPDX-License-Identifier: GPL-3.0-or-later
#![allow(clippy::unwrap_used)]

use megabasterd_cli::protocol::{
    containers,
    links::{self, LinkType},
};

#[test]
fn keyless_public_links_are_recognized_without_accepting_a_foreign_host() {
    for input in ["https://mega.nz/file/abc", "https://mega.co.nz/file/abc"] {
        assert!(links::is_mega_url(input));
        let parsed = links::parse_link(input).unwrap();
        assert_eq!(parsed.kind, LinkType::File);
        assert_eq!(parsed.public_id, "abc");
        assert!(parsed.key.is_none());
        assert!(links::require_link_key(&parsed).is_err());
    }
    assert!(!links::is_mega_url("https://example.com"));
}

#[test]
fn exact_source_encrypted_link_literals_resolve_with_both_published_keys() {
    // Independent Node/OpenSSL AES-256-CBC vectors; source full URLs use zero padding.
    for (variant, ciphertext, public_id, key) in [
        (
            "enc",
            "yd5uIhSeIV0FpvUjQ0v35jdgaAwYEjyWqRrXqrezvInLIKQieZUwolzU5BFuojGg",
            "ABC123",
            "KEY-456",
        ),
        (
            "enc2",
            "668qkYWUdZiYk9Wu0jEnHf7nLRhOa03XUP2G3GAOvz4=",
            "F2",
            "K2",
        ),
    ] {
        let parsed = links::parse_link(&format!("mega://{variant}?{ciphertext}")).unwrap();
        assert_eq!(parsed.kind, LinkType::EncryptedContainer);
        assert_eq!(parsed.container_variant.as_deref(), Some(variant));
        assert_eq!(parsed.container_blob.as_deref(), Some(ciphertext));
        let resolved = containers::resolve_encrypted_container_link(&parsed).unwrap();
        assert_eq!(resolved.kind, LinkType::File);
        assert_eq!(resolved.public_id, public_id);
        assert_eq!(resolved.key.as_deref(), Some(key));
        assert!(resolved.subpath.is_none());
        let offline = links::resolve_offline(&parsed, None).unwrap();
        assert_eq!(
            serde_json::to_value(offline).unwrap(),
            serde_json::to_value(&resolved).unwrap()
        );
        // Synthetic source keys are parser fixtures, not valid download keys.
        assert!(links::require_link_key(&resolved).is_err());
    }
}
