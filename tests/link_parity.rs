// SPDX-License-Identifier: GPL-3.0-or-later
#![allow(clippy::unwrap_used)]
use megabasterd_cli::protocol::links::{self, LinkType};
use serde_json::Value;
use std::sync::OnceLock;
fn vectors() -> &'static Value {
    static DATA: OnceLock<Value> = OnceLock::new();
    DATA.get_or_init(|| serde_json::from_str(include_str!("fixtures/link-vectors.json")).unwrap())
}
#[test]
fn modern_legacy_nested_and_third_party_grammar_matches_source() {
    let mut protected = links::ParsedLink::new(LinkType::PasswordProtected);
    protected.public_id = "ABC".into();
    let mut plain = links::ParsedLink::new(LinkType::File);
    plain.public_id = "DEF".into();
    assert!(protected.needs_password());
    assert!(!plain.needs_password());
    assert_eq!(
        links::normalize_link("  https://mega.nz/file/ABC#key  ").unwrap(),
        "https://mega.nz/file/ABC#key"
    );
    for vector in vectors()["links"].as_array().unwrap() {
        let input = vector["input"].as_str().unwrap();
        assert_eq!(
            serde_json::to_value(links::parse_link(input).unwrap()).unwrap(),
            vector["parsed"]
        );
        assert_eq!(
            links::normalize_link(input).unwrap(),
            vector["normalized"].as_str().unwrap()
        );
    }
    for input in [
        "",
        "not a link",
        "https://mega.nz.evil.invalid/file/x",
        "https://evilmega.nz/file/x",
        "https://mega.nz/file/x?unexpected",
    ] {
        assert!(links::parse_link(input).is_err());
    }
}
#[test]
fn exact_source_public_link_shapes_keep_literal_identifiers_keys_and_nested_node_selection() {
    for (input, kind, public_id, key, selected) in [
        (
            "https://mega.nz/file/ABC#KEY",
            LinkType::File,
            "ABC",
            "KEY",
            None,
        ),
        (
            "https://mega.nz/folder/ABC#KEY",
            LinkType::Folder,
            "ABC",
            "KEY",
            None,
        ),
        (
            "https://mega.nz/folder/ABC#KEY/file/XYZ",
            LinkType::FileInFolder,
            "ABC",
            "KEY",
            Some("XYZ"),
        ),
        (
            "https://mega.nz/folder/ABC#KEY/folder/SUB",
            LinkType::FolderInFolder,
            "ABC",
            "KEY",
            Some("SUB"),
        ),
        (
            "https://mega.nz/#!ABC!KEY",
            LinkType::File,
            "ABC",
            "KEY",
            None,
        ),
        (
            "https://mega.nz/#F!ABC!KEY",
            LinkType::Folder,
            "ABC",
            "KEY",
            None,
        ),
        (
            "https://mega.nz/#F!ABC@SUB!KEY",
            LinkType::FolderInFolder,
            "ABC",
            "KEY",
            Some("SUB"),
        ),
        (
            "https://mega.nz/#F!ABC!KEY!FILE",
            LinkType::FileInFolder,
            "ABC",
            "KEY",
            Some("FILE"),
        ),
        (
            "https://mega.nz/#F*FILE!FOLDER!KEY",
            LinkType::FileInFolder,
            "FOLDER",
            "KEY",
            Some("FILE"),
        ),
        (
            "https://mega.nz/#N!FILE!FOLDER!KEY",
            LinkType::FileInFolder,
            "FOLDER",
            "KEY",
            Some("FILE"),
        ),
        (
            "https://mega.nz/file/abc123#xyz",
            LinkType::File,
            "abc123",
            "xyz",
            None,
        ),
        (
            "https://mega.nz/folder/abc123#xyz",
            LinkType::Folder,
            "abc123",
            "xyz",
            None,
        ),
        (
            "https://mega.nz/folder/abc123#xyz/file/inner",
            LinkType::FileInFolder,
            "abc123",
            "xyz",
            Some("inner"),
        ),
        (
            "https://mega.nz/#!abc123!xyz",
            LinkType::File,
            "abc123",
            "xyz",
            None,
        ),
        (
            "https://mega.nz/#F!abc123!xyz",
            LinkType::Folder,
            "abc123",
            "xyz",
            None,
        ),
        (
            "https://mega.nz/file/MyFileID#MyKeyValue",
            LinkType::File,
            "MyFileID",
            "MyKeyValue",
            None,
        ),
        (
            "https://mega.nz/file/abc123#xyz/",
            LinkType::File,
            "abc123",
            "xyz",
            None,
        ),
    ] {
        let parsed = links::parse_link(input).unwrap();
        assert_eq!(parsed.kind, kind, "{input}");
        assert_eq!(parsed.public_id, public_id);
        assert_eq!(parsed.key.as_deref(), Some(key));
        assert_eq!(parsed.subpath.as_deref(), selected);
        assert_eq!(
            parsed.is_folder(),
            matches!(kind, LinkType::Folder | LinkType::FolderInFolder)
        );
        assert_eq!(
            parsed.is_file(),
            matches!(kind, LinkType::File | LinkType::FileInFolder)
        );
    }
    for invalid in [
        "not a url",
        "https://example.com/file/ABC#KEY",
        "https://example.com/file/abc",
    ] {
        assert!(links::parse_link(invalid).is_err());
    }
}

#[test]
fn exact_source_container_recognition_keeps_variants_and_payload_without_decoding() {
    // Independent standard-base64 encoding of the source's 32 X bytes.
    let blob = "WFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFg=";
    for variant in ["enc", "enc2", "fenc", "fenc2"] {
        let parsed = links::parse_link(&format!("mega://{variant}?{blob}")).unwrap();
        assert_eq!(parsed.kind, LinkType::EncryptedContainer);
        assert_eq!(parsed.container_variant.as_deref(), Some(variant));
        assert_eq!(parsed.container_blob.as_deref(), Some(blob));
    }
    let parsed = links::parse_link("mega://elc?abc_DEF,123").unwrap();
    assert_eq!(parsed.kind, LinkType::ElcContainer);
    assert_eq!(parsed.elc_blob.as_deref(), Some("abc_DEF,123"));
    for recognized in [
        "https://mega.nz/file/ABC#KEY",
        "https://mega.co.nz/folder/ABC#KEY",
        "mc://server.example/token",
        "mega://enc?xxx",
        "mega://fenc2?xxx",
        "mega://elc?xxx",
    ] {
        assert!(links::is_mega_url(recognized));
    }
    assert!(!links::is_mega_url("https://example.com/file"));
    let parsed = links::parse_link("mc://example.com/abcdef").unwrap();
    assert_eq!(parsed.kind, LinkType::Megacrypter);
    assert_eq!(parsed.crypter_server.as_deref(), Some("example.com"));
    assert_eq!(parsed.crypter_token.as_deref(), Some("abcdef"));
}

#[test]
fn public_keys_are_strict_at_boundary_and_file_in_folder_uses_folder_key() {
    for vector in vectors()["links"].as_array().unwrap() {
        let parsed = links::parse_link(vector["input"].as_str().unwrap()).unwrap();
        if let Some(expected) = parsed.expected_key_bytes() {
            if parsed.key.is_some() {
                assert_eq!(links::require_link_key(&parsed).unwrap().len(), expected);
            } else {
                assert!(links::require_link_key(&parsed).is_err());
            }
        }
    }
    let filekey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    for bad in [
        format!("{filekey},"),
        format!("{filekey}="),
        filekey[..filekey.len() - 1].to_owned(),
        format!("{filekey}+"),
    ] {
        let parsed = links::parse_link(&format!("https://mega.nz/file/TESTID#{bad}")).unwrap();
        assert!(links::require_link_key(&parsed).is_err());
    }
    let nested =
        links::parse_link("https://mega.nz/folder/FOLDER#AAECAwQFBgcICQoLDA0ODw/file/INNER")
            .unwrap();
    assert_eq!(nested.kind, LinkType::FileInFolder);
    assert_eq!(links::require_link_key(&nested).unwrap().len(), 16);
}
#[test]
fn offline_protected_and_encrypted_wrappers_resolve_to_source_and_upstream_fixtures() {
    for vector in vectors()["protected"].as_array().unwrap() {
        let parsed = links::parse_link(vector["input"].as_str().unwrap()).unwrap();
        let result =
            links::resolve_offline(&parsed, Some(vector["password"].as_str().unwrap())).unwrap();
        assert_eq!(
            result.kind,
            if vector["resolved"]["kind"] == "file" {
                LinkType::File
            } else {
                LinkType::Folder
            }
        );
        assert_eq!(
            megabasterd_cli::crypto::wire::b64_url_decode(&result.public_id).unwrap(),
            vec![0, 1, 2, 3, 4, 5]
        );
        assert_eq!(serde_json::to_value(result).unwrap(), vector["resolved"]);
        assert!(links::resolve_offline(&parsed, Some("wrong")).is_err());
        assert!(links::resolve_offline(&parsed, None).is_err());
    }
    for vector in vectors()["encrypted"].as_array().unwrap() {
        let parsed = links::parse_link(vector["input"].as_str().unwrap()).unwrap();
        let result = links::resolve_offline(&parsed, None).unwrap();
        assert_eq!(serde_json::to_value(result).unwrap(), vector["resolved"]);
    }
}
