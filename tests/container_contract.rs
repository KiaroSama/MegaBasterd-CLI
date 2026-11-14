// SPDX-License-Identifier: GPL-3.0-or-later
#![allow(clippy::unwrap_used)]
use megabasterd_cli::protocol::{containers, links};
use serde_json::{Value, json};
fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/link-vectors.json")).unwrap()
}
#[test]
fn elc_raw_and_bounded_gzip_envelopes_and_local_decrypt_match_source() {
    for vector in fixture()["elc"].as_array().unwrap() {
        let parsed = links::parse_link(vector["input"].as_str().unwrap()).unwrap();
        let payload = containers::decode_elc_payload(&parsed).unwrap();
        assert_eq!(
            payload.encrypted_links,
            hex::decode(vector["encrypted_links"].as_str().unwrap()).unwrap()
        );
        assert_eq!(payload.service_url, vector["service_url"].as_str().unwrap());
        assert_eq!(payload.data_token, vector["data_token"].as_str().unwrap());
        assert_eq!(
            serde_json::to_value(
                containers::decrypt_elc_links(&payload, vector["decrypt_key"].as_str().unwrap())
                    .unwrap()
            )
            .unwrap(),
            vector["links"]
        );
    }
    let mut empty = links::ParsedLink::new(links::LinkType::ElcContainer);
    for blob in ["", "AA", "uQAAAAA", "cA"] {
        empty.elc_blob = Some(blob.into());
        assert!(containers::decode_elc_payload(&empty).is_err());
    }
    let data = fixture();
    for name in ["oversized", "truncated"] {
        empty.elc_blob = Some(data["malformed_gzip"][name].as_str().unwrap().into());
        assert!(containers::decode_elc_payload(&empty).is_err());
    }
}
#[test]
fn elc_inflation_and_compressed_input_guards_distinguish_corruption_from_size_refusal() {
    use megabasterd_cli::{crypto::wire, error::Error};
    use std::io::Write;

    let decode = |bytes: &[u8]| {
        let parsed =
            links::parse_link(&format!("mega://elc?{}", wire::b64_url_encode(bytes))).unwrap();
        containers::decode_elc_payload(&parsed)
    };
    let data = fixture();
    let bomb = links::parse_link(&format!(
        "mega://elc?{}",
        data["malformed_gzip"]["oversized"].as_str().unwrap()
    ))
    .unwrap();
    assert!(bomb.elc_blob.as_ref().unwrap().len() < 100_000);
    assert!(matches!(containers::decode_elc_payload(&bomb),
        Err(Error::Invalid(message)) if message == "ELC envelope expands beyond 8 MiB"));

    let mut oversized = vec![0; containers::MAX_ELC_COMPRESSED_BYTES + 2];
    oversized[0] = 0x70;
    assert!(matches!(decode(&oversized), Err(Error::Invalid(message))
        if message == "Compressed ELC envelope exceeds 1 MiB"));
    assert!(
        matches!(decode(b"\x70not gzip at all"), Err(Error::Invalid(message))
        if message == "Corrupt or truncated gzip ELC envelope")
    );

    let service = b"https://elc.example/api";
    let mut inner = 0u32.to_le_bytes().to_vec();
    inner.extend((service.len() as u16).to_le_bytes());
    inner.extend(service);
    inner.extend(3u16.to_le_bytes());
    inner.extend(b"tok");
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&inner).unwrap();
    let mut envelope = vec![0x70];
    envelope.extend(encoder.finish().unwrap());
    let payload = decode(&envelope).unwrap();
    assert!(payload.encrypted_links.is_empty());
    assert_eq!(payload.service_url, "https://elc.example/api");
    assert_eq!(payload.data_token, "tok");
}

#[test]
fn megacrypter_password_check_precedes_metadata_and_url_decryption() {
    let data = fixture();
    let vector = &data["megacrypter"];
    let info = containers::decrypt_megacrypter_info(
        &vector["body"],
        Some(vector["password"].as_str().unwrap()),
    )
    .unwrap();
    assert_eq!(info.raw, vector["decrypted"]);
    assert_eq!(info.pass_hash.as_deref(), vector["pass_hash"].as_str());
    assert_eq!(info.name.as_deref(), Some("folder/نام.mkv"));
    assert_eq!(info.size, Some(1234));
    assert_eq!(
        containers::decrypt_megacrypter_download_url(&vector["download_response"], &info).unwrap(),
        vector["download_url"].as_str().unwrap()
    );
    assert!(containers::decrypt_megacrypter_info(&vector["body"], Some("wrong")).is_err());
    assert!(
        containers::decrypt_megacrypter_info(&json!({"pass":"1000000000000000#a#b#c"}), Some("x"))
            .is_err()
    );
    assert!(containers::decrypt_megacrypter_info(&json!({"pass":3}), Some("x")).is_err());
    assert!(
        containers::decrypt_megacrypter_download_url(&json!({"url":"garbage"}), &info).is_err()
    );
}
#[test]
fn megacrypter_iteration_bounds_refuse_before_derivation_and_descriptor_types_stay_strict() {
    use megabasterd_cli::error::Error;
    use std::time::{Duration, Instant};

    for power in [1_000_000_000, 18, 30] {
        let start = Instant::now();
        let result = containers::decrypt_megacrypter_info(
            &json!({"pass":format!("{power}#a#b#c")}),
            Some("secret"),
        );
        assert!(
            matches!(result, Err(Error::Invalid(message)) if message == "MegaCrypter requests too many password iterations")
        );
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "untrusted exponent reached password derivation"
        );
    }
    assert!(
        matches!(containers::decrypt_megacrypter_info(&json!({"pass":12345}), Some("secret")), Err(Error::Invalid(message)) if message == "Malformed MegaCrypter password descriptor")
    );
}

#[test]
fn unprotected_megacrypter_metadata_accepts_documented_false_without_accepting_other_types() {
    for descriptor in [Value::Null, json!(""), json!(false)] {
        let body = json!({"name":"plain.bin","size":17,"key":"KEY","pass":descriptor});
        let info = containers::decrypt_megacrypter_info(&body, None).unwrap();
        assert_eq!(info.name.as_deref(), Some("plain.bin"));
        assert_eq!(info.size, Some(17));
        assert_eq!(info.key.as_deref(), Some("KEY"));
        assert!(info.pass_hash.is_none());
        assert_eq!(info.raw, body);
    }
    for descriptor in [json!(true), json!(12345), json!([]), json!({})] {
        assert!(matches!(
            containers::decrypt_megacrypter_info(&json!({"pass":descriptor}), None),
            Err(megabasterd_cli::error::Error::Invalid(message))
                if message == "Malformed MegaCrypter password descriptor"
        ));
    }
}

#[test]
fn dlc_request_and_offline_service_key_reply_match_source() {
    let data = fixture();
    let vector = &data["dlc"];
    let request = containers::parse_dlc_request(vector["data"].as_str().unwrap()).unwrap();
    assert_eq!(request.id, "A".repeat(88));
    assert_eq!(
        serde_json::to_value(
            containers::decrypt_dlc_response(&request, vector["key_response"].as_str().unwrap())
                .unwrap()
        )
        .unwrap(),
        vector["links"]
    );
    assert!(containers::parse_dlc_request("short").is_err());
    assert!(containers::decrypt_dlc_response(&request, "<no-key/>").is_err());
}
