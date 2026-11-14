#![allow(clippy::unwrap_used)]

use super::*;
use crate::protocol::test_peer::{self, Response};

#[test]
fn raw_link_keys_refuse_truncation_and_junk_before_metadata_io_without_rejecting_valid_keys() {
    use crate::protocol::links;

    let good = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    let folder_key = "AAECAwQFBgcICQoLDA0ODw";
    let (_, calls) = test_peer::with_peer(
        |request| {
            assert!(request.path.starts_with("/cs?"));
            let command: Value = serde_json::from_slice(&request.body).unwrap();
            assert_eq!(command, json!([{"a":"g","g":1,"ssl":2,"p":"AAAAAAAA"}]));
            Some(Response {
                status: 200,
                headers: vec![("Content-Type".into(), "application/json".into())],
                body: serde_json::to_vec(
                    &json!([{"s":1024,"g":"https://cdn.example/file","at":""}]),
                )
                .unwrap(),
            })
        },
        |address| {
            let mut api = Api::test_peer(address).unwrap();
            let valid =
                links::parse_link(&format!("https://mega.nz/file/AAAAAAAA#{good}")).unwrap();
            let info = file(&mut api, &valid).unwrap();
            assert_eq!(&*info.raw_key, &(0u8..32).collect::<Vec<_>>());
            assert_eq!(
                crate::crypto::keys::unpack_file_key(&wire::bytes_to_a32(&info.raw_key))
                    .unwrap()
                    .aes_key
                    .len(),
                16
            );
            assert_eq!(info.size, 1024);
            assert_eq!(&*links::require_link_key(&valid).unwrap(), &*info.raw_key);

            let truncated =
                links::parse_link(&format!("https://mega.nz/file/AAAAAAAA#{}", &good[..42]))
                    .unwrap();
            let error = file(&mut api, &truncated).err().unwrap();
            assert!(matches!(&error, Error::Invalid(_)));
            assert_eq!(error.exit_code(), 2);
            assert!(error.to_string().contains("31 bytes"));
            assert!(error.to_string().contains("expected 32"));
            assert!(!error.to_string().contains(good));

            let truncated = links::parse_link(&format!(
                "https://mega.nz/folder/AAAAAAAA#{}/file/BBBBBBBB",
                &folder_key[..20]
            ))
            .unwrap();
            let error = folder(&mut api, &truncated).err().unwrap();
            assert!(matches!(&error, Error::Invalid(_)));
            assert_eq!(error.exit_code(), 2);
            assert!(error.to_string().contains("15 bytes"));
            assert!(error.to_string().contains("expected 16"));
            assert!(!error.to_string().contains(folder_key));

            for junk in [
                format!("{good},,,,"),
                format!("{},{}", &good[..10], &good[10..]),
                format!(",{good}"),
                format!("{good} spaced"),
            ] {
                let link =
                    links::parse_link(&format!("https://mega.nz/file/AAAAAAAA#{junk}")).unwrap();
                let error = file(&mut api, &link).err().unwrap();
                assert!(matches!(&error, Error::Invalid(_)));
                assert_eq!(error.code(), "invalid_input");
                assert_eq!(error.exit_code(), 2);
                assert!(error.to_string().contains("URL-safe base64"));
                assert!(!error.to_string().contains(&junk));
            }
            assert_eq!(
                &*links::require_link_key(&valid).unwrap(),
                &(0u8..32).collect::<Vec<_>>()
            );
        },
    );
    assert_eq!(
        calls.len(),
        1,
        "invalid keys must not request file or folder metadata"
    );
}

#[test]
fn refreshed_megacrypter_ticket_uses_its_original_service_not_the_public_mega_api() {
    let (_, calls) = test_peer::with_peer(
        |request| {
            assert_eq!(request.method, "POST");
            assert_eq!(request.path, "/api", "source refresh switched to MEGA cs");
            let command: Value = serde_json::from_slice(&request.body).unwrap();
            let link = command["link"].as_str().unwrap();
            assert!(link.starts_with("mc://testserver.com:") && link.ends_with("/token"));
            assert_eq!(command["m"], "dl");
            assert_eq!(command["noexpire"], "synthetic-expiry");
            assert_eq!(
                command.as_object().unwrap().len(),
                3,
                "source key/SID leaked to link service"
            );
            Some(Response {
                status: 200,
                headers: vec![("Content-Type".into(), "application/json".into())],
                body: serde_json::to_vec(&json!({"url":"https://cdn.example/fresh"})).unwrap(),
            })
        },
        |address| {
            let mut api = Api::test_peer(address).unwrap();
            api.set_session("account-session-must-not-leak");
            let link = super::super::links::parse_link(&format!(
                "mc://testserver.com:{}/token",
                address.port()
            ))
            .unwrap();
            let metadata = super::super::containers::decrypt_megacrypter_info(
                &json!({"name":"folder/OAD -  09v2.mkv","size":17,
            "key":wire::b64_url_encode(&[0;32]),"expire":"noexpire#synthetic-expiry"}),
                None,
            )
            .unwrap();
            let file =
                FileInfo::megacrypter(link, metadata, "https://cdn.example/old".into()).unwrap();
            assert_eq!(
                refresh(&mut api, &file).unwrap(),
                "https://cdn.example/fresh"
            );
        },
    );
    assert_eq!(calls.len(), 1);
}

#[test]
fn public_file_without_optional_attributes_keeps_handle_name_and_rejects_present_malformed_attributes()
 {
    for (attributes, accepted) in [
        (None, true),
        (Some(Value::Null), true),
        (Some(json!("")), true),
        (Some(json!(17)), false),
        (Some(json!("not!base64")), false),
    ] {
        let (result, calls) = test_peer::with_peer(
            |request| {
                assert!(request.path.starts_with("/cs?"));
                let envelope: Value = serde_json::from_slice(&request.body).unwrap();
                assert_eq!(envelope, json!([{"a":"g","g":1,"ssl":2,"p":"FILEID"}]));
                let mut ticket = json!({"g":"https://example.invalid/file","s":1});
                if let Some(value) = &attributes {
                    ticket["at"] = value.clone();
                }
                Some(Response {
                    status: 200,
                    headers: vec![("Content-Type".into(), "application/json".into())],
                    body: serde_json::to_vec(&json!([ticket])).unwrap(),
                })
            },
            |address| {
                let mut api = Api::test_peer(address).unwrap();
                let link = super::super::links::parse_link(
                    "https://mega.nz/file/FILEID#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                )
                .unwrap();
                file(&mut api, &link)
            },
        );
        assert_eq!(calls.len(), 1);
        if accepted {
            let info = result.unwrap();
            assert_eq!(info.name, "FILEID");
            assert_eq!(info.size, 1);
            assert_eq!(info.raw_key.len(), 32);
        } else {
            assert!(result.is_err());
        }
    }
}

#[test]
fn public_and_folder_ticket_refreshes_preserve_wire_handle_and_source_size() {
    for folder in [false, true] {
        let (_, calls) = test_peer::with_peer(
            |request| {
                assert!(request.path.starts_with("/cs?"));
                let envelope: Value = serde_json::from_slice(&request.body).unwrap();
                let command = &envelope[0];
                assert_eq!(command["a"], "g");
                assert_eq!(command["g"], 1);
                assert_eq!(command["ssl"], 2);
                assert_eq!(
                    command[if folder { "n" } else { "p" }],
                    if folder { "child" } else { "public" }
                );
                let url =
                    url::Url::parse(&format!("https://testserver.com{}", request.path)).unwrap();
                assert_eq!(
                    url.query_pairs()
                        .any(|(key, value)| key == "n" && value == "public"),
                    folder
                );
                Some(Response {
                    status: 200,
                    headers: vec![("Content-Type".into(), "application/json".into())],
                    body: serde_json::to_vec(&json!([{"s":17,"g":"https://cdn.example/fresh"}]))
                        .unwrap(),
                })
            },
            |address| {
                let mut api = Api::test_peer(address).unwrap();
                let file = FileInfo {
                    name: "fixture".into(),
                    size: 17,
                    raw_key: Zeroizing::new(vec![0; 32]),
                    url: "https://cdn.example/old".into(),
                    handle: "child".into(),
                    public_id: "public".into(),
                    source: if folder {
                        DownloadSource::Folder
                    } else {
                        DownloadSource::Public
                    },
                };
                assert_eq!(
                    refresh(&mut api, &file).unwrap(),
                    "https://cdn.example/fresh"
                );
            },
        );
        assert_eq!(calls.len(), 1);
    }
}
