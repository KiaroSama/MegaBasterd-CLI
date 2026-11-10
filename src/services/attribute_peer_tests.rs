//! Actual image decoding, attribute encryption, TLS upload and node attachment.
#![allow(clippy::unwrap_used)]

use std::path::Path;

use image::GenericImageView;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::crypto::{keys, wire};
use crate::error::Error;
use crate::protocol::{
    api::Api,
    auth::Session,
    cloud::Cloud,
    test_peer::{self, Response},
};
use crate::services::attributes::{Attachment, attach};
use crate::transfers::control::Control;

const PNG: &[u8] = include_bytes!("../../tests/fixtures/media/1x1-green.png");
const HANDLE: [u8; 8] = [0, 1, 2, 3, 4, 5, 6, 7];

fn scratch() -> crate::test_support::TempDir {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/attribute-peers");
    std::fs::create_dir_all(&root).unwrap();
    crate::test_support::tempdir_in(root).unwrap()
}

fn api_reply(value: Value) -> Response {
    Response {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: serde_json::to_vec(&json!([value])).unwrap(),
    }
}

fn cloud(address: std::net::SocketAddr) -> Cloud {
    Cloud::new(
        Api::test_peer(address).unwrap(),
        Session {
            sid: "synthetic-session".into(),
            master_key: [9; 16],
            rsa_private_key: None,
            user_handle: "testuser".into(),
            email: "fixture@example.invalid".into(),
        },
    )
}

#[test]
fn real_png_thumbnail_is_encrypted_uploaded_and_attached_only_after_exact_handle() {
    assert_eq!(
        hex::encode(Sha256::digest(PNG)),
        "a236213916dd30bd771a233aa1d66381eabf335bf8885304b75a4e2e370d68ce"
    );
    for handle_bytes in [7usize, 8, 9] {
        let scratch = scratch();
        let source = scratch.path().join("green image.png");
        std::fs::write(&source, PNG).unwrap();
        let raw_key = wire::a32_to_bytes(&keys::pack_file_key(&[1; 16], &[2; 8], &[0, 0]).unwrap());
        let mut uploaded_length = None;
        let (_, calls) = test_peer::with_peer(
            |request| {
                assert_eq!(request.method, "POST");
                if request.path == "/attribute" {
                    assert!(!request.body.is_empty() && request.body.len().is_multiple_of(16));
                    uploaded_length = Some(request.body.len());
                    let plain = wire::aes_cbc_decrypt(&request.body, &[1; 16]).unwrap();
                    let end = plain
                        .windows(2)
                        .rposition(|bytes| bytes == [0xff, 0xd9])
                        .unwrap()
                        + 2;
                    assert!(plain[end..].iter().all(|&byte| byte == 0));
                    let image = image::load_from_memory(&plain[..end]).unwrap();
                    assert_eq!(image.dimensions(), (1, 1));
                    assert_eq!(image.color(), image::ColorType::Rgb8);
                    let pixel = image.to_rgb8().get_pixel(0, 0).0;
                    assert!(
                        pixel[0] <= 8 && pixel[1] >= 120 && pixel[2] <= 8,
                        "decrypted attribute did not retain the source green pixel"
                    );
                    return Some(Response {
                        status: 200,
                        headers: vec![],
                        body: (0..handle_bytes as u8).collect(),
                    });
                }
                assert!(request.path.starts_with("/cs?"));
                let commands: Value = serde_json::from_slice(&request.body).unwrap();
                assert_eq!(commands.as_array().unwrap().len(), 1);
                match commands[0]["a"].as_str().unwrap() {
                    "ufa" => {
                        assert!(commands[0].get("ssl").is_none());
                        assert_eq!(commands[0].as_object().unwrap().len(), 2);
                        let url = url::Url::parse(&format!("https://{}", request.headers["host"]))
                            .unwrap();
                        Some(api_reply(
                            json!({"p":format!("{}/attribute",url.origin().ascii_serialization())}),
                        ))
                    }
                    "pfa" => {
                        assert_eq!(handle_bytes, 8, "invalid attribute handle reached pfa");
                        assert_eq!(
                            commands[0],
                            json!({"a":"pfa","n":"AQIDBAUG",
                            "fa":format!("0*{}",wire::b64_url_encode(&HANDLE))})
                        );
                        Some(api_reply(json!(0)))
                    }
                    _ => panic!("unexpected media attribute action"),
                }
            },
            |address| {
                let mut cloud = cloud(address);
                let control = cloud.api.control.clone();
                let result = attach(&mut cloud, &source, "AQIDBAUG", &raw_key, &control);
                if handle_bytes == 8 {
                    let attachment = result.unwrap();
                    assert!(matches!(
                        &attachment,
                        Attachment::Attached { warning: None }
                    ));
                    assert_eq!(
                        serde_json::to_value(attachment).unwrap(),
                        json!({"status":"attached"})
                    );
                } else {
                    assert!(result.is_err());
                }
                assert_eq!(std::fs::read(&source).unwrap(), PNG);
            },
        );
        assert!(uploaded_length.is_some());
        assert_eq!(calls.len(), if handle_bytes == 8 { 3 } else { 2 });
        let ticket: Value = serde_json::from_slice(&calls[0].body).unwrap();
        assert_eq!(
            ticket[0]["s"].as_u64().unwrap(),
            uploaded_length.unwrap() as u64
        );
    }
}

#[test]
fn rejected_attachment_and_unsupported_or_canceled_inputs_never_claim_success() {
    let scratch = scratch();
    let source = scratch.path().join("green.png");
    std::fs::write(&source, PNG).unwrap();
    let raw_key = wire::a32_to_bytes(&keys::pack_file_key(&[1; 16], &[2; 8], &[0, 0]).unwrap());
    let (_, calls) = test_peer::with_peer(
        |request| {
            if request.path == "/attribute" {
                return Some(Response {
                    status: 200,
                    headers: vec![],
                    body: HANDLE.to_vec(),
                });
            }
            let commands: Value = serde_json::from_slice(&request.body).unwrap();
            match commands[0]["a"].as_str().unwrap() {
                "ufa" => Some(api_reply(
                    json!({"p":format!("https://{}/attribute",request.headers["host"])}),
                )),
                "pfa" => Some(api_reply(json!(-11))),
                _ => panic!("unexpected media action"),
            }
        },
        |address| {
            let mut cloud = cloud(address);
            let control = cloud.api.control.clone();
            assert!(matches!(
                attach(&mut cloud, &source, "AQIDBAUG", &raw_key, &control),
                Err(Error::Mega { code: -11, .. })
            ));
        },
    );
    assert_eq!(calls.len(), 3);
    let (_, calls) = test_peer::with_peer(
        |_| panic!("unsupported/canceled media contacted the API"),
        |address| {
            let mut cloud = cloud(address);
            let skipped = attach(
                &mut cloud,
                &scratch.path().join("missing.txt"),
                "AQIDBAUG",
                &raw_key,
                &Control::new(),
            )
            .unwrap();
            assert!(matches!(&skipped, Attachment::NotApplicable));
            assert_eq!(
                serde_json::to_value(skipped).unwrap(),
                json!({"status":"not_applicable"})
            );
            let control = Control::new();
            control.cancel();
            assert!(matches!(
                attach(&mut cloud, &source, "AQIDBAUG", &raw_key, &control),
                Err(Error::Canceled)
            ));
        },
    );
    assert!(calls.is_empty());
}

#[test]
fn upstream_thumbnail_retry_is_bounded_and_keeps_nonretryable_failures_and_cancellation_final() {
    use crate::transfers::control::Control;
    use std::{cell::Cell, time::Duration};
    let calls = Cell::new(0);
    let mut waits = Vec::new();
    let value = super::retry_upload(
        &Control::new(),
        || {
            calls.set(calls.get() + 1);
            if calls.get() < 3 {
                Err(Error::mega(-3))
            } else {
                Ok(42)
            }
        },
        |delay| {
            waits.push(delay);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(value, 42);
    assert_eq!(waits, [Duration::from_secs(1), Duration::from_secs(2)]);
    calls.set(0);
    let error = super::retry_upload::<()>(
        &Control::new(),
        || {
            calls.set(calls.get() + 1);
            Err(Error::Timeout)
        },
        |_| Ok(()),
    )
    .unwrap_err();
    assert!(matches!(error, Error::Timeout));
    assert_eq!(calls.get(), 5);
    calls.set(0);
    assert!(
        super::retry_upload::<()>(
            &Control::new(),
            || {
                calls.set(calls.get() + 1);
                Err(Error::protocol("invalid attribute handle"))
            },
            |_| panic!("malformed responses must not be retried")
        )
        .is_err()
    );
    assert_eq!(calls.get(), 1);
    let control = Control::new();
    control.cancel();
    assert!(matches!(
        super::retry_upload::<()>(&control, || panic!("sent after cancellation"), |_| Ok(())),
        Err(Error::Canceled)
    ));
}
