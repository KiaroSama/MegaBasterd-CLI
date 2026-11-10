//! Supplied limiter ownership across actual download and upload transfer interfaces.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::{
    protocol::metadata::{DownloadSource, FileInfo},
    transfers::{
        control::observe_limiters,
        download::{DownloadOptions, download},
    },
};

#[test]
fn two_downloads_and_two_uploads_acquire_the_same_supplied_limiter() {
    let scratch = scratch();
    let vectors: Value =
        serde_json::from_str(include_str!("../../tests/fixtures/transfers/vectors.json")).unwrap();
    let vector = &vectors["vectors"][1];
    assert_eq!(vector["size"], 17);
    let raw_key = hex::decode(vector["raw_key"].as_str().unwrap()).unwrap();
    let plaintext: Vec<_> = (0..17).map(|i| ((13 * i + 7) % 256) as u8).collect();
    let ciphertext = include_bytes!("../../tests/fixtures/transfers/ciphertext-17.bin");
    let mut sources = Vec::new();
    for name in ["first source", "second source"] {
        let directory = scratch.path().join(name);
        std::fs::create_dir(&directory).unwrap();
        sources.push(source(&directory, 17));
    }
    let vault = Vault::new("synthetic supplied-limiter vault");
    let progress = Progress::new(false);
    let options = DownloadOptions {
        workers: 1,
        verify: true,
        overwrite: false,
        resume: true,
        keep_state: true,
        quota_wait: 0,
        quota_attempts: 1,
    };
    let (acquired, acquisitions) = std::sync::mpsc::sync_channel(4);
    let limiter = observe_limiters(acquired, || RateLimiter::new(1024.0)).unwrap();
    let expected_limiter = std::ptr::from_ref(&limiter) as usize;
    let mut uploaded_bodies = Vec::new();
    let mut registered = 0usize;
    let mut downloads = 0usize;
    let ((), calls) = test_peer::with_peer(
        |request| {
            if request.path == "/cdn" {
                assert_eq!(request.method, "GET");
                assert!(request.body.is_empty());
                assert_eq!(request.headers["range"], "bytes=0-16");
                downloads += 1;
                assert!(downloads <= 2);
                return Some(Response {
                    status: 206,
                    headers: vec![("Content-Range".into(), "bytes 0-16/17".into())],
                    body: ciphertext.to_vec(),
                });
            }
            if request.path == "/native-peer-upload/slot/0" {
                assert_eq!(request.method, "POST");
                assert_eq!(request.body.len(), 17);
                uploaded_bodies.push(request.body.clone());
                assert!(uploaded_bodies.len() <= 2);
                return Some(Response {
                    status: 200,
                    headers: vec![],
                    body: TOKEN.as_bytes().to_vec(),
                });
            }
            let command = command(request);
            Some(api(match command["a"].as_str().unwrap() {
                "u" => {
                    assert_eq!(command["s"], 17);
                    json!({"p":SLOT})
                }
                "p" => {
                    assert_eq!(command["t"], "target");
                    assert_eq!(command["n"].as_array().unwrap().len(), 1);
                    let node = &command["n"][0];
                    assert_eq!(node["h"], TOKEN);
                    assert_eq!(node["t"], 0);
                    let raw = wire::aes_key_wrap_decrypt(
                        &wire::b64_url_decode(node["k"].as_str().unwrap()).unwrap(),
                        &MASTER,
                    )
                    .unwrap();
                    assert_eq!(raw.len(), 32);
                    let key = keys::unpack_file_key(&wire::bytes_to_a32(&raw)).unwrap();
                    assert_eq!(
                        wire::ctr_crypt_at_offset(
                            key.aes_key.as_slice(),
                            &key.nonce,
                            0,
                            &uploaded_bodies[registered],
                        )
                        .unwrap(),
                        plaintext
                    );
                    let mac =
                        chunks::chunk_mac(&plaintext, key.aes_key.as_slice(), &key.nonce).unwrap();
                    assert_eq!(
                        key.mac,
                        chunks::condense_mac(
                            &chunks::combine_chunk_macs(&[mac], key.aes_key.as_slice()).unwrap()
                        )
                        .unwrap()
                    );
                    assert_eq!(
                        wire::decrypt_attributes(
                            &wire::b64_url_decode(node["a"].as_str().unwrap()).unwrap(),
                            key.aes_key.as_slice(),
                        )
                        .unwrap()["n"],
                        NAME
                    );
                    registered += 1;
                    json!({"f":[{"h":"FILE0001"}]})
                }
                _ => panic!("supplied-limiter transfer sent an unrelated API action"),
            }))
        },
        |address| {
            for index in 0..2 {
                let api = Api::test_peer(address).unwrap();
                let control = api.control.clone();
                let item = progress.add(NAME, 17).unwrap();
                let destination = scratch.path().join(format!("download {index}.bin"));
                let downloaded = download(
                    api,
                    FileInfo {
                        name: NAME.into(),
                        size: 17,
                        raw_key: zeroize::Zeroizing::new(raw_key.clone()),
                        url: format!("https://testserver.com:{}/cdn", address.port()),
                        handle: "FILE0001".into(),
                        public_id: "FILE0001".into(),
                        source: DownloadSource::Public,
                    },
                    &destination,
                    &scratch.path().join("private download states"),
                    &options,
                    &limiter,
                    &progress,
                    item,
                    &control,
                )
                .unwrap();
                assert_eq!(downloaded, destination);
                let bytes = std::fs::read(downloaded).unwrap();
                assert_eq!(bytes, plaintext);
                assert_eq!(
                    hex::encode(Sha256::digest(&bytes)),
                    vector["plaintext_sha256"]
                );
            }
            for source in &sources {
                let mut cloud = cloud(address);
                let control = cloud.api.control.clone();
                let item = progress.add(NAME, 17).unwrap();
                let uploaded = upload(
                    &mut cloud,
                    source,
                    "target",
                    None,
                    1,
                    &scratch.path().join("private upload states"),
                    &vault,
                    false,
                    None,
                    &limiter,
                    &progress,
                    item,
                    &control,
                )
                .unwrap();
                assert_eq!((uploaded.handle.as_str(), uploaded.size), ("FILE0001", 17));
                assert_eq!(uploaded.name, NAME);
                assert_eq!(std::fs::read(source).unwrap(), plaintext);
                uploaded.acknowledge().unwrap();
            }
        },
    );
    assert_eq!((downloads, registered, uploaded_bodies.len()), (2, 2, 2));
    assert_eq!(calls.len(), 8);
    let acquired: Vec<_> = acquisitions.try_iter().collect();
    assert_eq!(acquired, vec![(expected_limiter, 17); 4]);
}
