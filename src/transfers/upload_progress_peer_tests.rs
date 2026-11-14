//! Resumed upload speed observes only new bytes through the real transfer and TLS peer.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::storage::transfer_state::TransferState;
use crate::terminal::progress::Status;

fn displayed_rate(progress: &Progress) -> f64 {
    let (rows, hidden) = progress.frame().unwrap();
    assert_eq!((rows.len(), hidden), (1, 0));
    let label = rows[0].split(" | ").nth(1).unwrap();
    let number = label.strip_suffix(" B/s").unwrap_or_else(|| {
        panic!("resumed upload displayed an inflated or nonnumeric rate: {label}")
    });
    number.parse().unwrap()
}

#[test]
fn actual_resumed_upload_rate_excludes_durable_bytes_and_sends_only_the_missing_tail() {
    let scratch = scratch();
    let source = source(scratch.path(), 131089);
    let states = scratch.path().join("private resumed state");
    let vault = Vault::new("synthetic progress passphrase");
    let canonical = std::fs::canonicalize(&source).unwrap();
    let binding = serde_json::to_string(&json!([
        canonical.to_string_lossy(),
        "fixture@example.invalid",
        "testuser",
        "target",
        NAME,
        Option::<&str>::None
    ]))
    .unwrap();
    let state_name = hex::encode(Sha256::digest(binding.as_bytes()));
    let state_path = states.join(format!("{state_name}.json"));
    let material = hex::decode("000102030405060708090a0b0c0d0e0f0001020304050607").unwrap();
    let mut state =
        TransferState::new("upload", &binding, &state_path, 131089, &material[..16]).unwrap();
    state.source_identity = Some(
        crate::transfers::upload::source_hash(
            &mut std::fs::File::open(&source).unwrap(),
            &Control::new(),
        )
        .unwrap(),
    );
    state.upload_url = Some(SLOT.into());
    state.sealed_upload_key = Some(
        vault
            .seal(&material, format!("upload:{state_name}").as_bytes())
            .unwrap(),
    );
    // Independent source oracle: tests/fixtures/transfers/vectors.json, first128KiB MAC.
    let first_mac: [u8; 16] = hex::decode("1f7ec6ce08f27461f268bf02cfe09156")
        .unwrap()
        .try_into()
        .unwrap();
    state.completed.insert(0, first_mac);
    States::new(&state_path).save(&state).unwrap();
    let progress = Progress::new(false);
    let item = progress.add(NAME, 131089).unwrap();
    progress.defer_completion(item).unwrap();
    let mut tail_seen = false;
    let mut registration_seen = false;
    let (uploaded, calls) = test_peer::with_peer(
        |request| {
            if request.path.starts_with("/native-peer-upload/") {
                assert!(!tail_seen, "resumed upload repeated an accepted chunk");
                tail_seen = true;
                assert_eq!(request.path, "/native-peer-upload/slot/131072");
                assert_eq!(request.body.len(), 17);
                assert_eq!(progress.snapshot(item).unwrap().completed, 131072);
                assert_eq!(displayed_rate(&progress), 0.0);
                let expected =
                    include_bytes!("../../tests/fixtures/transfers/ciphertext-131089.bin");
                assert_eq!(request.body.as_slice(), &expected[131072..]);
                return Some(Response {
                    status: 200,
                    headers: vec![],
                    body: TOKEN.as_bytes().to_vec(),
                });
            }
            assert!(tail_seen);
            assert!(!registration_seen);
            registration_seen = true;
            let value = command(request);
            assert_eq!(
                value["a"], "p",
                "resumed upload unnecessarily requested a fresh slot"
            );
            assert_eq!(value["n"][0]["h"], TOKEN);
            assert_eq!(progress.snapshot(item).unwrap().completed, 131089);
            let speed = displayed_rate(&progress);
            assert!(
                speed.is_finite() && speed > 0.0 && speed < 68.0,
                "rate was missing or counted resumed bytes: {speed}"
            );
            let saved = States::new(&state_path).load().unwrap().unwrap();
            assert_eq!(saved.completed.len(), 2);
            assert_eq!(saved.completed[&0], first_mac);
            assert!(saved.registration_started);
            Some(api(json!({"f":[{"h":"AQIDBAUG"}]})))
        },
        |address| {
            let mut cloud = cloud(address);
            // A real limiter reservation, not a blind fixture sleep, provides a500ms sample span.
            let limiter = RateLimiter::new(17.0 / 512.0).unwrap();
            let control = cloud.api.control.clone();
            upload(
                &mut cloud, &source, "target", None, 1, &states, &vault, true, None, &limiter,
                &progress, item, &control,
            )
            .unwrap()
        },
    );
    assert!(tail_seen && registration_seen);
    assert_eq!(calls.len(), 2);
    assert_eq!(
        (uploaded.handle.as_str(), uploaded.size),
        ("AQIDBAUG", 131089)
    );
    assert_eq!(progress.snapshot(item).unwrap().status, Status::Verifying);
    let saved = States::new(&state_path).load().unwrap().unwrap();
    assert_eq!(saved.completed.len(), 2);
    assert_eq!(saved.completed[&0], first_mac);
    assert_eq!(saved.registered_handle.as_deref(), Some("AQIDBAUG"));
    assert_eq!(
        std::fs::read(&source).unwrap(),
        (0..131089)
            .map(|i| ((13 * i + 7) % 256) as u8)
            .collect::<Vec<_>>()
    );
}
