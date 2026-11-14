//! The actual zero-byte download publishes collision-safe names and only explicit overwrites.
#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn empty_download_preserves_existing_bytes_unless_overwrite_and_uses_requested_fresh_name() {
    let fixture = Fixture::new(0);
    for (requested, existing, overwrite, expected) in [
        ("f.bin", true, false, "f (1).bin"),
        ("f.bin", true, true, "f.bin"),
        ("f.bin", false, false, "f.bin"),
        ("fresh.bin", false, false, "fresh.bin"),
    ] {
        let scratch = scratch();
        let destination = scratch.path().join(requested);
        let states = scratch.path().join("private state");
        if existing {
            std::fs::write(&destination, b"original-keepme").unwrap();
        }
        let ((), calls) = test_peer::with_peer(
            |_| panic!("empty file attempted a CDN request"),
            |address| {
                let progress = Progress::new(false);
                let item = progress.add("empty file", 0).unwrap();
                let mut configured = options(true);
                configured.overwrite = overwrite;
                let result = download(
                    Api::test_peer(address).unwrap(),
                    fixture.info(address),
                    &destination,
                    &states,
                    &configured,
                    &RateLimiter::new(0.0).unwrap(),
                    &progress,
                    item,
                    &Control::new(),
                )
                .unwrap();
                assert_eq!(result, destination.with_file_name(expected));
                assert_eq!(std::fs::read(&result).unwrap(), b"");
                if existing && !overwrite {
                    assert_eq!(std::fs::read(&destination).unwrap(), b"original-keepme");
                }
                assert!(
                    States::new(state_path(&states, &result))
                        .load()
                        .unwrap()
                        .is_none()
                );
            },
        );
        assert!(calls.is_empty());
    }
}

#[test]
fn forced_proxy_refusal_is_final_before_any_download_request_or_completed_chunk() {
    for empty_pool in [false, true] {
        let fixture = Fixture::new(17);
        let scratch = scratch();
        let destination = scratch.path().join("refused.bin");
        let states = scratch.path().join("private state");
        let ((), calls) = test_peer::with_peer(
            |_| panic!("forced proxy refusal sent a direct request"),
            |address| {
                let mut api = Api::test_peer(address).unwrap();
                api.transport.routing.force = true;
                if empty_pool {
                    api.transport.routing.pool =
                        Some(crate::storage::proxies::Pool::new(vec![], vec![], None).unwrap());
                }
                let progress = Progress::new(false);
                let item = progress.add("refused", 17).unwrap();
                let error = download(
                    api,
                    fixture.info(address),
                    &destination,
                    &states,
                    &options(false),
                    &RateLimiter::new(0.0).unwrap(),
                    &progress,
                    item,
                    &Control::new(),
                )
                .unwrap_err();
                assert!(
                    matches!(&error,Error::Protocol(message) if message.contains("direct connection was refused"))
                );
                assert!(!error.retryable_network());
                assert!(!destination.exists());
                let saved = States::new(state_path(&states, &destination))
                    .load()
                    .unwrap()
                    .unwrap();
                assert!(saved.completed.is_empty());
                assert_eq!(progress.snapshot(item).unwrap().completed, 0);
            },
        );
        assert!(calls.is_empty());
    }
}
