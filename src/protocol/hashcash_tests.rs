//! Hashcash wire input, proof bounds and cancellation use the real solver.
#![allow(clippy::unwrap_used)]

use std::time::{Duration, Instant};

use super::*;

fn token() -> String {
    "QUFB".repeat(16)
}

#[test]
fn legacy_and_timestamped_challenges_preserve_the_same_token_and_threshold() {
    for header in [
        format!("1:255:{}", token()),
        format!("1:255:1731410499:{}", token()),
    ] {
        let challenge = Challenge::parse(&header).unwrap();
        assert_eq!(challenge.easiness, 255);
        assert_eq!(challenge.token, [b'A'; 48]);
        assert_eq!(challenge.threshold(), 0x7f00_0000);
    }
    for (easiness, threshold) in [(0, 8), (192, 0x0100_0000), (255, 0x7f00_0000)] {
        let challenge = Challenge::parse(&format!("1:{easiness}:{}", token())).unwrap();
        assert_eq!(challenge.threshold(), threshold);
    }
}

#[test]
fn malformed_hashcash_is_typed_bounded_and_never_echoes_the_header() {
    for (header, guidance) in [
        ("not-a-challenge".to_owned(), "Malformed"),
        (format!("1:nope:{}", token()), "easiness"),
        (format!("1:10000000000:{}", token()), "easiness"),
        (format!("1:1000000000000000:{}", token()), "easiness"),
        (format!("1:-1:{}", token()), "easiness"),
        (format!("1:256:{}", token()), "easiness"),
        (format!("0:192:{}", token()), "version"),
        (format!("2:192:{}", token()), "version"),
        (format!("999:192:{}", token()), "version"),
        (format!("-1:192:{}", token()), "version"),
        (
            format!("1:192:private-timestamp-sentinel:{}", token()),
            "timestamp",
        ),
        (format!("1:192:{}", "A".repeat(161)), "bound"),
        (format!("1:192:{}!", "A".repeat(128)), "token bound"),
        ("1:192:bad!".into(), "token"),
        ("1:192:QUFB".into(), "48"),
        (format!("1:192:1731410499:{}:extra", token()), "Malformed"),
    ] {
        let error = match Challenge::parse(&header) {
            Ok(_) => panic!("malformed challenge was accepted"),
            Err(error) => error,
        };
        assert!(matches!(&error, Error::Protocol(_)));
        assert!(error.to_string().contains(guidance));
        assert!(!error.to_string().contains(&token()));
        assert!(!error.to_string().contains("private-timestamp-sentinel"));
        assert_eq!(error.exit_code(), 1);
    }
}

#[test]
fn direct_construction_keeps_easiness_in_a_byte_and_every_shift_bounded() {
    for value in [10_000_000_000i64, -1] {
        assert!(u8::try_from(value).is_err());
    }
    for easiness in u8::MIN..=u8::MAX {
        let challenge = Challenge {
            easiness,
            token: [0; 48],
            timestamped: false,
        };
        assert!((8..=0x7f00_0000).contains(&challenge.threshold()));
    }
}

#[test]
fn an_oversized_token_is_refused_before_any_base64_decoder_is_called() {
    let mut header = vec![b'A'; 10_000_006];
    header[..6].copy_from_slice(b"1:192:");
    let error = match Challenge::parse_with(std::str::from_utf8(&header).unwrap(), |_| {
        panic!("base64 decoder was called on an unbounded token")
    }) {
        Ok(_) => panic!("oversized token was accepted"),
        Err(error) => error,
    };
    assert!(matches!(&error, Error::Protocol(_)));
    assert!(error.to_string().contains("token"));
    assert!(error.to_string().len() < 128);
    assert_eq!(error.exit_code(), 1);
}

#[test]
fn expired_or_canceled_solves_refuse_before_work_even_while_paused() {
    let challenge = Challenge::parse(&format!("1:255:{}", token())).unwrap();
    let expired = Instant::now();
    for paused in [false, true] {
        let control = Control::new();
        if paused {
            assert!(control.toggle_pause().unwrap());
        }
        assert!(matches!(
            challenge.solve(expired, &control),
            Err(Error::Timeout)
        ));
        control.cancel();
        let error = challenge
            .solve(Instant::now() + Duration::from_secs(1), &control)
            .unwrap_err();
        assert!(matches!(error, Error::Canceled));
        assert_eq!(error.exit_code(), 130);
    }
}

#[test]
fn a_paused_solve_expires_at_its_future_deadline_without_needing_a_resume() {
    let challenge = Challenge::parse(&format!("1:200:{}", "dHR0".repeat(16))).unwrap();
    let control = Control::new();
    for budget in [Duration::from_millis(25), Duration::from_millis(2500)] {
        assert!(control.toggle_pause().unwrap());
        let start = Instant::now();
        let deadline = start + budget;
        let error = challenge.solve(deadline, &control).unwrap_err();
        assert!(matches!(error, Error::Timeout));
        assert!(Instant::now() >= deadline);
        assert!(start.elapsed() < budget + Duration::from_secs(1));
        assert!(!control.toggle_pause().unwrap());
        assert!(control.checkpoint().is_ok());
    }
    let solution = challenge
        .solve(Instant::now() + Duration::from_millis(2500), &control)
        .unwrap();
    assert!(solution.starts_with("1:200:"));
}

#[test]
fn cancellation_and_expiry_inside_hashing_cannot_return_a_successful_nonce() {
    // The independent vector says nonce zero wins for this token if no cancellation intervenes.
    let challenge = Challenge::parse(&format!("1:255:{}", "AgIC".repeat(16))).unwrap();
    for canceled in [false, true] {
        for stop_at in [3, 1026] {
            let control = Control::new();
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut checkpoints = 0;
            let started = Instant::now();
            let error = challenge
                .solve_with(|| {
                    checkpoints += 1;
                    if checkpoints == stop_at {
                        if canceled {
                            control.cancel();
                        } else {
                            return control.checkpoint_until(Instant::now());
                        }
                    }
                    control.checkpoint_until(deadline)
                })
                .unwrap_err();
            assert!(if canceled {
                matches!(error, Error::Canceled)
            } else {
                matches!(error, Error::Timeout)
            });
            assert_eq!(checkpoints, stop_at);
            assert!(started.elapsed() < Duration::from_secs(10));
            if canceled {
                assert_eq!(error.exit_code(), 130);
            }
        }
    }
}

#[test]
fn proof_validation_and_both_solution_formats_match_independent_sha256_vectors() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/fixtures/hashcash-vectors.json")).unwrap();
    for vector in vectors["vectors"].as_array().unwrap() {
        let byte = u8::try_from(vector["token_byte"].as_u64().unwrap()).unwrap();
        let easiness = vector["easiness"].as_u64().unwrap();
        let token = b64_url_encode(&[byte; 48]);
        let challenge = Challenge::parse(&format!("1:{easiness}:{token}")).unwrap();
        let nonce: [u8; 4] = hex::decode(vector["nonce"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(
            challenge.threshold() as u64,
            vector["threshold"].as_u64().unwrap()
        );
        assert!(challenge.valid(nonce));
        if easiness == 192 {
            assert!(!challenge.valid([0; 4]));
            let solution = challenge
                .solve(Instant::now() + Duration::from_secs(30), &Control::new())
                .unwrap();
            let nonce = vector["nonce_b64"].as_str().unwrap();
            assert_eq!(solution, format!("1:192:{token}:{nonce}"));
            continue;
        }
        for timestamped in [false, true] {
            let header = if timestamped {
                format!("1:255:1731410499:{token}")
            } else {
                format!("1:255:{token}")
            };
            let challenge = Challenge::parse(&header).unwrap();
            let solution = challenge
                .solve(Instant::now() + Duration::from_secs(5), &Control::new())
                .unwrap();
            let nonce = vector["nonce_b64"].as_str().unwrap();
            assert_eq!(
                solution,
                if timestamped {
                    format!("1:{token}:{nonce}")
                } else {
                    format!("1:255:{token}:{nonce}")
                }
            );
        }
    }
}
