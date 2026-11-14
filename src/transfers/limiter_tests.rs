//! Rate reservations use the real scheduler; only time and waiting vary in virtual cases.
#![allow(clippy::unwrap_used)]

use std::{cell::Cell, sync::mpsc, time::Duration};

use super::*;

#[test]
fn oversized_download_and_upload_reservations_finish_at_the_configured_rate() {
    for (kbps, bytes, expected) in [
        (1.0, 4096, Duration::from_secs(4)),
        (10.0, 64 * 1024, Duration::from_millis(6400)),
        (64.0, 1024 * 1024, Duration::from_secs(16)),
    ] {
        let limiter = RateLimiter::new(kbps).unwrap();
        let start = Instant::now();
        let now = Cell::new(start);
        let waits = Cell::new(0);
        limiter
            .acquire_with(
                bytes,
                &Control::new(),
                || now.get(),
                |duration| {
                    assert_eq!(duration, expected);
                    waits.set(waits.get() + 1);
                    now.set(now.get().checked_add(duration).unwrap());
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(waits.get(), 1);
        assert_eq!(now.get().duration_since(start), expected);
        // A completed reservation cannot leave debt that blocks the next block forever.
        limiter
            .acquire_with(
                bytes,
                &Control::new(),
                || now.get(),
                |duration| {
                    assert_eq!(duration, expected);
                    Ok(())
                },
            )
            .unwrap();
    }
}

#[test]
fn unlimited_and_zero_bytes_never_wait_but_still_observe_cancellation() {
    for (kbps, bytes) in [(0.0, 1_000_000_000), (1.0, 0)] {
        let limiter = RateLimiter::new(kbps).unwrap();
        let control = Control::new();
        for canceled in [false, true] {
            if canceled {
                control.cancel();
            }
            let result = limiter.acquire_with(
                bytes,
                &control,
                || panic!("unlimited or empty acquisition requested a clock"),
                |_| panic!("unlimited or empty acquisition waited"),
            );
            if canceled {
                let error = result.unwrap_err();
                assert!(matches!(error, Error::Canceled));
                assert_eq!(error.exit_code(), 130);
            } else {
                result.unwrap();
            }
        }
    }
}

#[test]
fn unsupported_reservation_does_not_poison_the_next_valid_deadline() {
    let limiter = RateLimiter::new(1.0 / 1024.0).unwrap();
    let now = Instant::now();
    let error = limiter
        .acquire_with(
            usize::MAX,
            &Control::new(),
            || now,
            |_| panic!("overflowing reservation reached a wait"),
        )
        .unwrap_err();
    assert!(matches!(error, Error::Invalid(_)));
    limiter
        .acquire_with(
            1,
            &Control::new(),
            || now,
            |duration| {
                assert_eq!(duration, Duration::from_secs(1));
                Ok(())
            },
        )
        .unwrap();
}

#[test]
fn four_consumers_share_the_public_aggregate_rate_and_reap_their_workers() {
    struct CancelOnDrop(Control);
    impl Drop for CancelOnDrop {
        fn drop(&mut self) {
            self.0.cancel();
        }
    }

    let limiter = RateLimiter::new(2048.0).unwrap();
    let control = Control::new();
    let (finished, completion) = mpsc::sync_channel(4);
    let start = Instant::now();
    let deadline = start + Duration::from_millis(4750);
    std::thread::scope(|scope| {
        let mut workers = Vec::new();
        for _ in 0..2 {
            let finished = finished.clone();
            let limiter = &limiter;
            let control = &control;
            workers.push(scope.spawn(move || {
                for _ in 0..2 {
                    let result = limiter.acquire(512 * 1024, control);
                    let failed = result.is_err();
                    finished.try_send(result).unwrap();
                    if failed {
                        break;
                    }
                }
            }));
        }
        drop(finished);
        // Declared after the workers: cancel before the scope joins on timeout or assertion unwind.
        let _cancel = CancelOnDrop(control.clone());
        for _ in 0..4 {
            completion
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .unwrap()
                .unwrap();
        }
        let elapsed = start.elapsed();
        // No native burst: 2MiB at2MiB/s needs1s. Independent worker budgets finish in0.5s.
        assert!(elapsed >= Duration::from_millis(900), "{elapsed:?}");
        assert!(elapsed <= Duration::from_millis(4750), "{elapsed:?}");
        for worker in workers {
            worker.join().unwrap();
        }
    });
    assert!(control.is_canceled());
}
