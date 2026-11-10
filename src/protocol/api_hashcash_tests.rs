//! The real API retry loop shares one proof deadline; clock and proof work are external seams.
#![allow(clippy::unwrap_used)]

use std::{cell::Cell, time::Duration};

use super::*;

fn challenge() -> Challenge {
    Challenge::parse(&format!("1:200:{}", "dHR0".repeat(16))).unwrap()
}

#[test]
fn each_challenge_receives_the_same_deadline_and_only_the_remaining_budget() {
    let start = Instant::now();
    let elapsed = Cell::new(Duration::ZERO);
    let mut deadlines = Vec::new();
    let mut remaining = Vec::new();
    let mut exchanges = 0;
    let error = tests::api()
        .request_with_hashcash(
            json!({"a":"ug"}),
            &[],
            |_, headers, _, _| {
                exchanges += 1;
                if exchanges == 1 {
                    assert!(!headers.contains_key("X-Hashcash"));
                } else {
                    assert_eq!(headers["X-Hashcash"], "synthetic-proof");
                    assert!(headers["X-Hashcash"].is_sensitive());
                }
                Ok(Exchange::Challenge(challenge()))
            },
            |_| panic!("challenge rejection used transport backoff"),
            (
                || start + elapsed.get(),
                |_, deadline, _| {
                    deadlines.push(deadline);
                    remaining.push(deadline.saturating_duration_since(start + elapsed.get()));
                    elapsed.set(elapsed.get() + Duration::from_secs(10));
                    Ok("synthetic-proof".into())
                },
            ),
        )
        .unwrap_err();
    assert!(matches!(error, Error::Timeout));
    assert_eq!(exchanges, 3);
    assert_eq!(deadlines, [start + Duration::from_secs(30); 2]);
    assert_eq!(
        remaining,
        [Duration::from_secs(30), Duration::from_secs(20)]
    );
    assert_eq!(elapsed.get(), Duration::from_secs(20));
    assert!(remaining.iter().all(|time| !time.is_zero()));
}

#[test]
fn a_solver_that_consumes_the_budget_cannot_send_a_late_solution_or_restart_the_clock() {
    for overdue in [false, true] {
        let start = Instant::now();
        let elapsed = Cell::new(Duration::ZERO);
        let mut exchanges = 0;
        let mut offered = Vec::new();
        let error = tests::api()
            .request_with_hashcash(
                json!({"a":"ug"}),
                &[],
                |_, _, _, _| {
                    exchanges += 1;
                    Ok(Exchange::Challenge(challenge()))
                },
                |_| panic!("budget exhaustion used transport backoff"),
                (
                    || start + elapsed.get(),
                    |_, deadline, _| {
                        let remaining = deadline.saturating_duration_since(start + elapsed.get());
                        assert!(!remaining.is_zero());
                        offered.push(remaining);
                        assert_eq!(deadline, start + Duration::from_secs(30));
                        elapsed.set(
                            elapsed.get() + remaining + Duration::from_secs(u64::from(overdue)),
                        );
                        Ok("late-proof".into())
                    },
                ),
            )
            .unwrap_err();
        assert!(matches!(error, Error::Timeout));
        assert_eq!(exchanges, 1);
        assert_eq!(offered, [Duration::from_secs(30)]);
        assert!(offered.iter().copied().sum::<Duration>() <= Duration::from_secs(30));
        assert_eq!(
            elapsed.get(),
            Duration::from_secs(if overdue { 31 } else { 30 })
        );
    }
}

#[test]
fn an_expired_challenge_never_starts_the_solver_and_cancellation_stays_cancellation() {
    for canceled in [false, true] {
        let start = Instant::now();
        let elapsed = Cell::new(Duration::ZERO);
        let mut api = tests::api();
        let control = api.control.clone();
        let error = api
            .request_with_hashcash(
                json!({"a":"ug"}),
                &[],
                |_, _, _, _| {
                    if canceled {
                        control.cancel();
                    } else {
                        elapsed.set(Duration::from_secs(30));
                    }
                    Ok(Exchange::Challenge(challenge()))
                },
                |_| panic!("expired challenge used transport backoff"),
                (
                    || start + elapsed.get(),
                    |_, _, _| panic!("solver started without usable time/control"),
                ),
            )
            .unwrap_err();
        assert!(if canceled {
            matches!(error, Error::Canceled)
        } else {
            matches!(error, Error::Timeout)
        });
        assert_eq!(api.sequence, 1);
    }
}
