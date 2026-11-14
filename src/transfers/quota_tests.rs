//! Quota recovery changes when a retry occurs, never its total attempt or routing budget.
#![allow(clippy::unwrap_used)]

use std::{collections::VecDeque, net::IpAddr};

use super::*;
use crate::storage::proxies::Pool;

fn options(wait: u64, attempts: u32) -> DownloadOptions {
    DownloadOptions {
        workers: 1,
        max_parallel_verifications: 1,
        verify: false,
        overwrite: false,
        resume: true,
        keep_state: true,
        quota_wait: wait,
        quota_attempts: attempts,
    }
}

#[test]
fn available_pool_skips_only_one_wait_within_the_original_total_attempt_budget() {
    for code in [-17, -24] {
        for (failures, wait, attempts, expected_calls, expected_waits) in [
            (1, 3600, 24, 2, vec![]),
            (2, 4, 24, 3, vec![4]),
            (99, 2, 3, 3, vec![2]),
        ] {
            let pool = Pool::new(vec!["http://proxy.invalid:8080".into()], vec![], None).unwrap();
            let mut calls = 0;
            let mut waits = Vec::new();
            let result = retry_with(
                &options(wait, attempts),
                &Control::new(),
                || {
                    calls += 1;
                    if calls <= failures {
                        Err(Error::mega(code))
                    } else {
                        Ok("ok")
                    }
                },
                || pool.has_available(),
                |duration| {
                    waits.push(duration.as_secs());
                    Ok(())
                },
            );
            assert_eq!(calls, expected_calls);
            assert_eq!(waits, expected_waits);
            if failures == 99 {
                assert!(matches!(result, Err(Error::Mega { code: actual, .. }) if actual == code));
            } else {
                assert_eq!(result.unwrap(), "ok");
            }
        }
    }
}

#[test]
fn absent_or_cooled_pool_waits_without_selecting_a_route_and_zero_is_one_attempt() {
    for cooled in [false, true] {
        let proxy = "http://proxy.invalid:8080";
        let pool = Pool::new(vec![proxy.into()], vec![], None).unwrap();
        if cooled {
            for _ in 0..3 {
                pool.report(proxy, false).unwrap();
            }
        }
        let mut calls = 0;
        let mut waited = Duration::ZERO;
        let seconds = if cooled { 4 } else { 6 };
        assert_eq!(
            retry_with(
                &options(seconds, 24),
                &Control::new(),
                || {
                    calls += 1;
                    if calls == 1 {
                        Err(Error::mega(-17))
                    } else {
                        Ok("ok")
                    }
                },
                || if cooled {
                    pool.has_available()
                } else {
                    Ok(false)
                },
                |duration| {
                    waited += duration;
                    Ok(())
                },
            )
            .unwrap(),
            "ok"
        );
        assert_eq!(calls, 2);
        assert_eq!(waited, Duration::from_secs(seconds));
        if cooled {
            assert!(!pool.has_available().unwrap());
        }
    }
    for attempts in [0, 1] {
        let mut calls = 0;
        let result = retry_with::<()>(
            &options(3600, attempts),
            &Control::new(),
            || {
                calls += 1;
                Err(Error::mega(-24))
            },
            || panic!("exhausted budget inspected routing"),
            |_| panic!("exhausted budget waited"),
        );
        assert!(matches!(result, Err(Error::Mega { code: -24, .. })));
        assert_eq!(calls, 1);
    }
}

#[test]
fn cancellation_precedes_pool_escalation_and_wakes_a_quota_wait() {
    for available in [false, true] {
        let control = Control::new();
        let mut calls = 0;
        let mut inspections = 0;
        let result = retry_with::<()>(
            &options(6, 24),
            &control,
            || {
                calls += 1;
                control.cancel();
                Err(Error::mega(-17))
            },
            || {
                inspections += 1;
                Ok(available)
            },
            |_| panic!("canceled attempt waited"),
        );
        assert!(matches!(result, Err(Error::Canceled)));
        assert_eq!(calls, 1);
        assert_eq!(inspections, 0);
    }
    let control = Control::new();
    let mut calls = 0;
    let result = retry_with::<()>(
        &options(6, 24),
        &control,
        || {
            calls += 1;
            Err(Error::mega(-17))
        },
        || Ok(false),
        |_| {
            control.cancel();
            control.wait(Duration::ZERO)
        },
    );
    assert!(matches!(result, Err(Error::Canceled)));
    assert_eq!(calls, 1);
}

#[test]
fn only_definitive_quota_errors_may_retry_and_disabled_wait_never_escalates() {
    for error in [
        Error::mega(-9),
        Error::protocol("fixed refusal"),
        Error::Timeout,
    ] {
        let mut calls = 0;
        let expected = error.code();
        let mut error = Some(error);
        let result = retry_with::<()>(
            &options(4, 3),
            &Control::new(),
            || {
                calls += 1;
                Err(error.take().unwrap())
            },
            || panic!("nonquota error inspected routing"),
            |_| panic!("nonquota error waited"),
        );
        assert_eq!(result.unwrap_err().code(), expected);
        assert_eq!(calls, 1);
    }
    let result = retry_with::<()>(
        &options(0, 24),
        &Control::new(),
        || Err(Error::mega(-17)),
        || panic!("disabled quota wait escalated"),
        |_| panic!("disabled quota wait slept"),
    );
    assert!(matches!(result, Err(Error::Mega { code: -17, .. })));
}

#[test]
fn local_route_changes_shorten_wait_but_missing_observations_do_not() {
    let original: IpAddr = "10.0.0.5".parse().unwrap();
    let changed: IpAddr = "10.9.9.9".parse().unwrap();
    for (values, seconds, expected_wait) in [
        (vec![Some(original), Some(original), Some(changed)], 3600, 4),
        (vec![Some(original), None, None], 4, 4),
        (vec![None, Some(changed), Some(changed)], 4, 4),
        (vec![Some(original), Some(original), Some(original)], 3, 3),
    ] {
        let last = *values.last().unwrap();
        let mut routes = VecDeque::from(values);
        let mut waited = Duration::ZERO;
        wait_with(
            Duration::from_secs(seconds),
            &Control::new(),
            || routes.pop_front().unwrap_or(last),
            |duration| {
                assert!(duration <= Duration::from_secs(2));
                waited += duration;
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(waited, Duration::from_secs(expected_wait));
    }
    let control = Control::new();
    let result = wait_with(
        Duration::from_secs(6),
        &control,
        || Some(original),
        |_| {
            control.cancel();
            Ok(())
        },
    );
    assert!(matches!(result, Err(Error::Canceled)));
}
