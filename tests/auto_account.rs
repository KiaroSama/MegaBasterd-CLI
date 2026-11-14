#![allow(clippy::unwrap_used)]

use megabasterd_cli::transfers::accounts::QuotaLedger;
use std::collections::{BTreeMap, HashSet};

#[test]
fn reservations_choose_roomiest_account_and_live_refresh_never_recredits_inflight_bytes() {
    let ledger = QuotaLedger::new(BTreeMap::from([("a".into(), 100), ("b".into(), 50)]));
    assert_eq!(
        ledger.reserve(60, &HashSet::new()).unwrap().as_deref(),
        Some("a")
    );
    assert_eq!(
        ledger.reserve(45, &HashSet::new()).unwrap().as_deref(),
        Some("b")
    );
    ledger.reconcile("a", 100).unwrap();
    assert_eq!(ledger.free("a").unwrap(), Some(40));
    ledger.reconcile("a", 0).unwrap();
    assert!(ledger.reserve(10, &HashSet::new()).unwrap().is_none());
    ledger.release("b", 45).unwrap();
    assert_eq!(ledger.free("b").unwrap(), Some(50));
    assert_eq!(
        ledger.reserve(10, &HashSet::from(["b".into()])).unwrap(),
        None
    );
}

#[test]
fn reservations_preserve_exact_source_quota_and_bounded_retry_examples() {
    let excluded = HashSet::new();
    let ledger = QuotaLedger::new(BTreeMap::from([
        ("big@example.invalid".into(), 1000),
        ("small@example.invalid".into(), 300),
    ]));
    assert_eq!(
        ledger.reserve(600, &excluded).unwrap().as_deref(),
        Some("big@example.invalid")
    );
    assert_eq!(ledger.free("big@example.invalid").unwrap(), Some(400));
    assert_eq!(ledger.reserve(500, &excluded).unwrap(), None);
    assert_eq!(ledger.free("big@example.invalid").unwrap(), Some(400));
    assert_eq!(ledger.free("small@example.invalid").unwrap(), Some(300));

    let ledger = QuotaLedger::new(BTreeMap::from([
        ("a@example.invalid".into(), 700),
        ("b@example.invalid".into(), 600),
    ]));
    assert_eq!(
        ledger.reserve(500, &excluded).unwrap().as_deref(),
        Some("a@example.invalid")
    );
    assert_eq!(
        ledger.reserve(500, &excluded).unwrap().as_deref(),
        Some("b@example.invalid")
    );
    assert_eq!(ledger.free("a@example.invalid").unwrap(), Some(200));
    assert_eq!(ledger.free("b@example.invalid").unwrap(), Some(100));

    let ledger = QuotaLedger::new(BTreeMap::from([("tiny".into(), 10)]));
    assert_eq!(ledger.reserve(100, &excluded).unwrap(), None);
    assert_eq!(ledger.free("tiny").unwrap(), Some(10));
    let ledger = QuotaLedger::new(BTreeMap::from([("account".into(), 500)]));
    assert_eq!(
        ledger.reserve(400, &excluded).unwrap().as_deref(),
        Some("account")
    );
    ledger.release("account", 400).unwrap();
    assert_eq!(ledger.free("account").unwrap(), Some(500));
    ledger.reconcile("account", 42).unwrap();
    assert_eq!(ledger.free("account").unwrap(), Some(42));
    assert_eq!(ledger.reserve(100, &excluded).unwrap(), None);

    let ledger = QuotaLedger::new(BTreeMap::from([("a".into(), 1000), ("b".into(), 1000)]));
    assert_eq!(ledger.reserve(10, &excluded).unwrap().as_deref(), Some("b"));
    assert_eq!(
        ledger
            .reserve(10, &HashSet::from(["a".into(), "b".into()]))
            .unwrap(),
        None
    );
    assert_eq!(ledger.free("a").unwrap(), Some(1000));
    assert_eq!(ledger.free("b").unwrap(), Some(990));
}

#[test]
fn concurrent_live_reconciliations_never_increase_reserved_free_space_and_zero_stays_unusable() {
    let ledger = QuotaLedger::new(BTreeMap::from([("a@example.invalid".into(), 1000)]));
    assert_eq!(
        ledger.reserve(900, &HashSet::new()).unwrap().as_deref(),
        Some("a@example.invalid")
    );
    assert_eq!(ledger.free("a@example.invalid").unwrap(), Some(100));
    ledger.reconcile("a@example.invalid", 1000).unwrap();
    assert_eq!(ledger.free("a@example.invalid").unwrap(), Some(100));

    let ledger = QuotaLedger::new(BTreeMap::from([("a@example.invalid".into(), 500)]));
    assert_eq!(ledger.free("a@example.invalid").unwrap(), Some(500));
    std::thread::scope(|scope| {
        let (ready, readiness) = std::sync::mpsc::channel();
        let mut starts = Vec::new();
        let workers: Vec<_> = (0..2)
            .map(|_| {
                let (start, started) = std::sync::mpsc::sync_channel(1);
                starts.push(start);
                let ready = ready.clone();
                let ledger = &ledger;
                scope.spawn(move || {
                    ready.send(()).unwrap();
                    started
                        .recv_timeout(std::time::Duration::from_secs(2))
                        .unwrap();
                    for value in [900, 400, 900, 0] {
                        ledger.reconcile("a@example.invalid", value).unwrap();
                    }
                })
            })
            .collect();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        for _ in 0..2 {
            readiness
                .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
                .unwrap();
        }
        for start in starts {
            start.send(()).unwrap();
        }
        for worker in workers {
            worker.join().unwrap();
        }
    });
    assert_eq!(ledger.free("a@example.invalid").unwrap(), Some(0));

    let ledger = QuotaLedger::new(BTreeMap::from([("a@example.invalid".into(), 500)]));
    ledger.reconcile("a@example.invalid", 0).unwrap();
    assert_eq!(ledger.free("a@example.invalid").unwrap(), Some(0));
    assert!(ledger.reserve(1, &HashSet::new()).unwrap().is_none());
}

#[test]
fn concurrent_reservations_cannot_overcommit_known_space() {
    for (free, size, attempts, admitted, remaining) in [(64, 32, 2, 2, 0), (1000, 300, 4, 3, 100)] {
        let ledger = QuotaLedger::new(BTreeMap::from([("account".into(), free)]));
        let successes: usize = std::thread::scope(|scope| {
            let (ready, readiness) = std::sync::mpsc::channel();
            let mut starts = Vec::new();
            let workers: Vec<_> = (0..2)
                .map(|_| {
                    let (start, started) = std::sync::mpsc::sync_channel(1);
                    starts.push(start);
                    let ready = ready.clone();
                    let ledger = &ledger;
                    scope.spawn(move || {
                        ready.send(()).unwrap();
                        started
                            .recv_timeout(std::time::Duration::from_secs(2))
                            .unwrap();
                        (0..attempts)
                            .filter(|_| ledger.reserve(size, &HashSet::new()).unwrap().is_some())
                            .count()
                    })
                })
                .collect();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            for _ in 0..2 {
                readiness
                    .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
                    .unwrap();
            }
            for start in starts {
                start.send(()).unwrap();
            }
            workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .sum()
        });
        assert_eq!(successes, admitted);
        assert_eq!(ledger.free("account").unwrap(), Some(remaining));
    }
}
