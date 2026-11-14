#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn overall_totals_include_hidden_files_but_never_count_a_tree_summary_twice() {
    let mut progress = Progress::new(false);
    let parent = progress.add("photos", 400).unwrap();
    progress.summary(parent).unwrap();
    let a = progress.add("a.bin", 100).unwrap();
    let b = progress.add("b.bin", 300).unwrap();
    progress.update(a, 50, false).unwrap();
    progress.update(b, 100, false).unwrap();
    progress.update(parent, 150, false).unwrap();
    progress.status(a, Status::Failed).unwrap();
    let totals = progress.totals().unwrap();
    assert_eq!(totals.total, 400);
    assert_eq!(totals.completed, 150);
    assert_eq!(totals.items, 2);
    assert_eq!(totals.finished, 0);
    assert_eq!(totals.failed, 1);
    assert_eq!(totals.status, Status::Failed);
    let rendered = progress.overall_at(Instant::now()).unwrap();
    assert!(
        rendered.contains("Overall")
            && rendered.contains("Failed")
            && rendered.contains("0/2 files, 1 failed")
    );
    assert!(!rendered.contains("Done") && !rendered.contains("ETA"));
    assert!(!progress.close(true).unwrap());
    assert_eq!(progress.totals().unwrap().status, Status::Failed);

    let progress = Progress::new(false);
    for index in 0..50 {
        let item = progress.add(&format!("f{index:03}"), 10).unwrap();
        progress.update(item, 10, false).unwrap();
        progress.status(item, Status::Complete).unwrap();
    }
    let totals = progress.totals().unwrap();
    assert_eq!(
        (
            totals.total,
            totals.completed,
            totals.items,
            totals.finished,
            totals.failed
        ),
        (500, 500, 50, 50, 0)
    );
    assert_eq!(progress.frame().unwrap().0.len(), 12);
    assert_eq!(progress.frame().unwrap().1, 38);
}

#[test]
fn overall_render_sums_current_leaf_rates_and_uses_one_frozen_operation_clock() {
    let mut progress = Progress::new(false);
    let first = progress.add("a.bin", 2_000_000).unwrap();
    let second = progress.add("b.bin", 4_000_000).unwrap();
    let start = progress.shared.0.lock().unwrap().started;
    progress.update_at(first, 0, false, start).unwrap();
    progress.update_at(second, 0, false, start).unwrap();
    progress
        .update_at(first, 1_000_000, false, start + Duration::from_secs(1))
        .unwrap();
    progress
        .update_at(second, 2_000_000, false, start + Duration::from_secs(1))
        .unwrap();
    let rendered = progress.overall_at(start + Duration::from_secs(1)).unwrap();
    assert!(rendered.contains("Overall") && rendered.contains("50.0%"));
    assert!(
        rendered.contains("2.86 MB/s | ETA 00:01 | Elapsed 00:01"),
        "{rendered}"
    );
    assert!(rendered.contains("0/2 files"));
    let stalled = progress.overall_at(start + Duration::from_secs(7)).unwrap();
    assert!(
        stalled.contains("0.00 B/s | ETA --:-- | Elapsed 00:07"),
        "{stalled}"
    );
    assert!(
        !progress
            .close_at(true, start + Duration::from_secs(100))
            .unwrap()
    );
    let frozen = progress
        .overall_at(start + Duration::from_secs(101))
        .unwrap();
    assert!(frozen.contains("Failed") && frozen.contains("Elapsed 01:40"));
    assert!(!frozen.contains("ETA"));
    assert_eq!(
        frozen,
        progress
            .overall_at(start + Duration::from_secs(1000))
            .unwrap()
    );
}

#[test]
fn empty_tree_outcome_and_pause_are_truthful_without_a_renderer() {
    let mut progress = Progress::new(false);
    let parent = progress.add("empty-tree", 0).unwrap();
    progress.summary(parent).unwrap();
    assert_eq!(progress.totals().unwrap().items, 0);
    progress.pause(true).unwrap();
    let paused = progress.overall_at(Instant::now()).unwrap();
    assert!(paused.contains("Paused") && !paused.contains("ETA"));
    progress.status(parent, Status::Complete).unwrap();
    assert!(progress.close(true).unwrap());
    let complete = progress.overall_at(Instant::now()).unwrap();
    assert!(complete.contains("Done") && complete.contains("100.0%") && !complete.contains("ETA"));
    assert!(progress.renderer.is_none());

    let mut failed = Progress::new(false);
    let parent = failed.add("empty-tree", 0).unwrap();
    failed.summary(parent).unwrap();
    failed.status(parent, Status::Failed).unwrap();
    assert!(!failed.close(true).unwrap());
    assert_eq!(failed.totals().unwrap().status, Status::Failed);
}

#[test]
fn aggregate_byte_overflow_is_refused_instead_of_wrapping_to_a_false_total() {
    let progress = Progress::new(false);
    progress.add("huge", u64::MAX).unwrap();
    progress.add("extra", 1).unwrap();
    assert!(matches!(progress.totals(), Err(Error::Invalid(_))));
}
