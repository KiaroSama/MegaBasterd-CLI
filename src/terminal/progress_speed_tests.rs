#![allow(clippy::unwrap_used)]

use super::*;

fn line(progress: &Progress, now: Instant) -> String {
    let (mut lines, hidden) = progress.frame_at(now).unwrap();
    assert_eq!(hidden, 0);
    assert_eq!(lines.len(), 1);
    lines.remove(0)
}

#[test]
fn steady_rate_uses_recent_samples_and_displays_bytes_per_second() {
    let progress = Progress::new(false);
    let item = progress.add("steady.bin", 10_000_000).unwrap();
    let start = Instant::now();
    for second in 0..=5 {
        progress
            .update_at(
                item,
                second * 1_000_000,
                false,
                start + Duration::from_secs(second),
            )
            .unwrap();
    }
    let frame = line(&progress, start + Duration::from_secs(5));
    assert!(
        frame.contains(" | 976.56 KB/s | ETA 00:05 | Elapsed"),
        "{frame}"
    );
    assert!(frame.contains("50.0%") && frame.contains("4.77 MB / 9.54 MB"));
    assert!(!frame.contains("Active"));
}

#[test]
fn a_rate_change_discards_old_throughput_instead_of_using_a_lifetime_average() {
    let progress = Progress::new(false);
    let item = progress.add("changed.bin", 100_000_000).unwrap();
    let start = Instant::now();
    progress.update_at(item, 0, false, start).unwrap();
    for second in 1..=10 {
        progress
            .update_at(
                item,
                second * 1_000_000,
                false,
                start + Duration::from_secs(second),
            )
            .unwrap();
    }
    for second in 11..=16 {
        progress
            .update_at(
                item,
                10_000_000 + (second - 10) * 2_000_000,
                false,
                start + Duration::from_secs(second),
            )
            .unwrap();
    }
    let frame = line(&progress, start + Duration::from_secs(16));
    assert!(frame.contains(" | 1.91 MB/s | ETA 00:39"), "{frame}");
}

#[test]
fn resumed_bytes_and_queued_time_are_not_part_of_the_displayed_rate() {
    let progress = Progress::new(false);
    let item = progress.add("resumed.bin", 1_000_000_000).unwrap();
    let start = Instant::now() + Duration::from_secs(120);
    progress.update_at(item, 900_000_000, true, start).unwrap();
    let baseline = line(&progress, start);
    assert!(baseline.contains(" | 0.00 B/s | ETA --:--"), "{baseline}");
    assert!(
        progress
            .overall_at(start)
            .unwrap()
            .contains(" | 0.00 B/s | ETA --:--")
    );
    progress
        .update_at(item, 901_000_000, false, start + Duration::from_secs(1))
        .unwrap();
    let frame = line(&progress, start + Duration::from_secs(1));
    assert!(frame.contains(" | 976.56 KB/s | ETA 01:39"), "{frame}");
    assert!(
        progress
            .overall_at(start + Duration::from_secs(1))
            .unwrap()
            .contains(" | 976.56 KB/s | ETA 01:39")
    );
    // Refreshing an expired upload slot must reset the same-byte baseline too.
    progress
        .update_at(item, 901_000_000, true, start + Duration::from_secs(2))
        .unwrap();
    assert!(line(&progress, start + Duration::from_secs(2)).contains(" | 0.00 B/s | ETA --:--"));
}

#[test]
fn queued_rows_never_seed_rate_samples_and_overall_is_only_the_sum_of_leaf_rates() {
    let progress = Progress::new(false);
    let first = progress.add("queued-a", 100).unwrap();
    let second = progress.add("queued-b", 100).unwrap();
    let now = Instant::now();
    {
        let state = progress.shared.0.lock().unwrap();
        assert!(state.rows[&first].rate.samples.is_empty());
        assert!(state.rows[&second].rate.samples.is_empty());
    }
    let (queued, hidden) = progress.frame_at(now).unwrap();
    assert_eq!(hidden, 0);
    assert_eq!(queued.len(), 2);
    for row in &queued {
        assert!(row.contains("Queued") && row.contains("0.00 B / 100.00 B"));
    }
    assert!(progress.overall_at(now).unwrap().contains("0.00 B/s"));
    {
        let state = progress.shared.0.lock().unwrap();
        assert!(state.rows[&first].rate.samples.is_empty());
        assert!(state.rows[&second].rate.samples.is_empty());
    }
    progress.update_at(first, 20, false, now).unwrap();
    progress.update_at(second, 40, false, now).unwrap();
    progress
        .update_at(first, 30, false, now + Duration::from_secs(1))
        .unwrap();
    progress
        .update_at(second, 60, false, now + Duration::from_secs(1))
        .unwrap();
    let state = progress.shared.0.lock().unwrap();
    let sum = state
        .rows
        .values()
        .map(|row| row.rate.current(now + Duration::from_secs(1)))
        .sum::<f64>();
    assert_eq!(sum, 30.0);
    drop(state);
    assert!(
        progress
            .overall_at(now + Duration::from_secs(1))
            .unwrap()
            .contains("30.00 B/s")
    );

    let mut staggered = Progress::new(false);
    let first = staggered.add("resume-a", 1000).unwrap();
    let second = staggered.add("resume-b", 1000).unwrap();
    staggered.update_at(first, 100, true, now).unwrap();
    staggered
        .update_at(first, 110, false, now + Duration::from_secs(1))
        .unwrap();
    staggered
        .update_at(second, 800, true, now + Duration::from_secs(1))
        .unwrap();
    assert!(
        staggered
            .overall_at(now + Duration::from_secs(1))
            .unwrap()
            .contains(" | 10.00 B/s |")
    );
    staggered
        .update_at(first, 120, false, now + Duration::from_secs(2))
        .unwrap();
    staggered
        .update_at(second, 820, false, now + Duration::from_secs(2))
        .unwrap();
    assert!(
        staggered
            .overall_at(now + Duration::from_secs(2))
            .unwrap()
            .contains(" | 30.00 B/s |")
    );
    staggered.status(first, Status::Complete).unwrap();
    assert!(
        staggered
            .overall_at(now + Duration::from_secs(2))
            .unwrap()
            .contains(" | 20.00 B/s |")
    );
    assert!(!staggered.close(false).unwrap());
}

#[test]
fn silent_stall_decays_at_render_time_then_new_samples_recover() {
    let progress = Progress::new(false);
    let item = progress.add("stall.bin", 10_000_000).unwrap();
    let start = Instant::now();
    progress.update_at(item, 0, false, start).unwrap();
    progress
        .update_at(item, 2_000_000, false, start + Duration::from_secs(1))
        .unwrap();
    for (seconds, speed, eta) in [
        (1, "1.91 MB/s", "00:04"),
        (2, "976.56 KB/s", "00:08"),
        (4, "488.28 KB/s", "00:16"),
        (7, "0.00 B/s", "--:--"),
    ] {
        let frame = line(&progress, start + Duration::from_secs(seconds));
        assert!(
            frame.contains(&format!(" | {speed} | ETA {eta}")),
            "{frame}"
        );
    }
    progress
        .update_at(item, 3_000_000, false, start + Duration::from_secs(8))
        .unwrap();
    assert!(line(&progress, start + Duration::from_secs(8)).contains(" | 0.00 B/s | ETA --:--"));
    progress
        .update_at(item, 4_000_000, false, start + Duration::from_secs(9))
        .unwrap();
    assert!(line(&progress, start + Duration::from_secs(9)).contains(" | 976.56 KB/s | ETA 00:06"));
}

#[test]
fn rewound_counts_clear_rate_and_terminal_elapsed_stays_frozen() {
    let progress = Progress::new(false);
    let item = progress.add("rewind.bin", 10_000_000).unwrap();
    let start = Instant::now();
    progress.update_at(item, 5_000_000, false, start).unwrap();
    progress
        .update_at(item, 1_000_000, false, start + Duration::from_secs(1))
        .unwrap();
    assert!(
        line(&progress, start + Duration::from_millis(1200)).contains(" | 0.00 B/s | ETA --:--")
    );
    progress.status(item, Status::Failed).unwrap();
    let terminal = line(&progress, start + Duration::from_secs(2));
    assert_eq!(terminal, line(&progress, start + Duration::from_secs(200)));
    assert!(
        terminal.contains("Failed") && terminal.contains("Elapsed") && !terminal.contains("ETA")
    );
    progress
        .update_at(item, 9_000_000, false, start + Duration::from_secs(201))
        .unwrap();
    assert_eq!(progress.snapshot(item).unwrap().completed, 1_000_000);
    assert_eq!(terminal, line(&progress, start + Duration::from_secs(201)));
}

#[test]
fn burst_updates_keep_a_bounded_window_and_the_latest_byte_count() {
    let progress = Progress::new(false);
    // Half a second away from a rounding boundary; ETA still has an exact literal.
    let item = progress.add("burst.bin", 10_050_000).unwrap();
    let start = Instant::now();
    for millis in 0..=10_000 {
        progress
            .update_at(
                item,
                millis * 100,
                false,
                start + Duration::from_millis(millis),
            )
            .unwrap();
    }
    let frame = line(&progress, start + Duration::from_secs(10));
    assert!(frame.contains(" | 97.66 KB/s | ETA 01:30"), "{frame}");
    let locked = progress.shared.0.lock().unwrap();
    let row = locked.rows.get(&item).unwrap();
    assert!(row.rate.samples.len() <= 104);
    assert_eq!(row.completed, 1_000_000);
    drop(locked);
    assert!(line(&progress, start + Duration::from_secs(16)).contains(" | 0.00 B/s | ETA --:--"));
}

#[test]
fn subinterval_samples_and_clock_regression_do_not_create_infinite_speed() {
    let progress = Progress::new(false);
    let item = progress.add("short.bin", 10_000).unwrap();
    let start = Instant::now();
    progress.update_at(item, 0, false, start).unwrap();
    progress.update_at(item, 100, false, start).unwrap();
    progress
        .update_at(item, 200, false, start + Duration::from_millis(100))
        .unwrap();
    assert!(
        line(&progress, start + Duration::from_millis(100)).contains(" | 0.00 B/s | ETA --:--")
    );
    progress
        .update_at(item, 500, false, start + Duration::from_millis(500))
        .unwrap();
    assert!(
        line(&progress, start + Duration::from_millis(500)).contains(" | 1000.00 B/s | ETA 00:09")
    );
    progress
        .update_at(item, 600, false, start + Duration::from_millis(400))
        .unwrap();
    let frame = line(&progress, start + Duration::from_millis(500));
    assert!(!frame.contains("NaN") && !frame.contains("inf"));
}

#[test]
fn shared_progress_accepts_concurrent_updates_and_rendering_without_sleep_or_global_io() {
    let progress = Progress::new(false);
    let item = progress.add("concurrent.bin", 1024 * 1024).unwrap();
    std::thread::scope(|scope| {
        let writer = scope.spawn(|| {
            for count in 0..256 {
                progress.update(item, count * 1024, count == 0).unwrap();
            }
        });
        let reader = scope.spawn(|| {
            for _ in 0..256 {
                let (rows, hidden) = progress.frame().unwrap();
                assert_eq!(hidden, 0);
                assert_eq!(rows.len(), 1);
                assert!(rows[0].contains("Elapsed") && rows[0].contains("ETA"));
                assert!(!rows[0].contains("NaN") && !rows[0].contains("inf"));
            }
        });
        writer.join().unwrap();
        reader.join().unwrap();
    });
    assert_eq!(progress.snapshot(item).unwrap().completed, 255 * 1024);
}
