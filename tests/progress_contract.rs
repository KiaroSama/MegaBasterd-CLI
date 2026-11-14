#![allow(clippy::unwrap_used)]

use megabasterd_cli::terminal::progress::{MAX_VISIBLE_FILE_ROWS, Progress, Row, Status};

#[test]
fn source_byte_sizes_and_finite_durations_keep_their_exact_display() {
    use megabasterd_cli::terminal::progress::{duration, format_bytes};

    for (bytes, expected) in [
        (0, "0 B"),
        (1023, "1023 B"),
        (2048, "2.00 KB"),
        (5 * 1024 * 1024, "5.00 MB"),
        (2 * 1024_u64.pow(3), "2.00 GB"),
    ] {
        assert_eq!(format_bytes(bytes), expected);
    }
    assert_eq!(duration(65), "01:05");
    assert_eq!(duration(3725), "1:02:05");
}

#[test]
fn visible_frame_is_bounded_prioritizes_active_rows_and_preserves_all_snapshots() {
    let progress = Progress::new(false);
    let ids: Vec<_> = (0..50)
        .map(|index| progress.add(&format!("f{index:03}.bin"), 10).unwrap())
        .collect();
    progress.update(ids[40], 5, false).unwrap();
    let (visible, hidden) = progress.frame().unwrap();
    assert_eq!(MAX_VISIBLE_FILE_ROWS, 12);
    assert_eq!(visible.len(), 12);
    assert_eq!(hidden, 38);
    assert!(visible.iter().any(|line| line.starts_with("f040.bin ")));
    assert!(!visible.iter().any(|line| line.starts_with("f049.bin ")));
    assert_eq!(progress.snapshot(ids[49]).unwrap().total, 10);
    assert_eq!(progress.snapshot(ids[40]).unwrap().completed, 5);
    progress.status(ids[40], Status::Complete).unwrap();
    let (visible, hidden) = progress.frame().unwrap();
    assert_eq!(hidden, 38);
    assert!(!visible.iter().any(|line| line.starts_with("f040.bin ")));
    assert_eq!(progress.snapshot(ids[40]).unwrap().completed, 10);
    assert_eq!(progress.snapshot(ids[40]).unwrap().status, Status::Complete);
    for &id in &ids {
        progress.status(id, Status::Complete).unwrap();
    }
    let (visible, hidden) = progress.frame().unwrap();
    assert_eq!(visible.len(), 12);
    assert_eq!(hidden, 38);
    assert!(
        visible
            .iter()
            .all(|line| !line.contains("ETA") && line.contains("Elapsed"))
    );
    assert!(visible.first().unwrap().starts_with("f000.bin "));
    assert!(visible.last().unwrap().starts_with("f011.bin "));
}

#[test]
fn active_unknown_speed_retains_eta_but_completed_counts_and_terminal_states_do_not() {
    let progress = Progress::new(false);
    let active = progress.add("active.bin", 10).unwrap();
    progress.update(active, 0, false).unwrap();
    assert!(progress.frame().unwrap().0[0].contains("ETA --:--"));
    progress.update(active, 10, false).unwrap();
    let complete = progress.frame().unwrap().0.remove(0);
    assert!(complete.contains("Done") && !complete.contains("ETA"));
    assert!(complete.contains("100.0%"));
    assert!(complete.contains("10.00 B / 10.00 B"));
    for (status, label) in [
        (Status::Complete, "Done"),
        (Status::Failed, "Failed"),
        (Status::Canceled, "Canceled"),
        (Status::Skipped, "Skipped"),
    ] {
        let progress = Progress::new(false);
        let item = progress.add("terminal.bin", 10).unwrap();
        progress.status(item, status).unwrap();
        let row = progress.frame().unwrap().0.remove(0);
        assert!(row.contains(label) && row.contains("Elapsed"));
        assert!(!row.contains("ETA") && !row.contains(" |  | "));
        assert!(!row.trim_end().ends_with('|'));
    }
}

#[test]
fn pause_and_terminal_rows_keep_elapsed_without_a_stale_eta() {
    let progress = Progress::new(false);
    let item = progress.add("file  with spaces.bin", 10).unwrap();
    progress.update(item, 5, false).unwrap();
    assert!(progress.frame().unwrap().0[0].contains("ETA"));
    progress.pause(true).unwrap();
    let paused = progress.frame().unwrap().0.remove(0);
    assert!(paused.contains("Paused") && paused.contains("Elapsed"));
    assert!(!paused.contains("ETA"));
    progress.status(item, Status::Failed).unwrap();
    let terminal = progress.frame().unwrap().0.remove(0);
    assert!(terminal.contains("Failed") && terminal.contains("Elapsed"));
    assert!(!terminal.contains("ETA") && !terminal.contains("Paused"));
    assert!(
        !Row::new("name\nwith\x1bcontrol", 0)
            .render()
            .contains('\x1b')
    );
}
