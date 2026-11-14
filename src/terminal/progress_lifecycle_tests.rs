#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn closing_seals_every_item_and_does_not_resurrect_finished_rows() {
    let mut progress = Progress::new(false);
    let done = progress.add("a.bin", 100).unwrap();
    let failed = progress.add("b.bin", 100).unwrap();
    let leftover = progress.add("c.bin", 100).unwrap();
    let byte_complete = progress.add("d.bin", 100).unwrap();
    progress.update(done, 100, false).unwrap();
    progress.status(done, Status::Complete).unwrap();
    progress.update(failed, 10, false).unwrap();
    progress.status(failed, Status::Failed).unwrap();
    progress.update(byte_complete, 100, false).unwrap();
    assert!(!progress.close(false).unwrap());
    for (item, status, bytes) in [
        (done, Status::Complete, 100),
        (failed, Status::Failed, 10),
        (leftover, Status::Canceled, 0),
        (byte_complete, Status::Complete, 100),
    ] {
        assert_eq!(
            progress.snapshot(item).unwrap(),
            Snapshot {
                total: 100,
                completed: bytes,
                status
            }
        );
    }
    progress.status(leftover, Status::Complete).unwrap();
    progress.update(leftover, 100, true).unwrap();
    progress.pause(true).unwrap();
    assert_eq!(
        progress.snapshot(leftover).unwrap().status,
        Status::Canceled
    );
    assert_eq!(progress.snapshot(leftover).unwrap().completed, 0);
    assert!(!progress.close(true).unwrap());
    assert!(progress.add("late.bin", 1).is_err());
    assert!(
        progress
            .frame()
            .unwrap()
            .0
            .iter()
            .all(|row| !row.contains("ETA") && !row.contains("Paused"))
    );
}

#[test]
fn terminal_statuses_are_immutable_before_the_whole_view_closes() {
    let mut progress = Progress::new(false);
    let item = progress.add("a.bin", 10).unwrap();
    progress.status(item, Status::Complete).unwrap();
    progress.status(item, Status::Failed).unwrap();
    progress.update(item, 1, true).unwrap();
    assert_eq!(
        progress.snapshot(item).unwrap(),
        Snapshot {
            total: 10,
            completed: 10,
            status: Status::Complete
        }
    );
    assert!(progress.close(true).unwrap());
    assert!(progress.close(false).unwrap());
}

#[test]
fn close_combines_caller_success_with_failed_canceled_skipped_and_unfinished_items() {
    for (status, bytes, requested, expected, final_status) in [
        (Status::Complete, 10, true, true, Status::Complete),
        (Status::Complete, 10, false, false, Status::Complete),
        (Status::Failed, 0, true, false, Status::Failed),
        (Status::Canceled, 0, true, false, Status::Canceled),
        (Status::Skipped, 0, true, true, Status::Skipped),
        (Status::Active, 3, true, false, Status::Canceled),
        (Status::Active, 10, true, true, Status::Complete),
        (Status::Queued, 0, true, false, Status::Canceled),
    ] {
        let mut progress = Progress::new(false);
        let item = progress.add("a.bin", 10).unwrap();
        if status != Status::Queued {
            progress.update(item, bytes, false).unwrap();
            progress.status(item, status).unwrap();
        }
        assert_eq!(progress.close(requested).unwrap(), expected);
        assert_eq!(progress.snapshot(item).unwrap().status, final_status);
        assert_eq!(progress.close(!requested).unwrap(), expected);
    }
    let mut progress = Progress::new(false);
    let empty = progress.add("not-uploaded-empty.bin", 0).unwrap();
    assert!(!progress.close(true).unwrap());
    assert_eq!(progress.snapshot(empty).unwrap().status, Status::Canceled);
}

#[test]
fn a_failed_sibling_prevents_a_clean_close_from_claiming_batch_success() {
    let mut progress = Progress::new(false);
    let good = progress.add("a.bin", 10).unwrap();
    let bad = progress.add("b.bin", 10).unwrap();
    progress.update(good, 10, false).unwrap();
    progress.status(good, Status::Complete).unwrap();
    progress.status(bad, Status::Failed).unwrap();
    assert!(!progress.close(true).unwrap());
    assert!(!progress.close(true).unwrap());
    assert_eq!(progress.snapshot(good).unwrap().status, Status::Complete);
    assert_eq!(progress.snapshot(bad).unwrap().status, Status::Failed);
    let rows = progress.frame().unwrap().0;
    assert!(rows[0].contains("Done") && rows[1].contains("Failed"));
    assert!(rows.iter().all(|row| !row.contains("ETA")));
}

#[test]
fn byte_complete_failed_canceled_and_skipped_rows_keep_their_explicit_outcome() {
    for (status, label, success) in [
        (Status::Failed, "Failed", false),
        (Status::Canceled, "Canceled", false),
        (Status::Skipped, "Skipped", true),
    ] {
        let mut progress = Progress::new(false);
        let item = progress.add("verified.bin", 100).unwrap();
        progress.update(item, 100, false).unwrap();
        progress.status(item, status).unwrap();
        assert_eq!(progress.close(true).unwrap(), success);
        let row = &progress.frame().unwrap().0[0];
        assert!(row.contains(label) && row.contains("100.0%"), "{row}");
        assert!(!row.contains("Done") && !row.contains("ETA"), "{row}");
        assert!(row.contains("100.00 B / 100.00 B") && row.contains("Elapsed"));
    }
}

#[test]
fn command_owned_uploads_do_not_finish_until_finalization_is_confirmed() {
    for confirmed in [false, true] {
        let mut progress = Progress::new(false);
        let item = progress.add("uploaded.bin", 10).unwrap();
        progress.defer_completion(item).unwrap();
        progress.update(item, 10, false).unwrap();
        progress.transferred(item).unwrap();
        assert_eq!(progress.snapshot(item).unwrap().status, Status::Verifying);
        assert!(!progress.frame().unwrap().0[0].contains("Done"));
        if confirmed {
            progress.status(item, Status::Complete).unwrap();
        } else {
            progress.status(item, Status::Failed).unwrap();
        }
        assert_eq!(progress.close(true).unwrap(), confirmed);
        assert_eq!(
            progress.snapshot(item).unwrap().status,
            if confirmed {
                Status::Complete
            } else {
                Status::Failed
            }
        );
    }
    let mut progress = Progress::new(false);
    let item = progress.add("unfinished-finalization.bin", 10).unwrap();
    progress.defer_completion(item).unwrap();
    progress.update(item, 10, false).unwrap();
    progress.transferred(item).unwrap();
    assert!(!progress.close(true).unwrap());
    assert_eq!(progress.snapshot(item).unwrap().status, Status::Canceled);
}

#[test]
fn elapsed_advances_without_updates_and_freezes_at_the_explicit_close_time() {
    let mut progress = Progress::new(false);
    let item = progress.add("elapsed.bin", 10).unwrap();
    let start = progress.shared.0.lock().unwrap().rows[&item].started;
    progress.update_at(item, 3, true, start).unwrap();
    assert!(
        progress
            .frame_at(start + Duration::from_secs(99))
            .unwrap()
            .0[0]
            .contains("Elapsed 01:39")
    );
    assert!(
        progress
            .frame_at(start + Duration::from_secs(100))
            .unwrap()
            .0[0]
            .contains("Elapsed 01:40")
    );
    assert!(
        !progress
            .close_at(true, start + Duration::from_secs(100))
            .unwrap()
    );
    let frozen = progress.frame_at(start + Duration::from_secs(100)).unwrap();
    assert!(frozen.0[0].contains("Canceled") && frozen.0[0].contains("Elapsed 01:40"));
    assert_eq!(
        frozen,
        progress
            .frame_at(start + Duration::from_secs(1000))
            .unwrap()
    );
}
