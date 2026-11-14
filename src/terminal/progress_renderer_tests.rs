#![allow(clippy::unwrap_used)]

use super::super::{Progress, Status};
use super::*;
use crate::error::Error;
use std::sync::{Arc, Mutex, mpsc};

#[test]
fn active_and_final_frames_draw_without_holding_the_model_lock_and_close_joins() {
    let frames = Arc::new(Mutex::new(Vec::new()));
    let captured = frames.clone();
    let (ready, observed) = mpsc::sync_channel(1);
    let mut progress = Progress::with_renderer(true, move |shared| {
        let weak = Arc::downgrade(&shared);
        let mut live_seen = false;
        spawn(shared, move |line, closed| {
            // Probe only after the producer's update, or after close releases its lock.
            if !closed && (live_seen || !line.contains("item.bin") || !line.contains("50.0%")) {
                return Ok(());
            }
            let shared = weak.upgrade().unwrap();
            let unlocked = shared.0.try_lock().is_ok();
            captured
                .lock()
                .unwrap()
                .push((line.to_owned(), closed, unlocked));
            if !closed {
                live_seen = true;
                ready.try_send(()).unwrap();
            }
            Ok(())
        })
    });
    let item = progress.add("item.bin", 10).unwrap();
    progress.update(item, 5, false).unwrap();
    // Always close the owned renderer before asserting readiness, including a failed observation.
    let ready = observed.recv_timeout(Duration::from_secs(2));
    let closed = progress.close(false);
    ready.unwrap();
    assert!(!closed.unwrap());
    assert_eq!(progress.snapshot(item).unwrap().status, Status::Canceled);
    assert!(progress.renderer.is_none());
    let frames = frames.lock().unwrap();
    assert!(frames.iter().all(|(_, _, unlocked)| *unlocked));
    assert!(
        frames
            .iter()
            .any(|(line, closed, _)| !closed && line.contains("50.0%"))
    );
    assert_eq!(frames.iter().filter(|(_, closed, _)| *closed).count(), 1);
    let (last, closed, _) = frames.last().unwrap();
    assert!(*closed && last.contains("Overall") && last.contains("Failed"));
    assert!(last.contains("item.bin") && last.contains("Canceled") && last.contains("Elapsed"));
    assert!(!last.contains("ETA"));
}

#[test]
fn disabled_progress_never_constructs_a_renderer_but_preserves_the_terminal_model() {
    let mut progress =
        Progress::with_renderer(false, |_| panic!("quiet progress created a renderer"));
    let item = progress.add("quiet.bin", 10).unwrap();
    progress.update(item, 5, false).unwrap();
    progress.status(item, Status::Complete).unwrap();
    assert!(progress.close(true).unwrap());
    assert_eq!(progress.snapshot(item).unwrap().status, Status::Complete);
    assert!(progress.renderer.is_none());
}

#[test]
fn a_failed_final_draw_is_propagated_after_the_owned_renderer_is_joined() {
    let (failed, observed) = mpsc::sync_channel(1);
    let mut progress = Progress::with_renderer(true, |shared| {
        spawn(shared, move |_, closed| {
            if !closed {
                return Ok(());
            }
            failed.try_send(()).unwrap();
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "fixture output closed",
            ))
        })
    });
    let item = progress.add("finished.bin", 10).unwrap();
    progress.status(item, Status::Complete).unwrap();
    let error = progress.close(true).unwrap_err();
    assert!(matches!(error, Error::Io(error) if error.kind() == std::io::ErrorKind::BrokenPipe));
    observed.try_recv().unwrap();
    assert!(progress.renderer.is_none());
    assert!(!progress.close(false).unwrap());
    assert!(!progress.close(true).unwrap());
    assert_eq!(progress.totals().unwrap().status, Status::Failed);
    assert!(progress.add("late.bin", 1).is_err());
}
