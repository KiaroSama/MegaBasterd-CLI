#![allow(clippy::unwrap_used)]

use super::*;
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

struct CancelOnDrop(Control);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

#[test]
fn resumed_chunk_rereads_wait_for_the_shared_permit_and_cancel_without_mutating_coverage() {
    use std::io::Write;
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/resume-gate");
    std::fs::create_dir_all(&base).unwrap();
    let scratch = crate::test_support::tempdir_in(base).unwrap();
    let path = scratch.path().join("stage");
    let mut file = File::create(&path).unwrap();
    file.write_all(b"x").unwrap();
    drop(file);
    let key = keys::unpack_file_key(&[0; 8]).unwrap();
    let mac = chunks::chunk_mac(b"x", key.aes_key.as_slice(), &key.nonce).unwrap();
    let held = gate().acquire(&Control::new(), 1).unwrap();
    let control = Control::new();
    let _cancel = CancelOnDrop(control.clone());
    let (send, receive) = mpsc::sync_channel(1);
    std::thread::scope(|scope| {
        let waiting = control.clone();
        scope.spawn(move || {
            let mut file = File::open(path).unwrap();
            let mut completed = std::collections::BTreeMap::from([(0, mac)]);
            let result = validate_completed(&mut file, 1, &key, &mut completed, &waiting);
            send.send((result.map_err(|error| error.exit_code()), completed))
                .unwrap();
        });
        let early = receive.recv_timeout(Duration::from_millis(200));
        control.cancel();
        let was_waiting = matches!(early, Err(mpsc::RecvTimeoutError::Timeout));
        let (result, completed) =
            early.unwrap_or_else(|_| receive.recv_timeout(Duration::from_secs(2)).unwrap());
        drop(held);
        assert!(
            was_waiting,
            "resume reread bypassed the shared verification permit"
        );
        assert_eq!(result, Err(130));
        assert_eq!(completed, std::collections::BTreeMap::from([(0, mac)]));
    });
}

#[test]
fn configured_disk_gate_admits_two_and_cancels_the_third_until_release() {
    let gate = Gate {
        active: Mutex::new(0),
        changed: Condvar::new(),
    };
    let first = gate.acquire(&Control::new(), 2).unwrap();
    let waiting = Control::new();
    let (admitted, result) = mpsc::sync_channel(1);
    let (release, released) = mpsc::sync_channel(1);
    std::thread::scope(|scope| {
        let _cancel_on_panic = CancelOnDrop(waiting.clone());
        let gate = &gate;
        let worker_control = waiting.clone();
        let worker = scope.spawn(move || {
            let second = gate.acquire(&worker_control, 2);
            admitted.send(second.is_ok()).unwrap();
            if second.is_ok() {
                released.recv_timeout(Duration::from_secs(3)).unwrap();
            }
        });
        let outcome = result.recv_timeout(Duration::from_secs(2));
        if outcome.is_err() {
            waiting.cancel();
        } else {
            assert_eq!(*gate.active.lock().unwrap(), 2);
            release.send(()).unwrap();
        }
        worker.join().unwrap();
        assert_eq!(outcome, Ok(true));
    });
    let second = gate.acquire(&Control::new(), 2).unwrap();
    let canceled = Control::new();
    canceled.cancel();
    assert!(matches!(gate.acquire(&canceled, 2), Err(Error::Canceled)));
    drop(first);
    let replacement = gate.acquire(&Control::new(), 2).unwrap();
    assert_eq!(*gate.active.lock().unwrap(), 2);
    drop((second, replacement));
    assert_eq!(*gate.active.lock().unwrap(), 0);
    for invalid in [0, 33] {
        assert!(matches!(
            gate.acquire(&Control::new(), invalid),
            Err(Error::Invalid(_))
        ));
    }
}

#[test]
fn one_disk_permit_waits_cancellably_and_release_allows_the_next_verification() {
    let first = permit(&Control::new()).unwrap();
    let canceled = Control::new();
    let waiting = canceled.clone();
    let (ready, entered) = mpsc::sync_channel(1);
    let (finished, result) = mpsc::sync_channel(1);
    std::thread::scope(|scope| {
        let _cancel_on_panic = CancelOnDrop(canceled.clone());
        let worker = scope.spawn(|| {
            ready.send(()).unwrap();
            let outcome = permit(&waiting).map(drop);
            finished
                .send(outcome.map_err(|error| error.exit_code()))
                .unwrap();
        });
        entered.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(result.try_recv(), Err(mpsc::TryRecvError::Empty)));
        canceled.cancel();
        assert_eq!(
            result.recv_timeout(Duration::from_secs(2)).unwrap(),
            Err(130)
        );
        worker.join().unwrap();
    });
    drop(first);
    let second = permit(&Control::new()).unwrap();
    drop(second);
    let stopped = Control::new();
    stopped.cancel();
    assert!(matches!(permit(&stopped), Err(Error::Canceled)));
}

#[test]
fn simultaneous_disk_passes_never_hold_more_than_one_process_permit() {
    let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let peak = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (finished, result) = mpsc::sync_channel(2);
    let deadline = Instant::now() + Duration::from_secs(5);
    let control = Control::new();
    std::thread::scope(|scope| {
        let _cancel_on_panic = CancelOnDrop(control.clone());
        let mut workers = Vec::new();
        for _ in 0..2 {
            let active = active.clone();
            let peak = peak.clone();
            let finished = finished.clone();
            let control = &control;
            workers.push(scope.spawn(move || {
                for _ in 0..2 {
                    let permit = permit(control).unwrap();
                    assert!(Instant::now() < deadline);
                    let current = active.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                    peak.fetch_max(current, std::sync::atomic::Ordering::SeqCst);
                    assert_eq!(current, 1);
                    active.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                    drop(permit);
                }
                finished.send(()).unwrap();
            }));
        }
        for _ in 0..2 {
            result.recv_timeout(Duration::from_secs(5)).unwrap();
        }
        for worker in workers {
            worker.join().unwrap();
        }
    });
    assert_eq!(peak.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(active.load(std::sync::atomic::Ordering::SeqCst), 0);
}
