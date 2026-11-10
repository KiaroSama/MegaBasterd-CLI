#![allow(clippy::unwrap_used)]
use megabasterd_cli::transfers::control::Control;
use std::time::Duration;

#[test]
fn cancellation_wakes_paused_waiters_and_keeps_cancel_exit_meaning() {
    let control = Control::new();
    assert!(control.toggle_pause().unwrap());
    let waiter = control.clone();
    let (send, receive) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || send.send(waiter.checkpoint().is_err()).unwrap());
    control.cancel();
    assert!(receive.recv_timeout(Duration::from_secs(1)).unwrap());
    thread.join().unwrap();
    assert_eq!(control.checkpoint().unwrap_err().exit_code(), 130);
    assert!(control.wait(Duration::ZERO).is_err());
}

#[test]
fn invalid_speed_limit_cannot_overflow_into_an_unlimited_transfer() {
    use megabasterd_cli::transfers::control::RateLimiter;
    for speed in [-1.0, f64::NAN, f64::INFINITY, f64::MAX] {
        assert!(RateLimiter::new(speed).is_err());
    }
    assert!(RateLimiter::new(0.0).is_ok());
}
