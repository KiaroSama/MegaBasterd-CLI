#![allow(clippy::unwrap_used)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::time::Duration;

use megabasterd_cli::{services::http, transfers::control::Control};

struct CancelOnDrop(Control);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

fn client(address: std::net::SocketAddr) -> TcpStream {
    let socket = TcpStream::connect_timeout(&address, Duration::from_secs(2)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    socket
}

#[test]
fn actual_server_enforces_peer_limit_and_cancellation_reaps_blocked_readers() {
    for (per_peer, held_count) in [(1, 1), (2, 2)] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let control = Control::new();
        let (entered, active) = mpsc::sync_channel(1);
        let (finished, done) = mpsc::sync_channel(1);
        std::thread::scope(|scope| {
            let shutdown = CancelOnDrop(control.clone());
            let server_control = &control;
            let worker = scope.spawn(move || {
                let result = http::serve(
                    listener,
                    2,
                    per_peer,
                    server_control,
                    |socket, _| {
                        entered.send(()).unwrap();
                        http::read_head(socket, Duration::from_secs(5), server_control).map(|_| ())
                    },
                    |_| (),
                );
                finished.send(()).unwrap();
                result
            });
            let mut held = Vec::new();
            for _ in 0..held_count {
                let mut socket = client(address);
                socket.write_all(b"GET / HTTP/1.1\r\nHost:").unwrap();
                active.recv_timeout(Duration::from_secs(2)).unwrap();
                held.push(socket);
            }
            let mut refused = client(address);
            refused
                .write_all(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .unwrap();
            refused.shutdown(std::net::Shutdown::Write).unwrap();
            let mut rejected = Vec::new();
            refused.take(4096).read_to_end(&mut rejected).unwrap();
            assert!(rejected.starts_with(b"HTTP/1.1 503 Service Unavailable\r\n"));
            assert!(rejected.ends_with(b"Too many active connections"));
            control.cancel();
            done.recv_timeout(Duration::from_secs(3)).unwrap();
            worker.join().unwrap().unwrap();
            for mut socket in held {
                assert_eq!(socket.read(&mut [0]).unwrap(), 0);
            }
            drop(shutdown);
        });
        assert!(
            TcpListener::bind(address).is_ok(),
            "server retained its listener after shutdown"
        );
    }
}

#[test]
fn unfinished_and_dribbling_headers_expire_the_total_deadline_without_cancellation() {
    use std::time::Instant;

    for dribble in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut peer = client(listener.local_addr().unwrap());
        let (mut socket, _) = listener.accept().unwrap();
        let control = Control::new();
        let (finished, done) = mpsc::sync_channel(1);
        std::thread::scope(|scope| {
            let shutdown = CancelOnDrop(control.clone());
            let reader_control = &control;
            let worker = scope.spawn(move || {
                let result =
                    http::read_head(&mut socket, Duration::from_millis(400), reader_control);
                drop(socket);
                finished
                    .send(matches!(
                        result,
                        Err(megabasterd_cli::error::Error::Timeout)
                    ))
                    .unwrap();
            });
            peer.write_all(b"GET / HTTP/1.1\r\nHost:").unwrap();
            let started = Instant::now();
            if dribble {
                let deadline = started + Duration::from_secs(2);
                loop {
                    assert!(
                        Instant::now() < deadline,
                        "each arriving byte renewed the header deadline"
                    );
                    // A bounded cadence models the fault: bytes keep arriving before each read timeout.
                    let _ = peer.write_all(b"X");
                    match done.recv_timeout(Duration::from_millis(40)) {
                        Ok(timed_out) => {
                            assert!(timed_out);
                            break;
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => (),
                        Err(error) => panic!("header worker ended without a result: {error}"),
                    }
                }
            } else {
                assert!(done.recv_timeout(Duration::from_secs(2)).unwrap());
            }
            assert!(started.elapsed() < Duration::from_secs(2));
            assert!(
                !control.is_canceled(),
                "an external cancellation cannot prove the header deadline"
            );
            worker.join().unwrap();
            let mut byte = [0];
            match peer.read(&mut byte) {
                Ok(0) => (),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                    ) => {}
                result => panic!("expired header connection stayed open: {result:?}"),
            }
            drop(shutdown);
        });
    }
}

#[test]
fn expired_headers_release_real_server_capacity_for_the_same_peer() {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    for paused in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let control = Control::new();
        let (entered, active) = mpsc::sync_channel(1);
        let (expire, expiry_allowed) = mpsc::sync_channel(1);
        let expiry_allowed = Mutex::new(expiry_allowed);
        let requests = AtomicUsize::new(0);
        let timeouts = AtomicUsize::new(0);
        let (finished, done) = mpsc::sync_channel(1);
        std::thread::scope(|scope| {
            let shutdown = CancelOnDrop(control.clone());
            let server_control = &control;
            let requests = &requests;
            let timeouts = &timeouts;
            let expiry_allowed = &expiry_allowed;
            let worker = scope.spawn(move || {
                let result = http::serve(
                    listener,
                    1,
                    1,
                    server_control,
                    |socket, _| {
                        if requests.fetch_add(1, Ordering::Relaxed) == 1 {
                            entered.send(()).unwrap();
                            expiry_allowed
                                .lock()
                                .unwrap()
                                .recv_timeout(Duration::from_secs(2))
                                .unwrap();
                            return http::read_head(
                                socket,
                                Duration::from_millis(400),
                                server_control,
                            )
                            .map(|_| ());
                        }
                        let request =
                            http::read_head(socket, Duration::from_secs(2), server_control)?;
                        assert_eq!(request.method, "HEAD");
                        http::reply(socket, 200, &[], b"")
                    },
                    |error| {
                        assert!(matches!(error, megabasterd_cli::error::Error::Timeout));
                        timeouts.fetch_add(1, Ordering::Relaxed);
                    },
                );
                finished.send(()).unwrap();
                result
            });
            let mut served = client(address);
            served
                .write_all(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .unwrap();
            served.shutdown(std::net::Shutdown::Write).unwrap();
            let mut response = Vec::new();
            served.take(4096).read_to_end(&mut response).unwrap();
            assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));

            // A response EOF can precede the final peer-counter decrement.
            let deadline = Instant::now() + Duration::from_secs(2);
            let mut stalled = 'admission: loop {
                assert!(
                    Instant::now() < deadline,
                    "served request retained its slot"
                );
                let mut socket = client(address);
                socket.write_all(b"GET / HTTP/1.1\r\nHost:").unwrap();
                socket.set_nonblocking(true).unwrap();
                loop {
                    assert!(
                        Instant::now() < deadline,
                        "served request retained its slot"
                    );
                    match active.recv_timeout(Duration::from_millis(20)) {
                        Ok(()) => {
                            socket.set_nonblocking(false).unwrap();
                            break 'admission socket;
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => (),
                        Err(error) => panic!("header worker ended before admission: {error}"),
                    }
                    match socket.peek(&mut [0]) {
                        Ok(_) => break,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => (),
                        Err(error) => panic!("admission observation failed: {error}"),
                    }
                }
                socket.set_nonblocking(false).unwrap();
                socket.shutdown(std::net::Shutdown::Write).unwrap();
                let mut response = Vec::new();
                socket.take(4096).read_to_end(&mut response).unwrap();
                assert!(response.starts_with(b"HTTP/1.1 503 Service Unavailable\r\n"));
            };
            let mut refused = client(address);
            refused
                .write_all(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .unwrap();
            refused.shutdown(std::net::Shutdown::Write).unwrap();
            let mut response = Vec::new();
            refused.take(4096).read_to_end(&mut response).unwrap();
            assert!(response.starts_with(b"HTTP/1.1 503 Service Unavailable\r\n"));
            if paused {
                assert!(control.toggle_pause().unwrap());
            }
            expire.send(()).unwrap();
            assert_eq!(stalled.read(&mut [0]).unwrap(), 0);
            assert!(!control.is_canceled());
            if paused {
                assert!(
                    !control.toggle_pause().unwrap(),
                    "deadline handling changed pause state"
                );
            }
            // EOF can precede the final counter decrement. Each retry observes a real response,
            // and the deadline bounds that teardown race without guessing a settle sleep.
            for _ in 0..2 {
                let deadline = Instant::now() + Duration::from_secs(2);
                loop {
                    assert!(
                        Instant::now() < deadline,
                        "a completed request permanently occupied the slot"
                    );
                    let mut next = client(address);
                    next.write_all(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                        .unwrap();
                    next.shutdown(std::net::Shutdown::Write).unwrap();
                    let mut response = Vec::new();
                    next.take(4096).read_to_end(&mut response).unwrap();
                    if response.starts_with(b"HTTP/1.1 200 OK\r\n") {
                        break;
                    }
                    assert!(response.starts_with(b"HTTP/1.1 503 Service Unavailable\r\n"));
                }
            }
            control.cancel();
            done.recv_timeout(Duration::from_secs(3)).unwrap();
            worker.join().unwrap().unwrap();
            drop(shutdown);
        });
        assert_eq!(timeouts.load(Ordering::Relaxed), 1);
        assert_eq!(requests.load(Ordering::Relaxed), 4);
        assert!(TcpListener::bind(address).is_ok());
    }
}

#[test]
fn cancellation_wakes_a_paused_handler_before_server_join() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let control = Control::new();
    let (entered, active) = mpsc::sync_channel(1);
    let (finished, done) = mpsc::sync_channel(1);
    std::thread::scope(|scope| {
        let shutdown = CancelOnDrop(control.clone());
        let server_control = &control;
        let worker = scope.spawn(move || {
            let result = http::serve(
                listener,
                1,
                1,
                server_control,
                |_, _| {
                    assert!(server_control.toggle_pause()?);
                    entered.send(()).unwrap();
                    server_control.checkpoint()
                },
                |_| (),
            );
            finished.send(()).unwrap();
            result
        });
        let _socket = client(address);
        active.recv_timeout(Duration::from_secs(2)).unwrap();
        control.cancel();
        done.recv_timeout(Duration::from_secs(3)).unwrap();
        worker.join().unwrap().unwrap();
        drop(shutdown);
    });
    assert!(control.is_canceled());
}
