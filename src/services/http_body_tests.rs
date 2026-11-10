//! Real body writes retain byte offsets and release stalled socket owners.
#![allow(clippy::unwrap_used)]

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{Mutex, mpsc},
    time::{Duration, Instant},
};

use super::{read_head, reply, serve, write_body};
use crate::{error::Error, transfers::control::Control};

fn client(address: SocketAddr) -> TcpStream {
    let socket = TcpStream::connect_timeout(&address, Duration::from_secs(2)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    socket
}

fn status(address: SocketAddr) -> u16 {
    let mut socket = client(address);
    socket
        .write_all(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    socket.shutdown(std::net::Shutdown::Write).unwrap();
    let mut response = Vec::new();
    socket.take(4096).read_to_end(&mut response).unwrap();
    assert!(response.len() < 4096);
    std::str::from_utf8(&response)
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}

struct CancelOnDrop(Control);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

#[test]
fn stalled_body_timeout_releases_actual_server_capacity_without_cancellation() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let control = Control::new();
    let (entered, active) = mpsc::sync_channel(1);
    let (start, allowed) = mpsc::sync_channel(1);
    let allowed = Mutex::new(allowed);
    let (timed_out, timeout) = mpsc::sync_channel(1);
    let (finished, done) = mpsc::sync_channel(1);
    let requests = AtomicUsize::new(0);
    let body: Vec<_> = (0..1024 * 1024).map(|index| (index % 251) as u8).collect();
    std::thread::scope(|scope| {
        let shutdown = CancelOnDrop(control.clone());
        let server_control = &control;
        let body = &body;
        let requests = &requests;
        let allowed = &allowed;
        let worker = scope.spawn(move || {
            let result = serve(
                listener,
                1,
                1,
                server_control,
                |socket, _| {
                    let request = read_head(socket, Duration::from_secs(2), server_control)?;
                    if requests.fetch_add(1, Ordering::Relaxed) == 0 {
                        assert_eq!(request.method, "GET");
                        let send = tokio::net::TcpSocket::from_std_stream(socket.try_clone()?);
                        send.set_send_buffer_size(4096)?;
                        drop(send);
                        reply(
                            socket,
                            200,
                            &[("Content-Length", body.len().to_string())],
                            b"",
                        )?;
                        entered.send(()).unwrap();
                        allowed
                            .lock()
                            .unwrap()
                            .recv_timeout(Duration::from_secs(3))
                            .unwrap();
                        return write_body(
                            socket,
                            body,
                            server_control,
                            Instant::now() + Duration::from_secs(3),
                            Duration::from_millis(400),
                        );
                    }
                    assert_eq!(request.method, "HEAD");
                    reply(socket, 200, &[], b"")
                },
                |error| {
                    assert!(matches!(error, Error::Timeout));
                    timed_out.send(()).unwrap();
                },
            );
            finished.send(result).unwrap();
        });
        let mut stalled = client(address);
        let receive = tokio::net::TcpSocket::from_std_stream(stalled.try_clone().unwrap());
        receive.set_recv_buffer_size(4096).unwrap();
        drop(receive);
        stalled
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        active.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(status(address), 503);
        start.send(()).unwrap();
        timeout.recv_timeout(Duration::from_secs(3)).unwrap();
        assert!(
            !control.is_canceled(),
            "cancellation cannot prove idle expiration"
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            assert!(
                Instant::now() < deadline,
                "stalled writer retained its server slot"
            );
            match status(address) {
                200 => break,
                503 => (),
                code => panic!("unexpected recovery status: {code}"),
            }
        }
        assert_eq!(requests.load(Ordering::Relaxed), 2);
        control.cancel();
        done.recv_timeout(Duration::from_secs(3)).unwrap().unwrap();
        worker.join().unwrap();
        drop(stalled);
        drop(shutdown);
    });
    assert!(TcpListener::bind(address).is_ok());
}

#[test]
fn real_body_writer_preserves_offsets_and_releases_on_idle_deadline_and_cancellation() {
    for mode in [
        "reading",
        "idle",
        "deadline",
        "cancel",
        "paused-idle",
        "paused-deadline",
    ] {
        let reading = mode == "reading";
        let paused = mode.starts_with("paused-");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let mut client = TcpStream::connect_timeout(&address, Duration::from_secs(2)).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let receive = tokio::net::TcpSocket::from_std_stream(client.try_clone().unwrap());
        receive.set_recv_buffer_size(4096).unwrap();
        drop(receive);
        let (mut socket, _) = listener.accept().unwrap();
        socket.set_nonblocking(false).unwrap();
        let send = tokio::net::TcpSocket::from_std_stream(socket.try_clone().unwrap());
        send.set_send_buffer_size(4096).unwrap();
        drop(send);
        let size = if reading { 33 * 1024 } else { 1024 * 1024 };
        let expected: Vec<_> = (0..size).map(|n| (n % 251) as u8).collect();
        let control = Control::new();
        let (finished, done) = mpsc::sync_channel(1);
        std::thread::scope(|scope| {
            let shutdown = CancelOnDrop(control.clone());
            let control = &control;
            let bytes = &expected;
            let writer = scope.spawn(move || {
                let result = write_body(
                    &mut socket,
                    bytes,
                    control,
                    Instant::now()
                        + if matches!(mode, "deadline" | "paused-deadline") {
                            Duration::from_millis(400)
                        } else {
                            Duration::from_secs(3)
                        },
                    if matches!(mode, "idle" | "paused-idle") {
                        Duration::from_millis(400)
                    } else {
                        Duration::from_secs(2)
                    },
                );
                drop(socket);
                finished.send(result).unwrap();
            });
            if reading {
                let mut actual = Vec::new();
                client
                    .by_ref()
                    .take(expected.len() as u64 + 1)
                    .read_to_end(&mut actual)
                    .unwrap();
                assert_eq!(actual, expected);
                done.recv_timeout(Duration::from_secs(3)).unwrap().unwrap();
            } else {
                let mut actual = Vec::new();
                if mode == "cancel" || paused {
                    let mut byte = [0];
                    client.read_exact(&mut byte).unwrap();
                    actual.push(byte[0]);
                    if paused {
                        assert!(control.toggle_pause().unwrap());
                    } else {
                        control.cancel();
                    }
                }
                let result = done.recv_timeout(Duration::from_secs(3)).unwrap();
                if mode == "cancel" {
                    assert!(matches!(result, Err(Error::Canceled)));
                } else {
                    assert!(matches!(result, Err(Error::Timeout)));
                    assert!(
                        !control.is_canceled(),
                        "external cancellation cannot prove a deadline"
                    );
                    if paused {
                        assert!(
                            !control.toggle_pause().unwrap(),
                            "deadline handling changed pause state"
                        );
                    }
                }
                client
                    .by_ref()
                    .take(expected.len() as u64 + 1)
                    .read_to_end(&mut actual)
                    .unwrap();
                assert!(actual.len() < expected.len());
                assert_eq!(actual, expected[..actual.len()]);
            }
            writer.join().unwrap();
            drop(shutdown);
        });
    }
}
