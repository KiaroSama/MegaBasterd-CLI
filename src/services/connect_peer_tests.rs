//! Real CONNECT handshakes, forwarding and shutdown with an owned isolated upstream.
#![allow(clippy::unwrap_used)]

use super::*;
use std::sync::{Mutex, mpsc};

struct CancelOnDrop(Control);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

fn socket(address: SocketAddr) -> TcpStream {
    let stream = TcpStream::connect_timeout(&address, Duration::from_secs(2)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
}

fn closed(stream: &mut TcpStream) {
    match stream.read(&mut [0]) {
        Ok(0) => (),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::NotConnected
            ) =>
        {
            ()
        }
        other => panic!("CONNECT endpoint remained open: {other:?}"),
    }
}

#[test]
fn actual_connect_forwards_both_directions_and_cancellation_reaps_the_owned_server() {
    for (expiry, paused) in [
        (None, false),
        (Some(false), false),
        (Some(true), false),
        (Some(false), true),
        (Some(true), true),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let upstream_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut remote = socket(upstream_listener.local_addr().unwrap());
        let upstream = Mutex::new(Some(upstream_listener.accept().unwrap().0));
        drop(upstream_listener);
        let control = Control::new();
        let (diagnostic, diagnostics) = mpsc::sync_channel(1);
        let (finished, done) = mpsc::sync_channel(1);
        std::thread::scope(|scope| {
            let shutdown = CancelOnDrop(control.clone());
            let server_control = &control;
            let upstream = &upstream;
            let worker = scope.spawn(move || {
                let limits = Limits {
                    header: Duration::from_secs(2),
                    idle: if expiry == Some(false) {
                        Duration::from_millis(100)
                    } else {
                        Duration::from_secs(5)
                    },
                    lifetime: if expiry == Some(true) {
                        Duration::from_millis(100)
                    } else {
                        Duration::from_secs(5)
                    },
                };
                let result = http::serve(
                    listener,
                    1,
                    1,
                    server_control,
                    |client, _| {
                        handle_with(
                            client,
                            "test-password",
                            false,
                            server_control,
                            limits,
                            |host, port, _, _| {
                                assert_eq!(host, "g.api.mega.nz");
                                assert_eq!(port, 443);
                                if paused {
                                    assert!(server_control.toggle_pause().unwrap());
                                }
                                Ok(upstream.lock().unwrap().take().unwrap())
                            },
                        )
                    },
                    |error| {
                        diagnostic.send(matches!(error, Error::Timeout)).unwrap();
                    },
                );
                finished.send(()).unwrap();
                result
            });
            let mut client = socket(address);
            client
                .write_all(
                    concat!(
                        "CONNECT g.api.mega.nz:443 HTTP/1.1\r\n",
                        "Proxy-Authorization: Basic dTp0ZXN0LXBhc3N3b3Jk\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .unwrap();
            let expected = b"HTTP/1.1 200 Connection Established\r\n\r\n";
            let mut head = vec![0; expected.len()];
            client.read_exact(&mut head).unwrap();
            assert_eq!(head, expected);
            if expiry.is_none() {
                client.write_all(b"ping").unwrap();
                let mut bytes = [0; 4];
                remote.read_exact(&mut bytes).unwrap();
                assert_eq!(&bytes, b"ping");
                remote.write_all(b"pong").unwrap();
                client.read_exact(&mut bytes).unwrap();
                assert_eq!(&bytes, b"pong");
                control.cancel();
            } else {
                assert!(diagnostics.recv_timeout(Duration::from_secs(2)).unwrap());
                assert!(
                    !control.is_canceled(),
                    "cancellation cannot prove tunnel expiry"
                );
                closed(&mut client);
                closed(&mut remote);
                control.cancel();
            }
            done.recv_timeout(Duration::from_secs(2)).unwrap();
            worker.join().unwrap().unwrap();
            closed(&mut client);
            closed(&mut remote);
            drop(shutdown);
        });
        assert!(
            TcpListener::bind(address).is_ok(),
            "CONNECT server retained its listener"
        );
    }
}

#[test]
fn unfinished_connect_headers_expire_without_dialing_even_when_control_is_paused() {
    for paused in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let control = Control::new();
        if paused {
            assert!(control.toggle_pause().unwrap());
        }
        let (diagnostic, diagnostics) = mpsc::sync_channel(1);
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
                    |client, _| {
                        handle_with(
                            client,
                            "test-password",
                            false,
                            server_control,
                            Limits {
                                header: Duration::from_millis(100),
                                idle: Duration::from_secs(5),
                                lifetime: Duration::from_secs(5),
                            },
                            |_, _, _, _| panic!("unfinished CONNECT header reached outbound dial"),
                        )
                    },
                    |error| {
                        diagnostic.send(matches!(error, Error::Timeout)).unwrap();
                    },
                );
                finished.send(()).unwrap();
                result
            });
            let mut client = socket(address);
            client
                .write_all(b"CONNECT g.api.mega.nz:443 HTTP/1.1\r\n")
                .unwrap();
            assert!(diagnostics.recv_timeout(Duration::from_secs(2)).unwrap());
            assert!(!control.is_canceled());
            // A final rejection may precede closure; bound and inspect the complete local reply.
            let mut response = Vec::new();
            match Read::by_ref(&mut client)
                .take(4096)
                .read_to_end(&mut response)
            {
                Ok(_) => (),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                    ) =>
                {
                    ()
                }
                other => panic!("CONNECT header refusal did not close: {other:?}"),
            }
            assert!(response.len() < 4096, "header reply exhausted its byte cap");
            if !response.is_empty() {
                assert!(response.starts_with(b"HTTP/1.1 400 "));
            }
            closed(&mut client);
            control.cancel();
            done.recv_timeout(Duration::from_secs(2)).unwrap();
            worker.join().unwrap().unwrap();
            drop(shutdown);
        });
        assert!(TcpListener::bind(address).is_ok());
    }
}
