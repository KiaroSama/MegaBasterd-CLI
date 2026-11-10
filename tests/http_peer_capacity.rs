//! Real distinct loopback peers exercise production admission, refusal and capacity recovery.
#![allow(clippy::unwrap_used)]

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::mpsc,
    time::{Duration, Instant},
};

use megabasterd_cli::{services::http, transfers::control::Control};

struct CancelOnDrop(Control);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

fn listener() -> (TcpListener, SocketAddr, SocketAddr) {
    #[cfg(not(target_os = "macos"))]
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        (listener, address, address)
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let socket = tokio::net::TcpSocket::new_v6().unwrap();
        let disabled: libc::c_int = 0;
        // SAFETY: the owned socket stays live; the initialized c_int and its exact length
        // are readable for this synchronous call, and only this fixture's socket is changed.
        let result = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_V6ONLY,
                (&disabled as *const libc::c_int).cast(),
                std::mem::size_of_val(&disabled) as libc::socklen_t,
            )
        };
        assert_eq!(result, 0, "could not configure owned dual-stack fixture");
        socket.bind("[::]:0".parse().unwrap()).unwrap();
        let listener = {
            let _entered = runtime.enter();
            socket.listen(8).unwrap().into_std().unwrap()
        };
        let port = listener.local_addr().unwrap().port();
        (
            listener,
            SocketAddr::from(([127, 0, 0, 1], port)),
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], port)),
        )
    }
}

fn client(address: SocketAddr, other: bool) -> TcpStream {
    // Reuse the fixture reactor: repeatedly creating/dropping kqueue reactors
    // otherwise adds macOS teardown time to the accept-loop latency assertion.
    thread_local! {
        static RUNTIME: tokio::runtime::Runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
    }
    let socket = if address.is_ipv6() {
        tokio::net::TcpSocket::new_v6().unwrap()
    } else {
        tokio::net::TcpSocket::new_v4().unwrap()
    };
    #[cfg(not(target_os = "macos"))]
    socket
        .bind(SocketAddr::from((
            [127, 0, 0, if other { 2 } else { 1 }],
            0,
        )))
        .unwrap();
    #[cfg(target_os = "macos")]
    let _ = other;
    let stream = RUNTIME.with(|runtime| {
        runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(2), socket.connect(address))
                .await
                .unwrap()
                .unwrap()
                .into_std()
                .unwrap()
        })
    });
    stream.set_nonblocking(false).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
}

fn status(address: SocketAddr, other: bool) -> u16 {
    let mut socket = client(address, other);
    socket
        .write_all(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    socket.shutdown(std::net::Shutdown::Write).unwrap();
    let mut response = Vec::new();
    socket.take(4096).read_to_end(&mut response).unwrap();
    assert!(
        response.len() < 4096,
        "local response exceeded its capture bound"
    );
    let line = response.split(|byte| *byte == b'\n').next().unwrap();
    std::str::from_utf8(line)
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}

#[test]
fn actual_distinct_peers_keep_separate_allowances_and_the_global_limit_remains_outermost() {
    for (workers, expected_other) in [(8, 200), (2, 503)] {
        let (listener, first, other) = listener();
        let bound = listener.local_addr().unwrap();
        let control = Control::new();
        let (entered, held) = mpsc::sync_channel(1);
        let (finished, done) = mpsc::sync_channel(1);
        std::thread::scope(|scope| {
            let shutdown = CancelOnDrop(control.clone());
            let server_control = &control;
            let worker = scope.spawn(move || {
                let result = http::serve(
                    listener,
                    workers,
                    2,
                    server_control,
                    |socket, peer| {
                        if peer.ip().to_canonical() == std::net::Ipv4Addr::LOCALHOST {
                            entered.send(()).unwrap();
                        }
                        let request =
                            http::read_head(socket, Duration::from_secs(5), server_control)?;
                        assert_eq!(request.method, "HEAD");
                        http::reply(socket, 200, &[], b"")
                    },
                    |_| (),
                );
                finished.send(result).unwrap();
            });
            let mut stalled = Vec::new();
            for _ in 0..2 {
                let mut socket = client(first, false);
                socket.write_all(b"GET / HTTP/1.1\r\nHost:").unwrap();
                held.recv_timeout(Duration::from_secs(2)).unwrap();
                stalled.push(socket);
            }
            assert_eq!(
                status(first, false),
                503,
                "one address exceeded its own allowance"
            );
            assert_eq!(
                status(other, true),
                expected_other,
                "peer isolation and global admission disagree"
            );
            control.cancel();
            done.recv_timeout(Duration::from_secs(3)).unwrap().unwrap();
            worker.join().unwrap();
            for mut socket in stalled {
                assert_eq!(socket.read(&mut [0]).unwrap(), 0);
            }
            drop(shutdown);
        });
        assert!(TcpListener::bind(bound).is_ok());
    }
}

#[test]
fn open_refused_peers_do_not_block_acceptance_of_a_different_address() {
    let (listener, first, other) = listener();
    let control = Control::new();
    let (entered, held) = mpsc::sync_channel(1);
    let (finished, done) = mpsc::sync_channel(1);
    std::thread::scope(|scope| {
        let shutdown = CancelOnDrop(control.clone());
        let server_control = &control;
        let worker = scope.spawn(move || {
            let result = http::serve(
                listener,
                2,
                1,
                server_control,
                |socket, peer| {
                    if peer.ip().to_canonical() == std::net::Ipv4Addr::LOCALHOST {
                        entered.send(()).unwrap();
                    }
                    let request = http::read_head(socket, Duration::from_secs(5), server_control)?;
                    assert_eq!(request.method, "HEAD");
                    http::reply(socket, 200, &[], b"")
                },
                |_| (),
            );
            finished.send(result).unwrap();
        });
        let mut stalled = client(first, false);
        stalled.write_all(b"GET / HTTP/1.1\r\nHost:").unwrap();
        held.recv_timeout(Duration::from_secs(2)).unwrap();
        let started = Instant::now();
        let mut rejected = Vec::new();
        for _ in 0..30 {
            let mut socket = client(first, false);
            // Keep every write half open. Past the four graceful closers an immediate
            // reset is legitimate, but no refusal may serialize a100ms drain on accept.
            match socket.write_all(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n") {
                Ok(()) => (),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::BrokenPipe
                    ) => {}
                Err(error) => panic!("refusal fixture request failed: {error}"),
            }
            rejected.push(socket);
        }
        assert_eq!(status(other, true), 200);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "refused clients serialized the accept loop"
        );
        control.cancel();
        done.recv_timeout(Duration::from_secs(3)).unwrap().unwrap();
        worker.join().unwrap();
        drop(rejected);
        drop(shutdown);
    });
}
