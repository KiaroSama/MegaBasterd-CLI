//! Admission policy and RAII retirement use the same state as the actual local servers.
#![allow(clippy::unwrap_used)]

use std::{
    collections::HashMap,
    io::Read,
    net::{IpAddr, TcpListener, TcpStream},
    sync::{Arc, Mutex},
    time::Duration,
};

use super::{Active, Connection};
use crate::{error::Error, transfers::control::Control};

#[test]
fn unexpected_accept_failure_reaps_handlers_closes_sockets_and_releases_the_listener() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc,
    };

    struct CancelOnDrop(Control);
    impl Drop for CancelOnDrop {
        fn drop(&mut self) {
            self.0.cancel();
        }
    }
    struct Retire<'a>(&'a AtomicUsize);
    impl Drop for Retire<'_> {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    for with_client in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut client = with_client.then(|| {
            let client = TcpStream::connect_timeout(&address, Duration::from_secs(2)).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            client
        });
        let control = Control::new();
        let active = AtomicUsize::new(0);
        let entered = AtomicUsize::new(0);
        let (ready, admitted) = mpsc::sync_channel(1);
        let (finished, done) = mpsc::sync_channel(1);
        std::thread::scope(|scope| {
            let _cleanup = CancelOnDrop(control.clone());
            let control = &control;
            let active = &active;
            let entered = &entered;
            let worker = scope.spawn(move || {
                let mut accepted = false;
                let result = super::serve_with_accept(
                    listener,
                    1,
                    1,
                    control,
                    |socket, _| {
                        active.fetch_add(1, Ordering::SeqCst);
                        let _retire = Retire(active);
                        entered.fetch_add(1, Ordering::SeqCst);
                        ready.send(()).unwrap();
                        super::read_head(socket, Duration::from_secs(5), control).map(drop)
                    },
                    |_| (),
                    |listener| {
                        if with_client && !accepted {
                            let result = listener.accept();
                            accepted = result.is_ok();
                            return result;
                        }
                        if with_client {
                            admitted.recv_timeout(Duration::from_secs(2)).unwrap();
                        }
                        Err(std::io::Error::other("selector exploded"))
                    },
                );
                finished.send(result).unwrap();
            });
            let error = done
                .recv_timeout(Duration::from_secs(3))
                .unwrap()
                .unwrap_err();
            assert!(
                matches!(error, Error::Io(ref cause) if cause.to_string() == "selector exploded")
            );
            worker.join().unwrap();
            assert!(control.is_canceled());
            assert_eq!(entered.load(Ordering::SeqCst), usize::from(with_client));
            assert_eq!(active.load(Ordering::SeqCst), 0);
            if let Some(client) = &mut client {
                assert_eq!(client.read(&mut [0]).unwrap(), 0);
            }
            assert!(TcpListener::bind(address).is_ok());
        });
    }
}

#[test]
fn distinct_peer_admission_keeps_global_capacity_and_drop_retires_all_peer_entries() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let state = Arc::new(Mutex::new(Active {
        sockets: HashMap::new(),
        peers: HashMap::new(),
    }));
    let first: IpAddr = "127.0.0.1".parse().unwrap();
    let other: IpAddr = "127.0.0.2".parse().unwrap();
    let mut owned = Vec::new();
    let mut clients = Vec::new();
    for id in 1..=2 {
        let client = TcpStream::connect_timeout(&address, Duration::from_secs(2)).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let (socket, _) = listener.accept().unwrap();
        socket.set_nonblocking(false).unwrap();
        let mut active = state.lock().unwrap();
        assert!(active.can_accept(first, 4, 2));
        active.sockets.insert(id, socket.try_clone().unwrap());
        *active.peers.entry(first).or_default() += 1;
        drop(active);
        owned.push(Connection {
            socket,
            peer: first,
            id,
            active: state.clone(),
        });
        clients.push(client);
    }
    {
        let active = state.lock().unwrap();
        assert!(
            !active.can_accept(first, 4, 2),
            "one peer exceeded its own bound"
        );
        assert!(
            active.can_accept(other, 4, 2),
            "one peer starved a different identity"
        );
        assert!(
            !active.can_accept(other, 2, 2),
            "the global bound ignored other peers"
        );
        assert_eq!(active.peers.len(), 1);
        assert_eq!(active.peers[&first], 2);
    }
    drop(owned.pop());
    {
        let active = state.lock().unwrap();
        assert!(active.can_accept(first, 4, 2));
        assert_eq!(active.peers[&first], 1);
        assert_eq!(active.sockets.len(), 1);
    }
    drop(owned);
    {
        let active = state.lock().unwrap();
        assert!(active.sockets.is_empty());
        assert!(
            active.peers.is_empty(),
            "zero-count peer entries were retained"
        );
    }
    for mut client in clients {
        assert_eq!(client.read(&mut [0]).unwrap(), 0);
    }
    // Identities are synthetic: this checks policy, not OS support for binding arbitrary 127/8 aliases.
    for last in 2u8..8 {
        let peer: IpAddr = format!("127.0.0.{last}").parse().unwrap();
        let client = TcpStream::connect_timeout(&address, Duration::from_secs(2)).unwrap();
        let (socket, _) = listener.accept().unwrap();
        let id = u64::from(last);
        {
            let mut active = state.lock().unwrap();
            assert!(active.can_accept(peer, 4, 2));
            active.sockets.insert(id, socket.try_clone().unwrap());
            active.peers.insert(peer, 1);
        }
        let connection = Connection {
            socket,
            peer,
            id,
            active: state.clone(),
        };
        drop(connection);
        drop(client);
        let active = state.lock().unwrap();
        assert!(active.sockets.is_empty());
        assert!(
            active.peers.is_empty(),
            "distinct peer history grew after retirement"
        );
    }
}
