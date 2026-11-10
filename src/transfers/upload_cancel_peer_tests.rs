//! Cancellation of an actually pending upload receipt never commits coverage or registers a node.
#![allow(clippy::unwrap_used)]

use super::*;
use std::{
    io::{Read, Write},
    sync::mpsc,
    time::Duration,
};

#[test]
fn pending_upload_token_cancellation_closes_without_retry_coverage_or_registration() {
    let scratch = scratch();
    let source = source(scratch.path(), 17);
    let original = std::fs::read(&source).unwrap();
    let states = scratch.path().join("private state");
    let vault = Vault::new("synthetic upload passphrase");
    let (pending, waiting) = mpsc::sync_channel(1);
    let (closed, closure) = mpsc::sync_channel(1);
    let control = Control::new();
    let peer_control = control.clone();
    let ((), calls) = test_peer::with_raw_peer(
        move |request, stream| {
            if request.path.starts_with("/cs?") {
                assert_eq!(command(request), json!({"a":"u","s":17}));
                let body = serde_json::to_vec(&json!([{"p":SLOT}])).unwrap();
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
                stream.write_all(&body).unwrap();
                stream.flush().unwrap();
                return;
            }
            assert_eq!(request.method, "POST");
            assert_eq!(request.path, "/native-peer-upload/slot/0");
            assert_eq!(request.body.len(), 17);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                TOKEN.len()
            )
            .unwrap();
            stream.write_all(&TOKEN.as_bytes()[..1]).unwrap();
            stream.flush().unwrap();
            // Start the observation budget after slot/key preparation, never around its KDF.
            let observed = waiting.recv_timeout(Duration::from_secs(2));
            peer_control.cancel();
            assert!(
                observed.is_ok(),
                "upload never reached a pending body after token data"
            );
            match stream.read(&mut [0]) {
                Ok(0) => (),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::UnexpectedEof
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                    ) => {}
                other => panic!("canceled upload left its receipt body open: {other:?}"),
            }
            closed.send(()).unwrap();
        },
        |address| {
            let mut cloud = cloud(address);
            cloud.api.transport =
                crate::protocol::transport::Transport::test_peer(address, control.clone()).unwrap();
            cloud.api.control = control.clone();
            cloud.api.transport.timeout = Duration::from_secs(60);
            cloud
                .api
                .transport
                .observe_body_pending("/native-peer-upload/slot/0", pending);
            let error = transfer(&mut cloud, &source, &states, &vault)
                .err()
                .unwrap();
            assert!(matches!(error, Error::Canceled));
            assert_eq!(error.exit_code(), 130);
            closure.recv_timeout(Duration::from_secs(2)).unwrap();
            let saved_paths: Vec<_> = std::fs::read_dir(&states)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .filter(|path| {
                    path.extension()
                        .is_some_and(|extension| extension == "json")
                })
                .collect();
            assert_eq!(saved_paths.len(), 1);
            let saved = States::new(&saved_paths[0]).load().unwrap().unwrap();
            assert!(saved.completed.is_empty());
            assert!(saved.completion_token.is_none());
            assert!(!saved.registration_started);
            assert!(saved.registered_handle.is_none());
            assert_eq!(std::fs::read(&source).unwrap(), original);
            assert!(
                crate::storage::files::Store::new(saved_paths[0].with_extension("lease"))
                    .with_timeout(Duration::ZERO)
                    .lock()
                    .is_ok()
            );
            let next = scratch.path().join("next.bin");
            std::fs::write(&next, b"next").unwrap();
            let documents = || {
                std::fs::read_dir(&states)
                    .unwrap()
                    .map(|entry| {
                        let path = entry.unwrap().path();
                        assert!(path.is_file());
                        let bytes = std::fs::read(&path).unwrap();
                        (path, bytes)
                    })
                    .collect::<BTreeMap<_, _>>()
            };
            let before = documents();
            let error = transfer_to(
                &mut cloud,
                &next,
                &states,
                &vault,
                "target",
                "next-canceled-operation",
            )
            .err()
            .unwrap();
            assert!(matches!(error, Error::Canceled));
            assert_eq!(error.exit_code(), 130);
            assert!(control.is_canceled() && cloud.api.control.is_canceled());
            assert_eq!(
                documents(),
                before,
                "canceled entry created new upload intent"
            );
            assert_eq!(std::fs::read(&next).unwrap(), b"next");
            assert_eq!(std::fs::read(&source).unwrap(), original);
        },
    );
    assert_eq!(
        calls.len(),
        2,
        "canceled upload retried, refreshed or registered"
    );
}
