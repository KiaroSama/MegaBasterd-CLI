//! Cancellation of an actually pending body closes the socket and preserves uncommitted state.
#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn pending_download_body_cancellation_never_commits_plaintext_or_retries() {
    for verify in [false, true] {
        let fixture = Fixture::new(17);
        let scratch = scratch();
        let destination = scratch.path().join("pending.bin");
        let states = scratch.path().join("private state");
        let (pending, waiting) = mpsc::sync_channel(1);
        let (closed, closure) = mpsc::sync_channel(1);
        let ((), calls) = test_peer::with_raw_peer(
            |request, stream| {
                assert_eq!(request.method, "GET");
                assert_eq!(request.path, "/cdn");
                assert_eq!(request.headers["range"], "bytes=0-16");
                stream.write_all(b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-16/17\r\nContent-Length: 17\r\nConnection: close\r\n\r\n").unwrap();
                stream.write_all(&fixture.ciphertext[..1]).unwrap();
                stream.flush().unwrap();
                match stream.read(&mut [0]) {
                    Ok(0) => (),
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::UnexpectedEof
                                | std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionAborted
                        ) =>
                    {
                        ()
                    }
                    other => panic!("canceled download left its pending body open: {other:?}"),
                }
                closed.send(()).unwrap();
            },
            |address| {
                let mut api = Api::test_peer(address).unwrap();
                api.transport.timeout = Duration::from_secs(60);
                api.transport.observe_body_pending("/cdn", pending);
                let control = api.control.clone();
                let cancel_control = control.clone();
                let progress = Progress::new(false);
                let item = progress.add("fixture", fixture.size).unwrap();
                std::thread::scope(|scope| {
                    let cancel = scope.spawn(move || {
                        let observed = waiting.recv_timeout(Duration::from_secs(2));
                        // Cancel even on a failed observation so a broken fixture cannot wait 60s.
                        cancel_control.cancel();
                        assert!(
                            observed.is_ok(),
                            "download never reached a pending body after reading data"
                        );
                    });
                    let result = download(
                        api,
                        fixture.info(address),
                        &destination,
                        &states,
                        &options(verify),
                        &RateLimiter::new(0.0).unwrap(),
                        &progress,
                        item,
                        &control,
                    );
                    cancel.join().unwrap();
                    let error = result.unwrap_err();
                    assert!(matches!(error, Error::Canceled));
                    assert_eq!(error.exit_code(), 130);
                });
                closure.recv_timeout(Duration::from_secs(2)).unwrap();
                assert!(!destination.exists());
                let saved = States::new(state_path(&states, &destination))
                    .load()
                    .unwrap()
                    .unwrap();
                assert!(saved.completed.is_empty());
                let stage =
                    std::fs::read(scratch.path().join(saved.staging_name.unwrap())).unwrap();
                assert_eq!(stage, [0; 17]);
                let claim =
                    crate::transfers::claims::Claim::acquire(&destination, false, |_| Ok(true))
                        .unwrap();
                assert_eq!(claim.path, destination);
            },
        );
        assert_eq!(
            calls.len(),
            1,
            "canceled pending body was replayed or refreshed"
        );
    }
}
