//! Pending direct requests and body reads release their owned socket when canceled.
#![allow(clippy::unwrap_used)]

use std::{
    io::{Read, Write},
    sync::mpsc,
    time::Duration,
};

use reqwest::{Method, header::HeaderMap};
use url::Url;

use crate::protocol::{api::Api, http_wait::observe_pending, test_peer};
use crate::{error::Error, transfers::control::Control};

struct CancelOnDrop(Control);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

#[test]
fn direct_http_cancels_pending_headers_and_body_without_waiting_for_the_request_timeout() {
    for headers_sent in [false, true] {
        let (waiting, ready) = mpsc::sync_channel(1);
        let (reading, body_ready) = mpsc::sync_channel(1);
        let (_, calls) = test_peer::with_raw_peer(
            |request, stream| {
                assert_eq!(request.method, "GET");
                assert_eq!(request.path, "/stalled");
                if headers_sent {
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\nConnection: close\r\n\r\n",
                        )
                        .unwrap();
                    stream.flush().unwrap();
                }
                waiting.send(()).unwrap();
                // The existing peer's five-second I/O ceiling fails if cancellation leaves it open.
                match stream.read(&mut [0; 1]) {
                    Ok(0) => (),
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::UnexpectedEof
                                | std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionAborted
                        ) => {}
                    result => {
                        panic!("canceled client did not close its upstream socket: {result:?}")
                    }
                }
            },
            |address| {
                let mut api = Api::test_peer(address).unwrap();
                api.transport.timeout = Duration::from_secs(60);
                let control = api.control.clone();
                let (finished, done) = mpsc::sync_channel(1);
                std::thread::scope(|scope| {
                    let shutdown = CancelOnDrop(control.clone());
                    let worker = scope.spawn(move || {
                        let _pending = (!headers_sent).then(|| observe_pending(reading.clone()));
                        let result = api.transport.send(
                            Method::GET,
                            Url::parse(&format!(
                                "https://testserver.com:{}/stalled",
                                address.port()
                            ))
                            .unwrap(),
                            HeaderMap::new(),
                            None,
                            false,
                        );
                        let canceled = if headers_sent {
                            let mut reply = result.unwrap();
                            let _pending = observe_pending(reading);
                            let error = reply.response.read(&mut [0; 16]).unwrap_err();
                            error.kind() == std::io::ErrorKind::ConnectionAborted
                        } else {
                            matches!(result, Err(Error::Canceled))
                        };
                        finished.send(canceled).unwrap();
                    });
                    ready.recv_timeout(Duration::from_secs(2)).unwrap();
                    body_ready.recv_timeout(Duration::from_secs(2)).unwrap();
                    control.cancel();
                    assert!(done.recv_timeout(Duration::from_secs(3)).unwrap());
                    worker.join().unwrap();
                    drop(shutdown);
                });
            },
        );
        assert_eq!(calls.len(), 1);
    }
}
