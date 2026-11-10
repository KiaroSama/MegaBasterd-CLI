//! Fetch failure privacy, partial success, and cancellation use the actual command path.
#![allow(clippy::unwrap_used)]

use std::{
    fs,
    io::{Read, Write},
    path::Path,
    sync::Arc,
};

use super::{args::Cli, auto_account_peer_tests::Capture, context::Context, dispatch, proxy};
use crate::{
    error::Error,
    protocol::{
        api::Api,
        test_peer::{self, Response},
    },
    storage::proxies::ProxyStore,
    terminal::{logging::Logger, output::Output},
};
use clap::Parser;

#[test]
fn parsed_proxy_fetch_cancellation_preserves_the_pool_after_a_request_with_or_without_headers() {
    for headers in [false, true] {
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/proxy-fetch");
        fs::create_dir_all(&base).unwrap();
        let scratch = tempfile::tempdir_in(base).unwrap();
        let store = ProxyStore::new(Context::test_context(scratch.path()).paths.proxies());
        store
            .update(|urls| urls.push("http://existing.example:8080".into()))
            .unwrap();
        let path = Context::test_context(scratch.path()).paths.proxies();
        let before = fs::read(&path).unwrap();
        let stdout = Capture::default();
        let stderr = Capture::default();
        let (send_control, receive_control) =
            std::sync::mpsc::sync_channel::<crate::transfers::control::Control>(1);
        let ((), calls) = test_peer::with_raw_peer(
            move |request, stream| {
                assert_eq!(request.method, "GET");
                assert_eq!(request.path, "/canceled?token=SENTINEL_TOKEN");
                if headers {
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\nConnection: close\r\n\r\n",
                        )
                        .unwrap();
                    stream.flush().unwrap();
                }
                // Cancellation follows a captured real request, never a pre-dispatch shortcut.
                receive_control
                    .recv_timeout(std::time::Duration::from_secs(2))
                    .unwrap()
                    .cancel();
                match stream.read(&mut [0]) {
                    Ok(0) => (),
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::UnexpectedEof
                                | std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionAborted
                        ) => {}
                    other => panic!("canceled fetch did not close its socket: {other:?}"),
                }
            },
            |address| {
                let mut context = Context::test_peer(
                    scratch.path(),
                    Api::test_peer(address).unwrap(),
                    Output::with_writers(false, false, stdout.clone(), stderr.clone()),
                );
                send_control.send(context.control.clone()).unwrap();
                let source = format!(
                    "https://testserver.com:{}/canceled?token=SENTINEL_TOKEN",
                    address.port()
                );
                let command = Cli::try_parse_from(["mb", "proxy", "fetch", "--source", &source])
                    .unwrap()
                    .command
                    .unwrap();
                let error = dispatch(&mut context, command).unwrap_err();
                assert!(matches!(error, Error::Canceled));
                assert_eq!(error.exit_code(), 130);
                context.report_error(&error);
                assert_eq!(fs::read(&path).unwrap(), before);
            },
        );
        assert_eq!(calls.len(), 1);
        assert!(stdout.0.lock().unwrap().is_empty());
        let text = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
        assert!(text.contains("canceled"));
        assert!(
            !text.contains("No proxies fetched")
                && !text.contains("[SUCCESS]")
                && !text.contains("[OK]")
        );
        assert!(!text.contains("SENTINEL_TOKEN"));
    }
}

#[test]
fn actual_fetch_sources_preserve_partial_success_and_use_host_only_typed_diagnostics() {
    for partial in [false, true] {
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/proxy-fetch");
        fs::create_dir_all(&base).unwrap();
        let scratch = tempfile::tempdir_in(base).unwrap();
        let paths = Context::test_context(scratch.path()).paths;
        let store = ProxyStore::new(paths.proxies());
        store
            .update(|urls| urls.push("http://existing.example:8080".into()))
            .unwrap();
        let before = fs::read(paths.proxies()).unwrap();
        let stdout = Capture::default();
        let stderr = Capture::default();
        let logger = Arc::new(Logger::start(&paths.logs).unwrap());
        let log_path = paths.logs.join(logger.name());
        let ((), calls) = test_peer::with_peer(
            |request| {
                assert_eq!(request.method, "GET");
                match request.path.as_str() {
                    "/failed?token=SENTINEL_TOKEN" => None,
                    "/valid?api_key=SENTINEL_PASSWORD" if partial => {
                        // Network I/O must not hold the merge lock or overwrite a newer commit.
                        store
                            .update(|urls| {
                                urls.push("http://added-during-fetch.example:8080".into())
                            })
                            .unwrap();
                        Some(Response {
                            status: 200,
                            headers: vec![],
                            body: b"1.2.3.4:8080\n".to_vec(),
                        })
                    }
                    "/valid?api_key=SENTINEL_PASSWORD" => None,
                    _ => panic!("unexpected proxy source"),
                }
            },
            |address| {
                let output = Output::with_writers(false, false, stdout.clone(), stderr.clone());
                output.attach_logger(logger.clone()).unwrap();
                let mut context =
                    Context::test_peer(scratch.path(), Api::test_peer(address).unwrap(), output);
                context.logger = Some(logger.clone());
                let sources = [
                    format!(
                        "https://testserver.com:{}/failed?token=SENTINEL_TOKEN",
                        address.port()
                    ),
                    format!(
                        "https://testserver.com:{}/valid?api_key=SENTINEL_PASSWORD",
                        address.port()
                    ),
                ];
                let result = proxy::fetch_sources(&mut context, &store, "http", &sources, 5, 5);
                if partial {
                    result.unwrap();
                    assert_eq!(
                        store.list().unwrap(),
                        [
                            "http://existing.example:8080",
                            "http://added-during-fetch.example:8080",
                            "http://1.2.3.4:8080"
                        ]
                    );
                } else {
                    let error = result.unwrap_err();
                    assert!(
                        matches!(&error, Error::Protocol(message) if message.contains("No proxies fetched"))
                    );
                    context.report_error(&error);
                    assert_eq!(fs::read(paths.proxies()).unwrap(), before);
                }
                context.finish(i32::from(!partial));
            },
        );
        assert_eq!(calls.len(), 2);
        assert!(stdout.0.lock().unwrap().is_empty());
        let text = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
        assert!(text.contains("testserver.com") && text.contains("network_error"));
        assert_eq!(text.contains("Fetched 1 http proxy/proxies"), partial);
        let log = fs::read_to_string(log_path).unwrap();
        for secret in [
            "SENTINEL_TOKEN",
            "SENTINEL_PASSWORD",
            "?token=",
            "?api_key=",
            "Errors: [",
            "Traceback",
        ] {
            assert!(!text.contains(secret) && !log.contains(secret));
        }
    }
}

#[test]
fn unsafe_credentialed_source_refuses_without_contact_and_keeps_only_its_host_in_diagnostics() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/proxy-fetch");
    fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    let stdout = Capture::default();
    let stderr = Capture::default();
    let ((), calls) = test_peer::with_peer(
        |_| panic!("credentialed endpoint was contacted"),
        |address| {
            let mut context = Context::test_peer(
                scratch.path(),
                Api::test_peer(address).unwrap(),
                Output::with_writers(false, false, stdout.clone(), stderr.clone()),
            );
            let command = Cli::try_parse_from([
                "mb",
                "proxy",
                "fetch",
                "--source",
                "https://user:SENTINEL_PASSWORD@example.invalid/list?sig=SENTINEL_TOKEN",
            ])
            .unwrap()
            .command
            .unwrap();
            let error = dispatch(&mut context, command).unwrap_err();
            assert_eq!(error.exit_code(), 1);
            context.report_error(&error);
        },
    );
    assert!(calls.is_empty());
    let text = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
    assert!(text.contains("example.invalid") && text.contains("invalid_input"));
    assert!(!text.contains("SENTINEL_PASSWORD") && !text.contains("SENTINEL_TOKEN"));
    assert!(stdout.0.lock().unwrap().is_empty());
}
