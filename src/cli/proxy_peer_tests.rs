//! Proxy commands preserve source privacy and report unsuccessful work as failure.
#![allow(clippy::unwrap_used)]

use std::{fs, path::Path, sync::Arc};

use super::{args::Cli, auto_account_peer_tests::Capture, context::Context, dispatch};
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

const PROXY: &str = "alice:hunter2@1.2.3.4:8080";

fn command(words: &[&str]) -> super::args::Command {
    Cli::try_parse_from(std::iter::once("mb").chain(words.iter().copied()))
        .unwrap()
        .command
        .unwrap()
}

#[test]
fn parsed_proxy_list_and_remove_preserve_hosts_but_never_credentials_or_secrets_in_logs() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/proxy-cli");
    fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    let stdout = Capture::default();
    let stderr = Capture::default();
    let logger = Arc::new(Logger::start(&scratch.path().join("private logs")).unwrap());
    let log_path = scratch.path().join("private logs").join(logger.name());
    let output = Output::with_writers(false, false, stdout.clone(), stderr.clone());
    output.attach_logger(logger.clone()).unwrap();
    let mut context = Context::test_context(scratch.path());
    context.output = output;
    context.logger = Some(logger);
    for (index, value) in [
        PROXY,
        "socks5://alice:hunter2@1.2.3.4:8080",
        "http://sentinel-user:sentinel-password@example.invalid:8080",
        "http://user:hunter2@host.example:8080",
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(
            dispatch(&mut context, command(&["proxy", "add", value])).unwrap(),
            0
        );
        if index == 2 {
            let listing = scratch.path().join("proxy input.txt");
            fs::write(&listing, format!("{value}\n")).unwrap();
            assert_eq!(
                dispatch(
                    &mut context,
                    command(&["proxy", "import", listing.to_str().unwrap()])
                )
                .unwrap(),
                0
            );
        }
        assert_eq!(
            dispatch(&mut context, command(&["proxy", "list"])).unwrap(),
            0
        );
        let table = String::from_utf8(std::mem::take(&mut *stdout.0.lock().unwrap())).unwrap();
        let host = [
            "1.2.3.4:8080",
            "1.2.3.4:8080",
            "example.invalid:8080",
            "host.example:8080",
        ][index];
        assert!(table.contains(host));
        assert!(table.contains("<redacted>"));
        for forbidden in ["alice", "hunter2", "sentinel-user", "sentinel-password"] {
            assert!(!table.contains(forbidden));
        }
        assert_eq!(
            ProxyStore::new(context.paths.proxies()).list().unwrap(),
            [value]
        );
        assert_eq!(
            dispatch(&mut context, command(&["proxy", "remove", value])).unwrap(),
            0
        );
        assert!(
            ProxyStore::new(context.paths.proxies())
                .list()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            dispatch(&mut context, command(&["proxy", "remove", value])).unwrap(),
            0
        );
    }
    context.finish(0);
    let diagnostic = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
    assert!(diagnostic.contains("Proxy removed") && diagnostic.contains("Proxy not found"));
    let log = fs::read_to_string(log_path).unwrap();
    for forbidden in ["alice", "hunter2", "sentinel-user", "sentinel-password"] {
        assert!(!diagnostic.contains(forbidden) && !log.contains(forbidden));
    }
}

#[test]
fn parsed_proxy_add_refuses_a_corrupt_store_and_keeps_its_exact_private_recovery_copy() {
    use crate::storage::files::Store;

    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/proxy-cli");
    fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    let stdout = Capture::default();
    let stderr = Capture::default();
    let mut context = Context::test_context(scratch.path());
    context.output = Output::with_writers(false, false, stdout.clone(), stderr.clone());
    let path = context.paths.proxies();
    let bytes = br#"["this is a list, not an object"]"#;
    Store::new(&path)
        .lock()
        .unwrap()
        .write_bytes(bytes)
        .unwrap();
    let error = dispatch(
        &mut context,
        command(&["proxy", "add", "http://new.invalid:1"]),
    )
    .unwrap_err();
    assert!(matches!(&error, Error::Corrupt(_)));
    assert_eq!(error.exit_code(), 1);
    context.report_error(&error);
    assert_eq!(fs::read(&path).unwrap(), bytes);
    let name = Store::new(&path).lock().unwrap().preserve().unwrap();
    assert_eq!(fs::read(path.parent().unwrap().join(name)).unwrap(), bytes);
    assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 3);
    assert!(stdout.0.lock().unwrap().is_empty());
    let message = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
    assert!(message.contains("recovery copy was preserved"));
    assert!(
        !message.contains("[SUCCESS]")
            && !message.contains("[OK]")
            && !message.contains("this is a list")
    );
}

#[test]
fn parsed_proxy_fetch_http_failure_preserves_pool_query_routing_and_private_diagnostics() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/proxy-cli");
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
            assert_eq!(request.path, "/list?token=SENTINEL_TOKEN");
            assert!(request.body.is_empty());
            Some(Response {
                status: 503,
                headers: vec![],
                body: b"SENTINEL_PASSWORD SENTINEL_TOKEN".to_vec(),
            })
        },
        |address| {
            let output = Output::with_writers(false, false, stdout.clone(), stderr.clone());
            output.attach_logger(logger.clone()).unwrap();
            let mut context =
                Context::test_peer(scratch.path(), Api::test_peer(address).unwrap(), output);
            context.logger = Some(logger.clone());
            let source = format!(
                "https://testserver.com:{}/list?token=SENTINEL_TOKEN",
                address.port()
            );
            let error = dispatch(
                &mut context,
                command(&["proxy", "fetch", "--source", &source]),
            )
            .unwrap_err();
            assert_eq!(error.exit_code(), 1);
            assert!(
                matches!(&error, Error::Protocol(message) if message.contains("No proxies fetched"))
            );
            context.report_error(&error);
            context.finish(1);
            assert_eq!(fs::read(paths.proxies()).unwrap(), before);
            assert_eq!(store.list().unwrap(), ["http://existing.example:8080"]);
        },
    );
    assert_eq!(calls.len(), 1);
    assert!(stdout.0.lock().unwrap().is_empty());
    let diagnostic = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
    let log = fs::read_to_string(log_path).unwrap();
    assert!(
        diagnostic.contains("No proxies fetched")
            && diagnostic.contains("unsuccessful HTTP status")
    );
    assert!(
        !diagnostic.contains("[SUCCESS]")
            && !diagnostic.contains("[OK]")
            && !diagnostic.contains("Errors: [")
    );
    for forbidden in [
        "SENTINEL_TOKEN",
        "SENTINEL_PASSWORD",
        "?token=",
        "Traceback",
    ] {
        assert!(!diagnostic.contains(forbidden) && !log.contains(forbidden));
    }
}

#[test]
fn parsed_proxy_fetch_caps_a_large_body_keeps_complete_lines_and_closes_the_response() {
    use std::io::{Read, Write};

    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/proxy-cli");
    fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    let paths = Context::test_context(scratch.path()).paths;
    let store = ProxyStore::new(paths.proxies());
    store
        .update(|urls| urls.push("http://existing.example:8080".into()))
        .unwrap();
    let stdout = Capture::default();
    let stderr = Capture::default();
    let prefix = b"1.2.3.4:8080\n5.6.7.8:1080\n9.8.7.6:80\n8.8.8.8:81\n#";
    let tail = b"\n9.9.9.9:999";
    let ((), calls) = test_peer::with_raw_peer(
        |request, stream| {
            assert_eq!(request.method, "GET");
            assert_eq!(request.path, "/large-list");
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 10400000\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
            stream.write_all(prefix).unwrap();
            let block = [b'x'; 64 * 1024];
            let mut remaining = 4 * 1024 * 1024 - prefix.len() - tail.len();
            while remaining != 0 {
                let count = remaining.min(block.len());
                stream.write_all(&block[..count]).unwrap();
                remaining -= count;
            }
            stream.write_all(tail).unwrap();
            stream.flush().unwrap();
            // The remaining advertised bytes never arrive: the bounded reader must close first.
            match stream.read(&mut [0]) {
                Ok(0) => (),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::UnexpectedEof
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                    ) => {}
                other => panic!("capped proxy response was not closed: {other:?}"),
            }
        },
        |address| {
            let output = Output::with_writers(false, false, stdout.clone(), stderr.clone());
            let mut context =
                Context::test_peer(scratch.path(), Api::test_peer(address).unwrap(), output);
            let source = format!("https://testserver.com:{}/large-list", address.port());
            assert_eq!(
                dispatch(
                    &mut context,
                    command(&["proxy", "fetch", "--source", &source, "--limit", "5"])
                )
                .unwrap(),
                0
            );
            assert_eq!(
                store.list().unwrap(),
                [
                    "http://existing.example:8080",
                    "http://1.2.3.4:8080",
                    "http://5.6.7.8:1080",
                    "http://9.8.7.6:80",
                    "http://8.8.8.8:81",
                ]
            );
        },
    );
    assert_eq!(calls.len(), 1);
    assert!(stdout.0.lock().unwrap().is_empty());
    let messages = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
    assert!(messages.contains("truncated at 4194304 bytes"));
    assert!(messages.contains("Fetched 4 http proxy/proxies"));
    assert!(!messages.contains("9.9.9.9") && !messages.contains("No proxies fetched"));
}

#[test]
fn parsed_proxy_serve_missing_password_exits_one_without_starting_a_listener_or_claiming_success() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/proxy-cli");
    fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    let stdout = Capture::default();
    let stderr = Capture::default();
    let mut context = Context::test_context(scratch.path());
    context.output = Output::with_writers(true, false, stdout.clone(), stderr.clone());
    let error = dispatch(&mut context, command(&["proxy", "serve"])).unwrap_err();
    assert!(matches!(&error, Error::Auth(message) if message.contains("password")));
    assert_eq!(error.exit_code(), 1);
    context.report_error(&error);
    let machine: serde_json::Value = serde_json::from_slice(&stdout.0.lock().unwrap()).unwrap();
    assert_eq!(machine["error_code"], "auth_failed");
    assert_eq!(machine["status"], "failed");
    let message = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
    assert!(message.contains("--password"));
    assert!(
        !message.contains("starting at")
            && !message.contains("[SUCCESS]")
            && !message.contains("[OK]")
    );
    assert_eq!(fs::read_dir(scratch.path()).unwrap().count(), 0);
}
