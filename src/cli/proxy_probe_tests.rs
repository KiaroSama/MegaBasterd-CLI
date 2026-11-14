//! Probe verdicts and worker deadlines stay useful without disclosing stored credentials.
#![allow(clippy::unwrap_used)]

use std::{
    fs,
    net::TcpListener,
    path::Path,
    sync::{Arc, Condvar, Mutex},
    time::Duration,
};

use super::*;
use crate::{
    cli::{args::Cli, auto_account_peer_tests::Capture, dispatch},
    storage::proxies::ProxyStore,
    terminal::output::Output,
};
use clap::Parser;

#[test]
fn parsed_proxy_probe_includes_configured_urls_and_reports_yes_no_with_safe_reasons() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/proxy-probe");
    fs::create_dir_all(&base).unwrap();
    let scratch = crate::test_support::tempdir_in(base).unwrap();
    let live = TcpListener::bind("127.0.0.1:0").unwrap();
    let unused = TcpListener::bind("127.0.0.1:0").unwrap();
    let dead = unused.local_addr().unwrap();
    drop(unused);
    let stdout = Capture::default();
    let stderr = Capture::default();
    let mut context = Context::test_context(scratch.path());
    context.config.timeout_seconds = 1;
    context.output = Output::with_writers(false, false, stdout.clone(), stderr.clone());
    let logger = Arc::new(crate::terminal::logging::Logger::start(&context.paths.logs).unwrap());
    let log_path = context.paths.logs.join(logger.name());
    context.output.attach_logger(logger.clone()).unwrap();
    context.logger = Some(logger);
    let stored = format!("alice:SENTINEL_PASSWORD@{dead}");
    ProxyStore::new(context.paths.proxies())
        .update(|urls| urls.push(stored.clone()))
        .unwrap();
    context.config.smart_proxy_url = Some(format!(
        "http://bob:SENTINEL_PASSWORD@{}",
        live.local_addr().unwrap()
    ));
    assert!(!context.config.smart_proxy_enabled);
    let command = || {
        Cli::try_parse_from(["mb", "proxy", "test"])
            .unwrap()
            .command
            .unwrap()
    };
    assert_eq!(dispatch(&mut context, command()).unwrap(), 0);
    let text = String::from_utf8(std::mem::take(&mut *stdout.0.lock().unwrap())).unwrap();
    // A refused loopback connection can reach the configured deadline before
    // Windows reports its socket error. Both remain controlled unavailable probes.
    let unavailable = |text: &str| {
        text.contains("IoError")
            || text.contains("TimeoutError")
            || text.contains("no answer within 1s")
    };
    assert!(
        text.contains("yes") && text.contains("no") && text.contains("ms") && unavailable(&text),
        "{text}"
    );
    assert!(text.contains("127.0.0.1") && !text.contains("SENTINEL_PASSWORD"));
    assert!(
        String::from_utf8(stderr.0.lock().unwrap().clone())
            .unwrap()
            .contains("1/2 reachable")
    );
    // A successful TCP probe closes its socket immediately, without a protocol request.
    let (mut accepted, _) =
        crate::protocol::test_peer::accept_ready(&live, Duration::from_secs(1)).unwrap();
    accepted
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    use std::io::Read;
    assert_eq!(accepted.read(&mut [0]).unwrap(), 0);
    context.config.smart_proxy_url = None;
    let error = dispatch(&mut context, command()).unwrap_err();
    assert_eq!(error.exit_code(), 1);
    let text = String::from_utf8(std::mem::take(&mut *stdout.0.lock().unwrap())).unwrap();
    assert!(text.contains("no") && unavailable(&text), "{text}");
    assert!(!text.contains("SENTINEL_PASSWORD"));
    assert_eq!(
        ProxyStore::new(context.paths.proxies()).list().unwrap(),
        [stored]
    );
    let raw = format!(
        "http://alice:SENTINEL_PASSWORD@{}",
        live.local_addr().unwrap()
    );
    ProxyStore::new(context.paths.proxies())
        .update(|urls| *urls = vec![raw.clone()])
        .unwrap();
    stderr.0.lock().unwrap().clear();
    assert_eq!(dispatch(&mut context, command()).unwrap(), 0);
    let text = String::from_utf8(std::mem::take(&mut *stdout.0.lock().unwrap())).unwrap();
    assert!(text.contains("yes") && text.contains("ms") && text.contains("127.0.0.1"));
    assert!(!text.contains("SENTINEL_PASSWORD"));
    assert!(
        String::from_utf8(stderr.0.lock().unwrap().clone())
            .unwrap()
            .contains("1/1 reachable")
    );
    assert_eq!(
        ProxyStore::new(context.paths.proxies()).list().unwrap(),
        [raw]
    );
    let (mut accepted, _) =
        crate::protocol::test_peer::accept_ready(&live, Duration::from_secs(1)).unwrap();
    accepted
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    assert_eq!(accepted.read(&mut [0]).unwrap(), 0);
    let qualified = format!("http://bob:SENTINEL_PASSWORD@{dead}");
    ProxyStore::new(context.paths.proxies())
        .update(|urls| *urls = vec![qualified])
        .unwrap();
    assert_eq!(
        dispatch(&mut context, command()).unwrap_err().exit_code(),
        1
    );
    let text = String::from_utf8(std::mem::take(&mut *stdout.0.lock().unwrap())).unwrap();
    assert!(text.contains("127.0.0.1") && !text.contains("SENTINEL_PASSWORD"));
    ProxyStore::new(context.paths.proxies())
        .update(Vec::clear)
        .unwrap();
    assert_eq!(
        dispatch(&mut context, command()).unwrap_err().exit_code(),
        1
    );
    assert!(stdout.0.lock().unwrap().is_empty());
    context.finish(1);
    assert!(
        !fs::read_to_string(log_path)
            .unwrap()
            .contains("SENTINEL_PASSWORD")
    );
}

#[test]
fn parsed_hostname_only_entry_reports_a_controlled_failure_without_losing_the_stored_value() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/proxy-probe");
    fs::create_dir_all(&base).unwrap();
    let scratch = crate::test_support::tempdir_in(base).unwrap();
    let stdout = Capture::default();
    let stderr = Capture::default();
    let mut context = Context::test_context(scratch.path());
    context.config.timeout_seconds = 1;
    context.output = Output::with_writers(false, false, stdout.clone(), stderr.clone());
    let command = Cli::try_parse_from(["mb", "proxy", "add", "not-a-proxy"])
        .unwrap()
        .command
        .unwrap();
    assert_eq!(dispatch(&mut context, command).unwrap(), 0);
    let store = ProxyStore::new(context.paths.proxies());
    assert_eq!(store.list().unwrap(), ["not-a-proxy"]);
    let before = fs::read(context.paths.proxies()).unwrap();
    stdout.0.lock().unwrap().clear();
    stderr.0.lock().unwrap().clear();
    let error = run_with(&context, store.list().unwrap(), 1, |url, timeout, _| {
        assert_eq!(url, "not-a-proxy");
        assert_eq!(timeout, Duration::from_secs(1));
        Err(Error::protocol("controlled DNS refusal"))
    })
    .unwrap_err();
    assert_eq!(error.exit_code(), 1);
    assert!(matches!(&error, Error::Protocol(_)));
    context.report_error(&error);
    let text = String::from_utf8(stdout.0.lock().unwrap().clone()).unwrap();
    assert_eq!(
        text,
        "URL | Reachable | Latency / reason\nnot-a-proxy | no | ProtocolError: endpoint DNS failed or was refused\n"
    );
    let diagnostic = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
    assert!(diagnostic.contains("0/1 reachable") && diagnostic.contains("No configured proxy"));
    assert!(!diagnostic.contains("controlled DNS refusal") && !diagnostic.contains("panicked"));
    assert_eq!(fs::read(context.paths.proxies()).unwrap(), before);
    assert_eq!(store.list().unwrap(), ["not-a-proxy"]);
}

#[test]
fn probe_engine_overlaps_two_callbacks_and_passes_the_configured_timeout_unchanged() {
    let entered = (Mutex::new(0usize), Condvar::new());
    let rows = probe_all(
        vec!["first".into(), "second".into()],
        Duration::from_secs(7),
        2,
        &Control::new(),
        |_, timeout, _| {
            assert_eq!(timeout, Duration::from_secs(7));
            let mut count = entered.0.lock().unwrap();
            *count += 1;
            entered.1.notify_all();
            let (count, wait) = entered
                .1
                .wait_timeout_while(count, Duration::from_secs(2), |count| *count != 2)
                .unwrap();
            assert!(!wait.timed_out() && *count == 2, "probes ran serially");
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|row| matches!(row, Verdict::Reachable(_))));
    let raw = "http://alice:SENTINEL_PASSWORD@127.0.0.1:9001";
    let rows = probe_all(
        vec![raw.into()],
        Duration::from_secs(7),
        1,
        &Control::new(),
        |value, _, _| {
            assert_eq!(value, raw, "display redaction changed the network input");
            Ok(())
        },
    )
    .unwrap();
    assert!(matches!(&rows[0], Verdict::Reachable(_)));
    for (value, expected) in [
        (None, 64),
        (Some("1"), 1),
        (Some("2"), 2),
        (Some("100"), 64),
    ] {
        assert_eq!(worker_limit(100, value).unwrap(), expected);
    }
    for value in ["0", "no", "-1"] {
        assert!(worker_limit(2, Some(value)).is_err());
    }
}

#[test]
fn probe_cancellation_wakes_an_entered_worker_and_joins_before_return() {
    let control = Control::new();
    let (entered, ready) = std::sync::mpsc::sync_channel(1);
    std::thread::scope(|scope| {
        struct CancelOnDrop(Control);
        impl Drop for CancelOnDrop {
            fn drop(&mut self) {
                self.0.cancel();
            }
        }
        let _cleanup = CancelOnDrop(control.clone());
        let worker = scope.spawn(|| {
            probe_all(
                vec!["first".into()],
                Duration::from_secs(7),
                1,
                &control,
                |_, _, stop| {
                    entered.send(()).unwrap();
                    stop.wait(Duration::from_secs(7))
                },
            )
        });
        ready.recv_timeout(Duration::from_secs(2)).unwrap();
        control.cancel();
        assert!(matches!(worker.join().unwrap(), Err(Error::Canceled)));
    });
}

#[test]
fn probe_command_reports_timed_out_and_unstarted_entries_within_its_budget_and_joins_workers() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Active<'a>(&'a AtomicUsize);
    impl Drop for Active<'_> {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/proxy-probe");
    fs::create_dir_all(&base).unwrap();
    for count in [1, 2] {
        let scratch = crate::test_support::tempdir_in(&base).unwrap();
        let stdout = Capture::default();
        let stderr = Capture::default();
        let mut context = Context::test_context(scratch.path());
        context.config.timeout_seconds = 1;
        context.output = Output::with_writers(false, false, stdout.clone(), stderr.clone());
        let urls: Vec<_> = (0..count)
            .map(|index| format!("http://alice:SENTINEL_PASSWORD@127.0.0.1:{}", 9201 + index))
            .collect();
        let started = AtomicUsize::new(0);
        let active = AtomicUsize::new(0);
        let begin = Instant::now();
        let error = run_with(&context, urls.clone(), 1, |url, timeout, stop| {
            assert_eq!(url, urls[0], "display redaction changed the network input");
            assert_eq!(timeout, Duration::from_secs(1));
            started.fetch_add(1, Ordering::SeqCst);
            active.fetch_add(1, Ordering::SeqCst);
            let _active = Active(&active);
            stop.wait(Duration::from_secs(3))
        })
        .unwrap_err();
        let ceiling = if count == 1 {
            Duration::from_millis(2500)
        } else {
            Duration::from_secs(4)
        };
        assert!(
            begin.elapsed() < ceiling,
            "probe command exceeded its run budget"
        );
        assert_eq!(error.exit_code(), 1);
        assert!(matches!(error, Error::Protocol(_)));
        assert_eq!(started.load(Ordering::SeqCst), 1);
        assert_eq!(
            active.load(Ordering::SeqCst),
            0,
            "probe worker outlived the report"
        );
        let table = String::from_utf8(stdout.0.lock().unwrap().clone()).unwrap();
        let diagnostic = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
        assert!(table.contains("no answer within 1s"));
        assert_eq!(
            table.contains("not probed within the run budget"),
            count == 2
        );
        assert!(diagnostic.contains(&format!("0/{count} reachable")));
        assert!(!table.contains("SENTINEL_PASSWORD") && !diagnostic.contains("SENTINEL_PASSWORD"));
        assert!(!table.contains("CancelledError") && !diagnostic.contains("CancelledError"));
        assert!(!context.paths.logs.exists());
    }
    let control = Control::new();
    control.cancel();
    assert!(matches!(
        probe_all(
            vec!["unused".into()],
            Duration::from_secs(7),
            1,
            &control,
            |_, _, _| panic!("canceled probe started")
        ),
        Err(Error::Canceled)
    ));
}
