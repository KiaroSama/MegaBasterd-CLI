//! Proxy transactions retain their lock through reload, validation and real private staging.
#![allow(clippy::unwrap_used)]

use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    process::Command,
    time::{Duration, Instant},
};

use serde_json::{Value, json};

use super::{ProxyStore, Store};
use crate::error::Error;

fn fixture() -> crate::test_support::TempDir {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/proxy-transactions");
    fs::create_dir_all(&base).unwrap();
    crate::test_support::tempdir_in(base).unwrap()
}

const PROCESS_TEST: &str = "storage::proxies::transaction_tests::overlapping_proxy_processes_refuse_contention_then_reload_before_retry";
const CHILD_MODE: &str = "MB_PROXY_TRANSACTION_CHILD";

fn message(stream: &mut TcpStream, expected: u8) {
    let mut byte = [0];
    stream.read_exact(&mut byte).unwrap();
    assert_eq!(byte, [expected]);
}

fn accept(listener: &TcpListener) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                return stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "proxy child did not connect");
                std::thread::park_timeout(Duration::from_millis(1));
            }
            Err(error) => panic!("proxy child accept failed: {error}"),
        }
    }
}

#[test]
fn overlapping_proxy_processes_refuse_contention_then_reload_before_retry() {
    use crate::{platform::process, transfers::control::Control};

    if let Some(mode) = std::env::var_os(CHILD_MODE) {
        let path = std::path::PathBuf::from(std::env::var_os("MB_PROXY_TRANSACTION_PATH").unwrap());
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/proxy-transactions");
        assert!(
            path.canonicalize()
                .unwrap()
                .starts_with(base.canonicalize().unwrap())
        );
        let address = std::env::var("MB_PROXY_TRANSACTION_PEER")
            .unwrap()
            .parse::<std::net::SocketAddr>()
            .unwrap();
        assert!(address.ip().is_loopback());
        let mut peer = TcpStream::connect_timeout(&address, Duration::from_secs(3)).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        peer.set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let store = ProxyStore(Store::new(path).with_timeout(Duration::ZERO));
        match mode.to_str().unwrap() {
            "first" => {
                store
                    .update(|urls| {
                        assert_eq!(urls, &["http://seed.invalid:1"]);
                        peer.write_all(b"L").unwrap();
                        message(&mut peer, b'C');
                        urls.push("http://p1.invalid:1".into());
                    })
                    .unwrap();
                peer.write_all(b"D").unwrap();
            }
            "second" => {
                assert!(matches!(
                    store.update(|_| panic!("contended process reached mutation")),
                    Err(Error::Busy(_))
                ));
                peer.write_all(b"B").unwrap();
                message(&mut peer, b'R');
                store
                    .update(|urls| {
                        assert_eq!(urls, &["http://seed.invalid:1", "http://p1.invalid:1"]);
                        urls.push("http://p2.invalid:2".into());
                    })
                    .unwrap();
                peer.write_all(b"D").unwrap();
            }
            _ => panic!("unknown proxy child mode"),
        }
        return;
    }

    let scratch = fixture();
    let path = scratch.path().join("private/proxies.json");
    let store = ProxyStore::new(path.clone());
    store
        .update(|urls| urls.push("http://seed.invalid:1".into()))
        .unwrap();
    let before = fs::read(&path).unwrap();
    let temporary = scratch.path().join("child temporary");
    fs::create_dir(&temporary).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let control = Control::new();
    let run_child = |mode: &str| {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.current_dir(scratch.path()).env_clear();
        for key in [
            "PATH",
            "SystemRoot",
            "WINDIR",
            "PATHEXT",
            "LD_LIBRARY_PATH",
            "DYLD_LIBRARY_PATH",
        ] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        for key in [
            "HOME",
            "USERPROFILE",
            "APPDATA",
            "LOCALAPPDATA",
            "TMP",
            "TEMP",
            "TMPDIR",
        ] {
            command.env(key, &temporary);
        }
        command
            .env(CHILD_MODE, mode)
            .env("MB_PROXY_TRANSACTION_PATH", &path)
            .env("MB_PROXY_TRANSACTION_PEER", address.to_string())
            .env("HOOKMAKER_MAX_TEST_WORKERS", "1")
            .args(["--exact", PROCESS_TEST, "--test-threads=1"]);
        let output = process::run_command(
            command,
            Duration::from_secs(10),
            16 * 1024,
            16 * 1024,
            &control,
            None,
        )
        .unwrap();
        assert!(
            output.status.success(),
            "proxy child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(
            stdout.contains("1 passed")
                && stdout.contains("0 failed")
                && stdout.contains("0 ignored")
        );
    };
    struct CancelOnDrop(Control);
    impl Drop for CancelOnDrop {
        fn drop(&mut self) {
            self.0.cancel();
        }
    }
    std::thread::scope(|scope| {
        let _cancel_on_failure = CancelOnDrop(control.clone());
        let first = scope.spawn(|| run_child("first"));
        let mut first_peer = accept(&listener);
        message(&mut first_peer, b'L');
        let second = scope.spawn(|| run_child("second"));
        let mut second_peer = accept(&listener);
        message(&mut second_peer, b'B');
        assert_eq!(fs::read(&path).unwrap(), before);
        first_peer.write_all(b"C").unwrap();
        message(&mut first_peer, b'D');
        first.join().unwrap();
        second_peer.write_all(b"R").unwrap();
        message(&mut second_peer, b'D');
        second.join().unwrap();
    });
    assert_eq!(
        store.list().unwrap(),
        [
            "http://seed.invalid:1",
            "http://p1.invalid:1",
            "http://p2.invalid:2"
        ]
    );
    assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 2);
}

#[test]
fn failed_proxy_transaction_replacement_preserves_the_pool_and_removes_only_its_stage() {
    let scratch = fixture();
    let path = scratch.path().join("private/proxies.json");
    let store = ProxyStore::new(path.clone());
    store
        .update(|urls| urls.push("http://old:1".into()))
        .unwrap();
    let before = fs::read(&path).unwrap();
    let mut attempted = false;
    let error = store
        .update_with_save(
            |urls| {
                urls.push("http://new:2".into());
                Ok(())
            },
            |locked, data| {
                let payload = serde_json::to_vec(&json!({"version":2,"data":data})).unwrap();
                locked.write_bytes_with_replace(&payload, |directory, stage, destination| {
                    attempted = true;
                    assert_eq!(destination, path.file_name().unwrap());
                    let mut staged = directory.open_private(stage, false).unwrap();
                    let mut bytes = Vec::new();
                    staged.read_to_end(&mut bytes).unwrap();
                    let actual: Value = serde_json::from_slice(&bytes).unwrap();
                    assert_eq!(
                        actual,
                        json!({"version":2,"data":{"urls":["http://old:1","http://new:2"]}})
                    );
                    assert_eq!(bytes, payload);
                    assert!(matches!(
                        Store::new(&path).with_timeout(Duration::ZERO).lock(),
                        Err(Error::Busy(_))
                    ));
                    Err(std::io::Error::other("controlled proxy replacement failure").into())
                })
            },
        )
        .unwrap_err();
    assert!(attempted);
    assert!(
        matches!(error, Error::Io(error) if error.to_string() == "controlled proxy replacement failure")
    );
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(store.list().unwrap(), ["http://old:1"]);
    assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 2);
    assert!(path.with_extension("json.lock").is_file());
    store
        .update(|urls| urls.push("http://new:2".into()))
        .unwrap();
    assert_eq!(store.list().unwrap(), ["http://old:1", "http://new:2"]);
}

#[test]
fn refused_proxy_mutation_after_locked_reload_never_reaches_commit() {
    let scratch = fixture();
    let path = scratch.path().join("private/proxies.json");
    let store = ProxyStore::new(path.clone());
    store
        .update(|urls| urls.push("http://old:1".into()))
        .unwrap();
    let before = fs::read(&path).unwrap();
    let control = crate::transfers::control::Control::new();
    let error = store
        .update_with_save(
            |urls| {
                assert_eq!(urls, &["http://old:1"]);
                assert!(matches!(
                    Store::new(&path).with_timeout(Duration::ZERO).lock(),
                    Err(Error::Busy(_))
                ));
                control.cancel();
                control.checkpoint()?;
                urls.push("http://new:2".into());
                Ok(())
            },
            |_, _| panic!("refused mutation reached the commit boundary"),
        )
        .unwrap_err();
    assert!(matches!(error, Error::Canceled));
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(store.list().unwrap(), ["http://old:1"]);
    assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 2);
}

#[test]
fn held_proxy_transaction_refuses_before_mutation_and_allows_retry_after_release() {
    let scratch = fixture();
    for existing in [false, true] {
        let path = scratch.path().join(if existing {
            "private/existing.json"
        } else {
            "private/absent.json"
        });
        let store = ProxyStore(Store::new(&path).with_timeout(Duration::ZERO));
        if existing {
            store
                .update(|urls| urls.push("http://old:1".into()))
                .unwrap();
        }
        let locked = Store::new(&path).lock().unwrap();
        let before = fs::read(&path).ok();
        assert!(matches!(
            store.update(|_| panic!("held proxy transaction reached its mutation callback")),
            Err(Error::Busy(_))
        ));
        assert_eq!(fs::read(&path).ok(), before);
        drop(locked);
        store
            .update(|urls| urls.push("http://new:2".into()))
            .unwrap();
        let expected = if existing {
            vec!["http://old:1", "http://new:2"]
        } else {
            vec!["http://new:2"]
        };
        assert_eq!(store.list().unwrap(), expected);
    }
}
