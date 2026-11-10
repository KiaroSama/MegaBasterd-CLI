#![allow(clippy::unwrap_used)]

use megabasterd_cli::storage::proxies::{ProxyStore, canonical_proxy, validate_proxy};

#[test]
fn source_schemeless_proxies_are_normalized_only_at_the_transport_boundary() {
    assert_eq!(
        canonical_proxy("proxy.example:8080").unwrap(),
        "http://proxy.example:8080/"
    );
    assert_eq!(
        canonical_proxy("user:fixture@proxy.example:8080").unwrap(),
        "http://user:fixture@proxy.example:8080/"
    );
    for proxy in [
        "http://proxy.example:8080/path",
        "http://proxy.example:8080?token=fixture",
        "http://proxy.example:0",
        "http://proxy.example:8080#fragment",
        "http://user:fixture@",
    ] {
        assert!(validate_proxy(proxy).is_err(), "accepted invalid proxy");
    }
}

#[test]
fn default_proxy_ports_survive_canonicalization_and_revalidation() {
    for (value, port) in [
        ("http://proxy.example:80", 80),
        ("proxy.example", 80),
        ("https://proxy.example:443", 443),
        ("proxy.example:80", 80),
        ("http://[::1]:80", 80),
    ] {
        assert_eq!(
            validate_proxy(value).unwrap().port_or_known_default(),
            Some(port)
        );
        let canonical = canonical_proxy(value).unwrap();
        assert_eq!(
            validate_proxy(&canonical).unwrap().port_or_known_default(),
            Some(port)
        );
    }
    for value in [
        "socks5://proxy.example",
        "socks5h://proxy.example",
        "socks4://proxy.example",
    ] {
        assert!(validate_proxy(value).is_err());
    }
}

#[test]
fn persisted_reload_keeps_config_proxies_and_deduplicates_the_union() {
    use megabasterd_cli::storage::proxies::Pool;
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/proxy-tests");
    std::fs::create_dir_all(&base).unwrap();
    let scratch = private_tempfile::tempdir_in(base).unwrap();
    let path = scratch.path().join("private/proxies.json");
    let store = ProxyStore::new(path.clone());
    let configured = "http://configured.example:8080".to_owned();
    let obsolete = "http://obsolete.example:8080".to_owned();
    let replacement = "http://replacement.example:8080".to_owned();
    store.update(|urls| urls.push(obsolete.clone())).unwrap();
    let pool = Pool::new(store.list().unwrap(), vec![configured.clone()], Some(path)).unwrap();
    store
        .update(|urls| *urls = vec![replacement.clone(), configured.clone()])
        .unwrap();
    pool.reload().unwrap();
    for _ in 0..3 {
        pool.report(&replacement, false).unwrap();
    }
    assert_eq!(pool.pick().unwrap().as_deref(), Some(configured.as_str()));
    // A duplicate configured entry would remain available after this cooldown.
    for _ in 0..3 {
        pool.report(&configured, false).unwrap();
    }
    assert!(pool.pick().unwrap().is_none());
    store.update(|urls| urls.clear()).unwrap();
    pool.reload().unwrap();
    assert!(
        pool.pick().unwrap().is_none(),
        "empty reload reset cooldowns or revived a removed proxy"
    );
}

#[test]
fn invalid_saved_proxy_data_is_preserved_before_mutation() {
    use megabasterd_cli::{error::Error, storage::files::Store};
    use serde_json::json;

    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/proxy-tests");
    std::fs::create_dir_all(&base).unwrap();
    let scratch = private_tempfile::tempdir_in(base).unwrap();
    let path = scratch.path().join("private/proxies.json");
    let store = ProxyStore::new(path.clone());
    let mut cases = vec![
        br#"["http://a:1"]"#.to_vec(),
        br#""proxies""#.to_vec(),
        b"123".to_vec(),
        b"null".to_vec(),
        b"{oops".to_vec(),
        b"\xff\xfe".to_vec(),
    ];
    for data in [
        json!({"urls":"http://a:1"}),
        json!({"urls":[1,2]}),
        json!({"urls":["http://proxy.example:0"]}),
        json!([["http://a:1"]]),
        json!({"urls":[],"unknown":"must not be lost"}),
        json!({}),
    ] {
        cases.push(serde_json::to_vec(&json!({"version":2,"data":data})).unwrap());
    }
    cases.push(serde_json::to_vec(&json!({"version":99,"data":{"urls":[]}})).unwrap());
    for (index, bytes) in cases.into_iter().enumerate() {
        Store::new(&path)
            .lock()
            .unwrap()
            .write_bytes(&bytes)
            .unwrap();
        for _ in 0..2 {
            let error = store.list().unwrap_err();
            assert!(
                matches!(&error, Error::Corrupt(message) if message.contains("recovery copy was preserved"))
            );
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
        }
        assert!(matches!(
            store.update(|_| panic!("corrupt data reached the mutation callback")),
            Err(Error::Corrupt(_))
        ));
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        let name = Store::new(&path).lock().unwrap().preserve().unwrap();
        assert_eq!(
            std::fs::read(path.parent().unwrap().join(name)).unwrap(),
            bytes
        );
        assert_eq!(
            std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
            index + 3
        );
    }
    assert!(
        !std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .any(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp")
            })
    );
}

#[test]
fn valid_proxy_transactions_reload_and_roundtrip_without_losing_other_updates() {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/proxy-tests");
    std::fs::create_dir_all(&base).unwrap();
    let scratch = private_tempfile::tempdir_in(base).unwrap();
    let path = scratch.path().join("private/proxies.json");
    let first = ProxyStore::new(path.clone());
    let second = ProxyStore::new(path.clone());
    first.update(|urls| urls.push("http://a:1".into())).unwrap();
    second
        .update(|urls| urls.push("socks5://b:2".into()))
        .unwrap();
    assert_eq!(first.list().unwrap(), ["http://a:1", "socks5://b:2"]);
    assert_eq!(
        ProxyStore::new(path).list().unwrap(),
        ["http://a:1", "socks5://b:2"]
    );
}

#[path = "common/private_tempfile.rs"]
mod private_tempfile;
