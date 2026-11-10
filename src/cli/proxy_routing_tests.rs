//! Shared API routing preserves explicit policy without opening any connection.
#![allow(clippy::unwrap_used)]

use std::{fs, path::Path, sync::Arc, time::Duration};

use super::context::Context;
use crate::{
    error::Error,
    storage::{
        files::Store,
        proxies::{Pool, ProxyStore, Routing},
    },
    transfers::download::DownloadOptions,
};

fn fixture() -> crate::test_support::TempDir {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/proxy-routing");
    fs::create_dir_all(&base).unwrap();
    crate::test_support::tempdir_in(base).unwrap()
}

#[test]
fn shared_api_skips_the_pool_when_disabled_or_explicit_and_preserves_corrupt_bytes() {
    let scratch = fixture();
    let mut context = Context::test_context(scratch.path());
    let path = context.paths.proxies();
    Store::new(&path)
        .lock()
        .unwrap()
        .write_bytes(b"{damaged proxy document")
        .unwrap();
    let before = fs::read(&path).unwrap();
    context.config.smart_proxy_url = Some("http://config-proxy:1234".into());
    let api = context.api(None).unwrap();
    assert!(api.transport.routing.pool.is_none());
    assert_eq!(api.transport.routing.select().unwrap(), (None, None));
    context.config.smart_proxy_enabled = true;
    let api = context.api(Some("http://manual:8080")).unwrap();
    assert!(api.transport.routing.pool.is_none());
    assert_eq!(
        api.transport.routing.select().unwrap(),
        (Some("http://manual:8080/".into()), None)
    );
    assert_eq!(fs::read(&path).unwrap(), before);
    assert!(matches!(context.api(None), Err(Error::Corrupt(_))));
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[test]
fn shared_api_merges_both_sources_and_deduplicates_without_probabilistic_sampling() {
    let scratch = fixture();
    let mut context = Context::test_context(scratch.path());
    context.config.smart_proxy_enabled = true;
    let configured = ["http://1.2.3.4:8080", "socks5://5.6.7.8:1080"];
    context.config.smart_proxy_url = Some(configured.join(", "));
    let stored = "http://disk-proxy:9999";
    ProxyStore::new(context.paths.proxies())
        .update(|urls| urls.push(stored.into()))
        .unwrap();
    let api = context.api(None).unwrap();
    let routing = &api.transport.routing;
    let mut picked = Vec::new();
    for _ in 0..3 {
        let (wire, selected) = routing.select().unwrap();
        let selected = selected.unwrap();
        assert!(wire.is_some());
        assert!(!picked.contains(&selected));
        for _ in 0..3 {
            routing.report(Some(&selected), false).unwrap();
        }
        picked.push(selected);
    }
    picked.sort();
    assert_eq!(picked, [configured[0], stored, configured[1]]);
    assert_eq!(routing.select().unwrap(), (None, None));

    let other = fixture();
    let mut context = Context::test_context(other.path());
    context.config.smart_proxy_enabled = true;
    context.config.smart_proxy_url = Some("http://duplicate:1111".into());
    ProxyStore::new(context.paths.proxies())
        .update(|urls| urls.push("http://duplicate:1111".into()))
        .unwrap();
    let api = context.api(None).unwrap();
    let (_, selected) = api.transport.routing.select().unwrap();
    assert_eq!(selected.as_deref(), Some("http://duplicate:1111"));
    for _ in 0..3 {
        api.transport
            .routing
            .report(selected.as_deref(), false)
            .unwrap();
    }
    assert_eq!(api.transport.routing.select().unwrap(), (None, None));
}

#[test]
fn configured_pool_handles_empty_input_and_all_source_separators_without_network() {
    for (configured, expected) in [
        (None, vec![]),
        (Some(""), vec![]),
        (Some(" , ;\n\t "), vec![]),
        (
            Some("http://1.2.3.4:8080, socks5://5.6.7.8:1080"),
            vec!["http://1.2.3.4:8080", "socks5://5.6.7.8:1080"],
        ),
        (Some("a, b;c\nd  e"), vec!["a", "b", "c", "d", "e"]),
    ] {
        let scratch = fixture();
        let mut context = Context::test_context(scratch.path());
        context.config.smart_proxy_enabled = true;
        context.config.smart_proxy_url = configured.map(str::to_owned);
        let api = context.api(None).unwrap();
        let mut selected = Vec::new();
        for _ in 0..expected.len() {
            let (wire, picked) = api.transport.routing.select().unwrap();
            let picked = picked.unwrap();
            assert!(wire.is_some() && !selected.contains(&picked));
            for _ in 0..3 {
                api.transport.routing.report(Some(&picked), false).unwrap();
            }
            selected.push(picked);
        }
        selected.sort();
        assert_eq!(selected, expected);
        assert_eq!(api.transport.routing.select().unwrap(), (None, None));
        context.config.force_smart_proxy = true;
        assert!(matches!(
            context.api(None).unwrap().transport.routing.select(),
            Err(Error::Protocol(message)) if message.contains("direct connection was refused")
        ));
        assert!(!context.paths.proxies().exists() && !context.paths.config().exists());
        assert!(!context.paths.logs.exists() && !context.paths.output.exists());
    }
}

#[test]
fn command_download_policy_and_worker_forks_preserve_every_native_option() {
    let scratch = fixture();
    let mut context = Context::test_context(scratch.path());
    context.config.max_workers = 3;
    context.config.verify_integrity = false;
    context.config.auto_resume = false;
    context.config.keep_state_files_on_error = false;
    context.config.quota_wait_seconds = 7;
    context.config.quota_max_wait_loops = 9;
    context.config.timeout_seconds = 42;
    context.config.user_agent = "MegaBasterd-CLI/custom-agent".into();
    context.config.smart_proxy_enabled = true;
    context.config.force_smart_proxy = true;
    let proxy = "http://policy-proxy.invalid:8080";
    ProxyStore::new(context.paths.proxies())
        .update(|urls| urls.push(proxy.into()))
        .unwrap();
    let saved = fs::read(context.paths.proxies()).unwrap();
    // Exhaustive patterns make a new policy field require an explicit forwarding review.
    let DownloadOptions {
        workers,
        verify,
        overwrite,
        resume,
        keep_state,
        quota_wait,
        quota_attempts,
    } = DownloadOptions::from_config(&context.config, None, false, false).unwrap();
    assert_eq!((workers, quota_wait, quota_attempts), (3, 7, 9));
    assert!(!verify && !overwrite && !resume && !keep_state);
    context.config.verify_integrity = true;
    let overrides = DownloadOptions::from_config(&context.config, Some(5), true, true).unwrap();
    assert_eq!(overrides.workers, 5);
    assert!(!overrides.verify && overrides.overwrite);
    assert!(!overrides.resume && !overrides.keep_state);
    assert_eq!((overrides.quota_wait, overrides.quota_attempts), (7, 9));
    assert!(
        DownloadOptions::from_config(&context.config, None, false, false)
            .unwrap()
            .verify
    );

    let parent = context.api(None).unwrap();
    let mut first = parent.fork().unwrap();
    let second = parent.fork().unwrap();
    for worker in [&first, &second] {
        assert_eq!(worker.transport.timeout, Duration::from_secs(42));
        assert_eq!(worker.transport.user_agent, "MegaBasterd-CLI/custom-agent");
        let Routing {
            explicit,
            pool,
            force,
        } = &worker.transport.routing;
        assert!(explicit.is_none() && *force);
        assert!(Arc::ptr_eq(
            pool.as_ref().unwrap(),
            parent.transport.routing.pool.as_ref().unwrap(),
        ));
        assert_eq!(
            worker.transport.routing.select().unwrap().1.as_deref(),
            Some(proxy)
        );
    }
    first.transport.timeout = Duration::from_secs(13);
    first.transport.user_agent = "worker-only".into();
    first.transport.routing.explicit = Some("http://manual.invalid:3128".into());
    first.transport.routing.force = false;
    for unchanged in [&parent, &second] {
        assert_eq!(unchanged.transport.timeout, Duration::from_secs(42));
        assert_eq!(
            unchanged.transport.user_agent,
            "MegaBasterd-CLI/custom-agent"
        );
        assert!(unchanged.transport.routing.explicit.is_none());
        assert!(unchanged.transport.routing.force);
    }
    assert_eq!(
        first.transport.routing.select().unwrap(),
        (Some("http://manual.invalid:3128/".into()), None),
    );
    let explicit = context.api(Some("http://explicit.invalid:8080")).unwrap();
    let explicit_worker = explicit.fork().unwrap();
    assert_eq!(
        explicit_worker.transport.routing.select().unwrap(),
        (Some("http://explicit.invalid:8080/".into()), None),
    );
    assert_eq!(explicit_worker.transport.timeout, Duration::from_secs(42));
    assert_eq!(
        explicit_worker.transport.user_agent,
        "MegaBasterd-CLI/custom-agent"
    );
    for _ in 0..3 {
        parent.transport.routing.report(Some(proxy), false).unwrap();
    }
    assert!(matches!(
        second.transport.routing.select(),
        Err(Error::Protocol(_))
    ));
    assert_eq!(fs::read(context.paths.proxies()).unwrap(), saved);
    assert!(!context.paths.logs.exists() && !context.paths.output.exists());
}

#[test]
fn force_policy_refuses_absent_empty_or_cooled_pools_but_accepts_an_explicit_proxy() {
    for pooled in [false, true] {
        let routing = Routing {
            explicit: None,
            pool: pooled.then(|| Pool::new(vec![], vec![], None).unwrap()),
            force: true,
        };
        assert!(
            matches!(routing.select(), Err(Error::Protocol(message)) if message.contains("direct connection was refused"))
        );
    }
    let routing = Routing {
        explicit: Some("http://manual:8080".into()),
        pool: None,
        force: true,
    };
    assert_eq!(
        routing.select().unwrap(),
        (Some("http://manual:8080/".into()), None)
    );
    let pool = Pool::new(vec!["http://pool-proxy:3128".into()], vec![], None).unwrap();
    for _ in 0..3 {
        pool.report("http://pool-proxy:3128", false).unwrap();
    }
    let routing = Routing {
        explicit: None,
        pool: Some(pool),
        force: true,
    };
    assert!(matches!(routing.select(), Err(Error::Protocol(_))));
    let scratch = fixture();
    let mut context = Context::test_context(scratch.path());
    context.config.smart_proxy_enabled = true;
    context.config.force_smart_proxy = true;
    assert!(matches!(
        context.api(None).unwrap().transport.routing.select(),
        Err(Error::Protocol(_))
    ));
}
