//! Structural safety contracts complement, not replace, native TLS and redirect peer tests.
#![allow(clippy::unwrap_used)]

fn executable_lines(source: &str) -> String {
    assert!(
        !source.contains("/*") && !source.contains("*/"),
        "Block comments require a reviewed structural-contract update"
    );
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn section<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    assert_eq!(source.matches(start).count(), 1, "ambiguous start: {start}");
    source
        .split_once(start)
        .unwrap()
        .1
        .split_once(end)
        .unwrap()
        .0
}

#[test]
fn online_link_operations_require_the_same_explicit_transport_without_a_default_resolver() {
    let source = include_str!("../src/protocol/link_services.rs");
    let fields = section(source, "pub struct Resolver<'a> {", "\n}");
    assert!(fields.contains("pub transport: &'a Transport,"));
    let implementation = executable_lines(source);
    assert!(implementation.contains("impl Resolver<'_> {"));
    for method in [
        "pub fn elc(&self,",
        "pub fn dlc(&self,",
        "pub fn megacrypter_info(&self,",
        "pub fn megacrypter_download(\n        &self,",
        "pub fn megacrypter_resolve(&self,",
    ] {
        assert!(
            implementation.contains(method),
            "missing explicit receiver: {method}"
        );
    }
    assert!(!implementation.contains("Default for Resolver"));
    assert!(!fields.contains("Option<&'a Transport>"));

    let positive = source
        .split_once("/// ```\n")
        .unwrap()
        .1
        .split_once("/// ```")
        .unwrap()
        .0;
    let negative = section(source, "/// ```compile_fail\n", "/// ```");
    assert_eq!(positive.matches("///         transport,\n").count(), 1);
    assert_eq!(
        positive.replacen("///         transport,\n", "", 1),
        negative,
        "the compile-fail example may differ only by its missing transport"
    );
}

#[test]
fn download_and_streaming_use_the_same_range_validator_before_consuming_content() {
    let download = executable_lines(include_str!("../src/transfers/download.rs"));
    let streaming = include_str!("../src/services/streaming.rs");
    let open = executable_lines(section(streaming, "fn open_with(", "fn pump("));
    let ranges = executable_lines(include_str!("../src/protocol/ranges.rs"));
    let imports = section(&download, "use crate::protocol::{", "use crate::storage::{");
    assert!(imports.contains("ranges::{ByteRange, validate_response}"));
    assert_eq!(ranges.matches("pub fn validate_response(").count(), 1);
    for source in [download.as_str(), streaming] {
        assert!(!source.contains("fn validate_response("));
    }
    let fetch = download.split_once("fn fetch_chunk_with_send(").unwrap().1;
    let validation = fetch
        .find("validate_response(status, reply.response.headers(), range, size)?;")
        .unwrap();
    assert!(
        validation
            < fetch
                .find("let ciphertext = reply.bytes(chunk.size)?;")
                .unwrap()
    );
    let validation = open
        .find("ranges::validate_response(status, reply.response.headers(), range, size)?;")
        .unwrap();
    assert!(validation < open.find("return Ok(reply);").unwrap());
}

#[test]
fn dlc_uses_the_shared_explicit_hop_loop_without_disabling_tls_verification() {
    let services = executable_lines(include_str!("../src/protocol/link_services.rs"));
    let transport = executable_lines(include_str!("../src/protocol/transport.rs"));
    let proxy = executable_lines(include_str!("../src/protocol/proxy_transport.rs"));
    let dlc = section(&services, "pub fn dlc(&self,", "fn dlc_with(");
    assert!(dlc.contains("self.dlc_with(input, None,"));
    assert!(dlc.contains("self.transport.post_link_service(url, headers, body, true)"));
    let service_post = section(
        &transport,
        "pub fn post_link_service(",
        "pub(crate) fn send_api(",
    );
    assert!(service_post.contains("self.send_inner("));
    assert!(service_post.contains("Redirects::Service { same_origin }"));
    let send = section(&transport, "fn send_inner(", "struct BodyReadFailure");
    assert!(send.contains("self.send_hops(method, url, policy,"));
    assert!(send.contains("proxy_transport::send("));
    assert!(send.contains("self.send_direct(method, url, &headers, body.as_deref(), proxy)"));

    let client = section(&transport, "fn client(&self,", "fn send_direct(");
    let production = client.split_once("let trusted_proxy_host").unwrap().1;
    assert!(production.contains(".redirect(Policy::none())"));
    assert!(production.contains(".dns_resolver(Arc::new(SafeResolver::new("));
    for method in [
        ".danger_accept_invalid_certs(",
        ".tls_danger_accept_invalid_certs(",
        ".danger_accept_invalid_hostnames(",
        ".tls_danger_accept_invalid_hostnames(",
        ".use_preconfigured_tls(",
    ] {
        assert!(
            !client.contains(method),
            "unreviewed TLS override: {method}"
        );
    }
    let pinned = section(
        &proxy,
        "let roots = RootCerts::PlatformVerifier;",
        "let resolver = FixedResolver",
    );
    assert!(pinned.contains(".max_redirects(0)"));
    assert!(pinned.contains("TlsConfig::builder()"));
    assert!(pinned.contains(".root_certs(roots)"));
    assert!(!proxy.contains(".disable_verification("));
}

#[test]
fn elc_and_megacrypter_delegate_to_the_same_manual_redirect_transport() {
    let services = executable_lines(include_str!("../src/protocol/link_services.rs"));
    let transport = executable_lines(include_str!("../src/protocol/transport.rs"));
    let elc = section(&services, "pub fn elc(&self,", "fn elc_with(");
    assert!(elc.contains("self.elc_with(link,"));
    assert!(elc.contains("response_json(self.transport, url, body, content_type)"));
    let mc = section(
        &services,
        "fn megacrypter_response(",
        "pub fn megacrypter_resolve(",
    );
    assert!(mc.contains("response_json("));
    assert!(mc.contains("self.transport,"));
    let json_exchange = section(&services, "fn response_json(", "impl Resolver<'_>");
    assert!(json_exchange.contains("transport.post_link_service(url, headers, body, false)?"));
    let service_post = section(
        &transport,
        "pub fn post_link_service(",
        "pub(crate) fn send_api(",
    );
    assert!(service_post.contains("self.send_inner("));
    assert!(service_post.contains("Redirects::Service { same_origin }"));
    let send = section(&transport, "fn send_inner(", "struct BodyReadFailure");
    assert!(send.contains("self.send_hops(method, url, policy,"));
    let client = section(&transport, "fn client(&self,", "fn send_direct(");
    let production = client.split_once("let trusted_proxy_host").unwrap().1;
    assert!(production.contains(".redirect(Policy::none())"));
    let proxy = executable_lines(include_str!("../src/protocol/proxy_transport.rs"));
    let pinned = section(
        &proxy,
        "let roots = RootCerts::PlatformVerifier;",
        "let resolver = FixedResolver",
    );
    assert!(pinned.contains(".max_redirects(0)"));
}
