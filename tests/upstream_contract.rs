#![allow(clippy::unwrap_used)]
use base64::{Engine, engine::general_purpose::STANDARD};
use megabasterd_cli::storage::proxies::{import_proxy, validate_proxy};

#[test]
fn upstream_proxy_base64_slashes_survive_import_and_numeric_url_passwords_are_unambiguous() {
    let url = import_proxy("http://1.2.3.4:8080/@VGhpcw==:Pz8/").unwrap();
    let parsed = validate_proxy(&url).unwrap();
    assert_eq!(parsed.host_str(), Some("1.2.3.4"));
    assert_eq!(parsed.username(), "This");
    assert_eq!(parsed.password(), Some("%3F%3F%3F"));
    let url = import_proxy("http://user:1234@1.2.3.4:8080").unwrap();
    assert_eq!(validate_proxy(&url).unwrap().host_str(), Some("1.2.3.4"));
}

#[test]
fn upstream_proxy_import_rejects_malformed_auth_ports_and_controls_without_echoing_secrets() {
    for entry in [
        "1.2.3.4:0",
        "1.2.3.4:99999",
        "1.2.3.4:8080@bad:***",
        "ftp://1.2.3.4:80",
        "1.2.3.4:8080\r",
    ] {
        assert!(import_proxy(entry).is_err(), "accepted {entry:?}");
    }
    let value = format!(
        "1.2.3.4:8080@{}:{}",
        STANDARD.encode("user\r\n"),
        STANDARD.encode("password")
    );
    let error = import_proxy(&value).unwrap_err().to_string();
    assert!(!error.contains("password") && !error.contains("user\r\n"));
}
