#![allow(clippy::unwrap_used)]

use megabasterd_cli::services::{
    connect::{destination, dial},
    http::Request,
};

#[test]
fn local_proxy_accepts_only_exact_mega_domains_and_permitted_ports() {
    for target in ["mega.nz:443", "g.api.mega.co.nz:443", "cdn.mega.nz:443"] {
        let request =
            Request::parse(format!("CONNECT {target} HTTP/1.1\r\n\r\n").as_bytes()).unwrap();
        assert!(destination(&request, false).is_ok());
    }
    for target in [
        "mega.nz.attacker.invalid:443",
        "evilmega.nz:443",
        "127.0.0.1:443",
        "mega.nz:22",
        "mega.nz:0",
        "mega.nz:65536",
        "user@mega.nz:443",
    ] {
        let request =
            Request::parse(format!("CONNECT {target} HTTP/1.1\r\n\r\n").as_bytes()).unwrap();
        assert!(destination(&request, false).is_err());
    }
    let request =
        Request::parse(b"POST http://cdn.mega.nz/file HTTP/1.1\r\nContent-Length: 8\r\n\r\n")
            .unwrap();
    let target = destination(&request, false).unwrap();
    assert_eq!(target.host, "cdn.mega.nz");
    assert_eq!(target.port, 80);
    assert_eq!(target.path.as_deref(), Some("/file"));
    let request = Request::parse(b"CONNECT mega.nz:22 HTTP/1.1\r\n\r\n").unwrap();
    assert!(destination(&request, true).is_ok());
}

#[test]
fn literal_source_host_and_port_matrix_preserves_destination_values_and_refusal_precedence() {
    use megabasterd_cli::error::Error;
    let host_refusal = "Proxy destination is outside approved MEGA domains";
    let port_refusal = "Proxy destination port is forbidden";
    for (host, allowed) in [
        ("mega.nz", true),
        ("g.api.mega.nz", true),
        ("eu.static.mega.nz", true),
        ("mega.co.nz", true),
        ("cdn.mega.co.nz", true),
        ("evil.com", false),
        ("notmega.nz", false),
        ("mega.nz.evil.com", false),
        ("evilmega.nz", false),
    ] {
        let request =
            Request::parse(format!("CONNECT {host}:443 HTTP/1.1\r\n\r\n").as_bytes()).unwrap();
        match destination(&request, false) {
            Ok(target) => {
                assert!(allowed, "forbidden source host {host} was accepted");
                assert_eq!(target.host, host);
                assert_eq!(target.port, 443);
                assert!(target.path.is_none());
            }
            Err(error) => assert!(
                !allowed && matches!(error, Error::Invalid(message) if message == host_refusal),
                "source host {host} did not receive its host-policy verdict"
            ),
        }
    }
    for (method, host, port, any_port, refusal) in [
        ("CONNECT", "mega.nz", 443, false, None),
        ("CONNECT", "mega.nz", 8080, false, Some(port_refusal)),
        ("CONNECT", "mega.nz", 80, false, Some(port_refusal)),
        ("GET", "mega.nz", 80, false, None),
        ("GET", "mega.nz", 443, false, None),
        ("GET", "mega.nz", 8080, false, Some(port_refusal)),
        ("GET", "mega.nz", 1234, false, Some(port_refusal)),
        ("CONNECT", "evil.com", 443, false, Some(host_refusal)),
        ("CONNECT", "evil.com", 443, true, Some(host_refusal)),
        ("CONNECT", "evil.com", 8080, false, Some(host_refusal)),
        ("CONNECT", "evil.com", 8080, true, Some(host_refusal)),
        ("GET", "evil.com", 8080, false, Some(host_refusal)),
        ("GET", "evil.com", 8080, true, Some(host_refusal)),
        ("CONNECT", "mega.nz", 8080, true, None),
        ("GET", "mega.nz", 8080, true, None),
    ] {
        let target = if method == "CONNECT" {
            format!("{host}:{port}")
        } else {
            format!("http://{host}:{port}/file?part=1")
        };
        let request =
            Request::parse(format!("{method} {target} HTTP/1.1\r\n\r\n").as_bytes()).unwrap();
        let result = destination(&request, any_port);
        if let Some(expected) = refusal {
            assert!(
                matches!(result, Err(Error::Invalid(message)) if message == expected),
                "wrong policy verdict for {method} {target}, any_port={any_port}"
            );
        } else {
            let resolved = result.unwrap();
            assert_eq!(resolved.host, host);
            assert_eq!(resolved.port, port);
            assert_eq!(
                resolved.path.as_deref(),
                if method == "CONNECT" {
                    None
                } else {
                    Some("/file?part=1")
                }
            );
        }
    }
}

#[test]
fn configured_proxy_probe_can_reach_loopback_without_relaxing_destination_policy() {
    use megabasterd_cli::{services::connect::probe_proxy, transfers::control::Control};
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let proxy = format!("http://127.0.0.1:{port}");
    let socket = probe_proxy(&proxy, std::time::Duration::from_secs(1), &Control::new()).unwrap();
    assert_eq!(socket.peer_addr().unwrap(), listener.local_addr().unwrap());
    drop(socket);
    let error = dial(
        "127.0.0.1",
        port,
        std::time::Duration::from_secs(1),
        &Control::new(),
    )
    .unwrap_err();
    assert!(matches!(error, megabasterd_cli::error::Error::Invalid(_)));
    let control = Control::new();
    control.cancel();
    assert!(matches!(
        probe_proxy(&proxy, std::time::Duration::from_secs(1), &control),
        Err(megabasterd_cli::error::Error::Canceled)
    ));
}

#[test]
fn unsafe_literal_destination_is_refused_before_a_connection() {
    use megabasterd_cli::transfers::control::Control;
    let error = dial(
        "127.0.0.1",
        443,
        std::time::Duration::from_millis(100),
        &Control::new(),
    )
    .unwrap_err();
    assert!(matches!(error, megabasterd_cli::error::Error::Invalid(_)));
}
