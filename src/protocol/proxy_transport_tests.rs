#![allow(clippy::unwrap_used)]

use super::*;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;
use ureq::tls::Certificate;

const ROOT: &[u8] = include_bytes!("../../tests/fixtures/proxy_tls/root.der");
const CERT: &[u8] = include_bytes!("../../tests/fixtures/proxy_tls/server.der");
const INTERMEDIATE: &[u8] = include_bytes!("../../tests/fixtures/proxy_tls/intermediate.der");
const PUBLIC_TEST_KEY: &[u8] = include_bytes!("../../tests/fixtures/proxy_tls/public-test-key.txt");

fn server_config() -> Arc<rustls::ServerConfig> {
    let key = ureq::tls::PrivateKey::from_pem(PUBLIC_TEST_KEY).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::try_from(key.der().to_vec()).unwrap();
    Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CERT.to_vec().into(), INTERMEDIATE.to_vec().into()],
            key,
        )
        .unwrap(),
    )
}

fn tls<S: Read + Write>(
    stream: S,
    config: &Arc<rustls::ServerConfig>,
) -> rustls::StreamOwned<rustls::ServerConnection, S> {
    rustls::StreamOwned::new(
        rustls::ServerConnection::new(config.clone()).unwrap(),
        stream,
    )
}

fn head(stream: &mut (impl Read + Write)) -> String {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        assert!(bytes.len() < 8192);
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        bytes.push(byte[0]);
    }
    String::from_utf8(bytes).unwrap()
}

struct TestClient {
    agent: ureq::Agent,
    sent: Arc<AtomicBool>,
    control: Control,
    uri: Uri,
}

fn client(
    proxy: Url,
    address: SocketAddr,
    hostname: &str,
    trust: bool,
    timeout: Duration,
) -> TestClient {
    let uri: Uri = format!("https://{hostname}/api").parse().unwrap();
    let deadline = Instant::now() + timeout;
    let control = Control::new();
    let sent = Arc::new(AtomicBool::new(false));
    let connector = ProxyConnector {
        proxy_uri: proxy_uri(&proxy).unwrap(),
        proxy,
        proxy_addresses: vec![address],
        target_uri: uri.clone(),
        deadline,
        connect_deadline: deadline,
        control: control.clone(),
        connected: Arc::new(AtomicBool::new(false)),
        sent: sent.clone(),
    };
    // Only the test resolver is replaced: the real connector must still send a public numeric IP.
    let resolver = FixedResolver {
        uri: uri.clone(),
        addresses: vec!["1.1.1.1:443".parse().unwrap()],
    };
    let certificates = if trust {
        vec![Certificate::from_der(ROOT)]
    } else {
        Vec::new()
    };
    let roots = RootCerts::new_with_certs(&certificates);
    let config = Config::builder()
        .proxy(None)
        .https_only(true)
        .http_status_as_error(false)
        .max_redirects(0)
        .max_idle_connections(0)
        .max_idle_connections_per_host(0)
        .timeout_global(Some(timeout))
        .timeout_connect(Some(timeout))
        .tls_config(
            TlsConfig::builder()
                .root_certs(roots)
                .unversioned_rustls_crypto_provider(Arc::new(
                    rustls::crypto::aws_lc_rs::default_provider(),
                ))
                .build(),
        )
        .build();
    TestClient {
        agent: ureq::Agent::with_parts(config, connector, resolver),
        sent,
        control,
        uri,
    }
}

fn listener() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    (listener, address)
}

fn accept(listener: &TcpListener) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                return stream;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "client never connected");
                thread::park_timeout(Duration::from_millis(5));
            }
            Err(error) => panic!("bounded accept failed: {error}"),
        }
    }
}

fn serve_target(
    mut stream: impl Read + Write,
    config: &Arc<rustls::ServerConfig>,
    response: &[u8],
) {
    let mut target = tls(&mut stream, config);
    let request = head(&mut target);
    assert_eq!(target.conn.server_name(), Some("testserver.com"));
    assert!(request.starts_with("POST /api HTTP/1.1\r\n"));
    assert!(
        request
            .to_ascii_lowercase()
            .contains("host: testserver.com\r\n")
    );
    assert!(!request.to_ascii_lowercase().contains("proxy-authorization"));
    let mut body = [0; 7];
    target.read_exact(&mut body).unwrap();
    assert_eq!(&body, b"payload");
    target.write_all(response).unwrap();
    target.flush().unwrap();
}

#[test]
fn connect_and_https_connect_pin_numeric_address_but_verify_original_sni() {
    let config = server_config();
    for secure_proxy in [false, true] {
        let (listener, address) = listener();
        let scheme = if secure_proxy { "https" } else { "http" };
        let proxy = Url::parse(&format!(
            "{scheme}://u%73er:syn%74hetic@localhost:{}",
            address.port()
        ))
        .unwrap();
        let client = client(
            proxy,
            address,
            "testserver.com",
            true,
            Duration::from_secs(5),
        );
        let config = config.clone();
        thread::scope(|scope| {
            let server = scope.spawn(move || {
                let socket = accept(&listener);
                let mut stream: Box<dyn ReadWrite> = if secure_proxy { Box::new(tls(socket, &config)) } else { Box::new(socket) };
                let connect = head(&mut stream);
                assert_eq!(connect, "CONNECT 1.1.1.1:443 HTTP/1.1\r\nHost: 1.1.1.1:443\r\nProxy-Authorization: Basic dXNlcjpzeW50aGV0aWM=\r\n\r\n");
                stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").unwrap();
                stream.flush().unwrap();
                serve_target(stream, &config, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK");
            });
            let mut response = request(
                &client.agent,
                &Method::POST,
                client.uri.clone(),
                &HeaderMap::new(),
                Some(b"payload"),
            )
            .unwrap();
            let mut body = String::new();
            response.read_to_string(&mut body).unwrap();
            assert_eq!(body, "OK");
            assert_eq!(response.status(), reqwest::StatusCode::OK);
            assert!(client.sent.load(Ordering::Acquire));
            server.join().unwrap();
        });
    }
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

#[test]
fn socks5h_authenticates_exactly_and_pins_numeric_target_before_tls() {
    let config = server_config();
    let (listener, address) = listener();
    let proxy = Url::parse(&format!(
        "socks5h://user:synthetic@localhost:{}",
        address.port()
    ))
    .unwrap();
    let client = client(
        proxy,
        address,
        "testserver.com",
        true,
        Duration::from_secs(5),
    );
    thread::scope(|scope| {
        let server = scope.spawn(move || {
            let mut socket = accept(&listener);
            let mut greeting = [0; 3];
            socket.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting, [5, 1, 2]);
            socket.write_all(&[5, 2]).unwrap();
            let mut auth = [0; 16];
            socket.read_exact(&mut auth).unwrap();
            assert_eq!(&auth, b"\x01\x04user\x09synthetic");
            socket.write_all(&[1, 0]).unwrap();
            let mut target = [0; 10];
            socket.read_exact(&mut target).unwrap();
            assert_eq!(target, [5, 1, 0, 1, 1, 1, 1, 1, 1, 187]);
            socket.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
            serve_target(
                socket,
                &config,
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
            );
        });
        let mut response = request(
            &client.agent,
            &Method::POST,
            client.uri.clone(),
            &HeaderMap::new(),
            Some(b"payload"),
        )
        .unwrap();
        let mut body = String::new();
        response.read_to_string(&mut body).unwrap();
        assert_eq!(body, "OK");
        assert!(client.sent.load(Ordering::Acquire));
        server.join().unwrap();
    });
}

#[test]
fn wrong_name_or_untrusted_ca_stops_before_target_http_bytes() {
    let config = server_config();
    for (hostname, trusted) in [("wrong.example", true), ("testserver.com", false)] {
        let (listener, address) = listener();
        let proxy = Url::parse(&format!("http://localhost:{}", address.port())).unwrap();
        let client = client(proxy, address, hostname, trusted, Duration::from_secs(5));
        let config = config.clone();
        thread::scope(|scope| {
            let server = scope.spawn(move || {
                let mut socket = accept(&listener);
                assert!(head(&mut socket).starts_with("CONNECT 1.1.1.1:443 "));
                socket.write_all(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();
                let mut target = tls(socket, &config);
                let mut byte = [0];
                assert!(target.read(&mut byte).is_err());
            });
            assert!(
                request(
                    &client.agent,
                    &Method::POST,
                    client.uri.clone(),
                    &HeaderMap::new(),
                    Some(b"payload")
                )
                .is_err()
            );
            assert!(!client.sent.load(Ordering::Acquire));
            server.join().unwrap();
        });
    }
}

#[test]
fn short_body_is_an_error_after_send_and_never_replays_the_post() {
    let config = server_config();
    let (listener, address) = listener();
    let proxy = Url::parse(&format!("http://localhost:{}", address.port())).unwrap();
    let client = client(
        proxy,
        address,
        "testserver.com",
        true,
        Duration::from_secs(5),
    );
    thread::scope(|scope| {
        let server = scope.spawn(move || {
            let mut socket = accept(&listener);
            head(&mut socket);
            socket.write_all(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();
            serve_target(
                socket,
                &config,
                b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nx",
            );
            assert!(
                matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
            );
        });
        let mut response = request(
            &client.agent,
            &Method::POST,
            client.uri.clone(),
            &HeaderMap::new(),
            Some(b"payload"),
        )
        .unwrap();
        assert!(response.read_to_end(&mut Vec::new()).is_err());
        assert!(client.sent.load(Ordering::Acquire));
        server.join().unwrap();
    });
}

#[test]
fn cancellation_interrupts_proxy_handshake_without_read_exact_retry_loop() {
    let (listener, address) = listener();
    let proxy = Url::parse(&format!("http://localhost:{}", address.port())).unwrap();
    let client = client(
        proxy,
        address,
        "testserver.com",
        true,
        Duration::from_secs(5),
    );
    let control = client.control.clone();
    let (ready, arrived) = mpsc::sync_channel(1);
    thread::scope(|scope| {
        let server = scope.spawn(move || {
            let mut socket = accept(&listener);
            head(&mut socket);
            ready.send(()).unwrap();
            let mut byte = [0];
            assert_eq!(socket.read(&mut byte).unwrap(), 0);
        });
        let cancel = scope.spawn(move || {
            arrived.recv_timeout(Duration::from_secs(3)).unwrap();
            control.cancel();
        });
        assert!(
            request(
                &client.agent,
                &Method::POST,
                client.uri.clone(),
                &HeaderMap::new(),
                Some(b"payload")
            )
            .is_err()
        );
        assert!(!client.sent.load(Ordering::Acquire));
        cancel.join().unwrap();
        server.join().unwrap();
    });
}

#[test]
fn expired_deadlines_stop_before_proxy_io_and_unsafe_dns_sets_never_contact_proxy() {
    let (listener, address) = listener();
    let proxy = Url::parse(&format!("http://localhost:{}", address.port())).unwrap();
    let mut client = client(
        proxy.clone(),
        address,
        "testserver.com",
        true,
        Duration::from_secs(5),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let resolver = FixedResolver {
        uri: client.uri.clone(),
        addresses: vec![
            "1.1.1.1:443".parse().unwrap(),
            "127.0.0.1:443".parse().unwrap(),
        ],
    };
    let connector = ProxyConnector {
        proxy_uri: proxy_uri(&proxy).unwrap(),
        proxy,
        proxy_addresses: vec![address],
        target_uri: client.uri.clone(),
        deadline,
        connect_deadline: deadline,
        control: client.control.clone(),
        connected: Arc::new(AtomicBool::new(false)),
        sent: client.sent.clone(),
    };
    client.agent = ureq::Agent::with_parts(client.agent.config().clone(), connector, resolver);
    assert!(
        request(
            &client.agent,
            &Method::POST,
            client.uri,
            &HeaderMap::new(),
            Some(b"payload")
        )
        .is_err()
    );
    assert!(!client.sent.load(Ordering::Acquire));
    assert!(matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    assert!(matches!(
        runtime.block_on(interruptible(
            std::future::pending::<Result<()>>(),
            Instant::now(),
            &Control::new()
        )),
        Err(Error::Timeout)
    ));
}

#[test]
fn numeric_target_and_proxy_address_failover_preserves_original_tls_authority() {
    let (listener, address) = listener();
    let closed = TcpListener::bind("127.0.0.1:0").unwrap();
    let unavailable = closed.local_addr().unwrap();
    drop(closed);
    let proxy = Url::parse(&format!("http://localhost:{}", address.port())).unwrap();
    let mut client = client(
        proxy.clone(),
        address,
        "testserver.com",
        true,
        Duration::from_secs(5),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let connector = ProxyConnector {
        proxy_uri: proxy_uri(&proxy).unwrap(),
        proxy,
        proxy_addresses: vec![unavailable, address],
        target_uri: client.uri.clone(),
        deadline,
        connect_deadline: deadline,
        control: client.control.clone(),
        connected: Arc::new(AtomicBool::new(false)),
        sent: client.sent.clone(),
    };
    let resolver = FixedResolver {
        uri: client.uri.clone(),
        addresses: vec![
            "1.1.1.1:443".parse().unwrap(),
            "8.8.8.8:443".parse().unwrap(),
        ],
    };
    client.agent = ureq::Agent::with_parts(client.agent.config().clone(), connector, resolver);
    let config = server_config();
    thread::scope(|scope| {
        let server = scope.spawn(move || {
            let mut first = accept(&listener);
            assert!(head(&mut first).starts_with("CONNECT 1.1.1.1:443 HTTP/1.1\r\n"));
            first
                .write_all(b"HTTP/1.1 502 Target unreachable\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
            first.flush().unwrap();
            drop(first);
            let mut second = accept(&listener);
            assert!(head(&mut second).starts_with("CONNECT 8.8.8.8:443 HTTP/1.1\r\n"));
            second
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .unwrap();
            second.flush().unwrap();
            serve_target(
                second,
                &config,
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
            );
            assert!(
                matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
            );
        });
        let mut response = request(
            &client.agent,
            &Method::POST,
            client.uri.clone(),
            &HeaderMap::new(),
            Some(b"payload"),
        )
        .unwrap();
        let mut body = String::new();
        response.read_to_string(&mut body).unwrap();
        assert_eq!(body, "OK");
        assert!(client.sent.load(Ordering::Acquire));
        server.join().unwrap();
    });
}

#[test]
fn resolver_and_credentials_fail_closed_without_external_dns_or_sockets() {
    let control = Control::new();
    let deadline = Instant::now() + Duration::from_secs(1);
    for target in ["https://127.0.0.1/api", "https://[::1]/api"] {
        assert!(addresses(&Url::parse(target).unwrap(), false, deadline, &control).is_err());
    }
    let uri: Uri = "https://testserver.com/api".parse().unwrap();
    let resolver = FixedResolver {
        uri,
        addresses: vec!["1.1.1.1:443".parse().unwrap()],
    };
    let timeout = NextTimeout {
        after: ureq::unversioned::transport::time::Duration::from_secs(1),
        reason: ureq::Timeout::Global,
    };
    assert!(
        resolver
            .resolve(
                &"https://other.example/api".parse().unwrap(),
                &Config::default(),
                timeout
            )
            .is_err()
    );
    assert_eq!(&*decode_credential("a%2Bb%20c").unwrap(), "a+b c");
    for invalid in ["%", "%z1", "%00", "%FF"] {
        assert!(decode_credential(invalid).is_err());
    }
    let proxy = validate_proxy("https://user:synthetic@[::1]:443").unwrap();
    assert_eq!(proxy_uri(&proxy).unwrap().to_string(), "https://[::1]:443/");
    control.cancel();
    assert!(matches!(
        addresses(
            &Url::parse("https://1.1.1.1/api").unwrap(),
            false,
            deadline,
            &control
        ),
        Err(Error::Canceled)
    ));
}
