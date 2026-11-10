use std::fmt;
use std::io;
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use reqwest::{Method, header::HeaderMap};
use ureq::config::Config;
use ureq::http::Uri;
use ureq::tls::{RootCerts, TlsConfig};
use ureq::unversioned::resolver::{ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::{
    ConnectionDetails, Connector, NextTimeout, RustlsConnector, Transport, TransportAdapter,
};
use url::{Host, Url};
use zeroize::Zeroizing;

use super::dns::SafeResolver;
use super::http_response::HttpResponse;
use super::http_wait::interruptible;
use super::proxy_handshake;
use super::proxy_io::{Socket, Target, Tunnel};
use super::transport::{AttemptFailure, safe_target};
use crate::error::{Error, Result};
use crate::storage::proxies::validate_proxy;
use crate::transfers::control::Control;

fn stopped(control: &Control, deadline: Instant) -> Result<Duration> {
    if control.is_canceled() {
        return Err(Error::Canceled);
    }
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(Error::Timeout);
    }
    Ok(remaining)
}

fn addresses(
    url: &Url,
    trusted: bool,
    deadline: Instant,
    control: &Control,
) -> Result<Vec<SocketAddr>> {
    stopped(control, deadline)?;
    if !trusted {
        safe_target(url)?;
    }
    let port = url
        .port_or_known_default()
        .ok_or_else(|| Error::invalid("Endpoint has no port"))?;
    let host = match url
        .host()
        .ok_or_else(|| Error::invalid("Endpoint has no host"))?
    {
        Host::Ipv4(ip) => return Ok(vec![SocketAddr::new(ip.into(), port)]),
        Host::Ipv6(ip) => return Ok(vec![SocketAddr::new(ip.into(), port)]),
        Host::Domain(host) => host,
    };
    let resolver = SafeResolver::new(
        stopped(control, deadline)?,
        trusted.then(|| host.to_owned()),
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let resolved = runtime.block_on(interruptible(
        async {
            resolver
                .resolve_name(host)
                .await
                .map_err(|_| Error::protocol("Endpoint DNS failed or returned an unsafe address"))
        },
        deadline,
        control,
    ))?;
    let addresses: Vec<_> = resolved
        .take(16)
        .map(|mut address| {
            address.set_port(port);
            address
        })
        .collect();
    if addresses.is_empty() {
        return Err(Error::protocol("Endpoint has no usable addresses"));
    }
    Ok(addresses)
}

struct FixedResolver {
    uri: Uri,
    addresses: Vec<SocketAddr>,
}

impl Resolver for FixedResolver {
    fn resolve(
        &self,
        uri: &Uri,
        _: &Config,
        _: NextTimeout,
    ) -> std::result::Result<ResolvedSocketAddrs, ureq::Error> {
        if uri != &self.uri {
            return Err(
                io::Error::new(io::ErrorKind::PermissionDenied, "Unexpected proxy target").into(),
            );
        }
        let mut result = self.empty();
        for address in &self.addresses {
            result.push(*address);
        }
        Ok(result)
    }
}

impl fmt::Debug for FixedResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinnedResolver").finish_non_exhaustive()
    }
}

struct ProxyConnector {
    proxy: Url,
    proxy_uri: Uri,
    proxy_addresses: Vec<SocketAddr>,
    target_uri: Uri,
    deadline: Instant,
    connect_deadline: Instant,
    control: Control,
    connected: Arc<AtomicBool>,
    sent: Arc<AtomicBool>,
}

impl ProxyConnector {
    fn socket(&self, connect_deadline: Instant) -> Result<TcpStream> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(interruptible(
            async {
                let mut last = None;
                for (index, address) in self.proxy_addresses.iter().enumerate() {
                    let budget = stopped(&self.control, connect_deadline)?
                        / (self.proxy_addresses.len() - index) as u32;
                    match tokio::time::timeout(budget, tokio::net::TcpStream::connect(*address))
                        .await
                    {
                        Ok(Ok(stream)) => {
                            let stream = stream.into_std()?;
                            stream.set_nonblocking(false)?;
                            return Ok(stream);
                        }
                        Ok(Err(error)) => last = Some(error),
                        Err(_) => {
                            last = Some(io::Error::new(
                                io::ErrorKind::TimedOut,
                                "Proxy address connect timed out",
                            ))
                        }
                    }
                }
                Err(last
                    .map(Error::Io)
                    .unwrap_or_else(|| Error::protocol("Configured proxy has no usable addresses")))
            },
            connect_deadline,
            &self.control,
        ))
    }

    fn tunnel(&self, details: &ConnectionDetails) -> Result<Box<dyn Transport>> {
        if details.uri != &self.target_uri {
            return Err(Error::protocol("Unexpected proxy destination"));
        }
        if details
            .addrs
            .iter()
            .any(|address| address.port() == 0 || !super::dns::is_public(address.ip()))
        {
            return Err(Error::protocol("Proxy destination is not public"));
        }
        let targets: Vec<_> = details.addrs.iter().copied().collect();
        let mut last = None;
        for (index, target) in targets.iter().copied().enumerate() {
            let remaining = stopped(&self.control, self.connect_deadline)?;
            let deadline = Instant::now() + remaining / (targets.len() - index) as u32;
            match self.tunnel_one(details, target, deadline) {
                Ok(transport) => return Ok(transport),
                Err(error @ (Error::Canceled | Error::Invalid(_) | Error::Auth(_))) => {
                    return Err(error);
                }
                Err(error) => last = Some(error),
            }
        }
        Err(last.unwrap_or_else(|| Error::protocol("Target DNS returned no address")))
    }

    fn tunnel_one(
        &self,
        details: &ConnectionDetails,
        target: SocketAddr,
        connect_deadline: Instant,
    ) -> Result<Box<dyn Transport>> {
        let user = decode_credential(self.proxy.username())?;
        let password = self.proxy.password().map(decode_credential).transpose()?;
        if !matches!(self.proxy.scheme(), "http" | "https" | "socks5h") {
            return Err(Error::invalid("Pinned proxy scheme is unsupported"));
        }
        let socket = Socket::new(
            self.socket(connect_deadline)?,
            self.control.clone(),
            self.deadline,
            connect_deadline,
            self.connected.clone(),
        )?;
        let mut transport: Box<dyn Transport> = Box::new(socket);
        let tls = RustlsConnector::default();
        if self.proxy.scheme() == "https" {
            let mut proxy_addresses = details.resolver.empty();
            for address in &self.proxy_addresses {
                proxy_addresses.push(*address);
            }
            let outer = ConnectionDetails {
                uri: &self.proxy_uri,
                addrs: proxy_addresses,
                config: details.config,
                request_level: details.request_level,
                resolver: details.resolver,
                now: details.now,
                timeout: details.timeout,
                current_time: details.current_time.clone(),
                run_connector: details.run_connector.clone(),
            };
            transport = tls
                .connect(&outer, Some(transport))
                .map_err(|_| Error::protocol("HTTPS proxy TLS verification or handshake failed"))?
                .ok_or_else(|| Error::protocol("HTTPS proxy did not establish TLS"))?
                .boxed();
            if !transport.is_tls() {
                return Err(Error::protocol("HTTPS proxy requires verified TLS"));
            }
        }
        let credentials = if self.proxy.username().is_empty() && password.is_none() {
            None
        } else {
            Some((
                user.as_str(),
                password.as_deref().map_or("", |value| value.as_str()),
            ))
        };
        let mut stream = TransportAdapter::new(transport);
        stream.set_timeout(details.timeout);
        match self.proxy.scheme() {
            "http" | "https" => proxy_handshake::connect(&mut stream, target, credentials)?,
            "socks5h" => proxy_handshake::socks5(&mut stream, target, credentials)?,
            _ => return Err(Error::invalid("Pinned proxy scheme is unsupported")),
        }
        // Reset TLS context after CONNECT: outer TLS authenticates the proxy, not the target.
        let tunnel = Tunnel(stream.into_inner());
        let transport = tls
            .connect(details, Some(tunnel))
            .map_err(|_| Error::protocol("Destination TLS verification or handshake failed"))?
            .ok_or_else(|| Error::protocol("Proxy target did not establish TLS"))?
            .boxed();
        if !transport.is_tls() {
            return Err(Error::protocol("Proxy destination requires verified TLS"));
        }
        stopped(&self.control, connect_deadline)?;
        self.connected.store(true, Ordering::Release);
        Ok(transport)
    }
}

impl Connector for ProxyConnector {
    type Out = Target;
    fn connect(
        &self,
        details: &ConnectionDetails,
        _: Option<()>,
    ) -> std::result::Result<Option<Target>, ureq::Error> {
        let transport = self
            .tunnel(details)
            .map_err(|error| ureq::Error::Other(Box::new(error)))?;
        Ok(Some(Target {
            inner: transport,
            sent: self.sent.clone(),
            control: self.control.clone(),
        }))
    }
}

impl fmt::Debug for ProxyConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinnedProxyConnector")
            .finish_non_exhaustive()
    }
}

fn proxy_uri(proxy: &Url) -> Result<Uri> {
    let host = proxy
        .host()
        .ok_or_else(|| Error::invalid("Proxy has no host"))?;
    let port = proxy
        .port_or_known_default()
        .ok_or_else(|| Error::invalid("Proxy has no port"))?;
    format!(
        "{}://{host}:{port}/",
        if proxy.scheme() == "https" {
            "https"
        } else {
            "http"
        }
    )
    .parse()
    .map_err(|_| Error::invalid("Proxy URI is invalid"))
}

fn decode_credential(value: &str) -> Result<Zeroizing<String>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(value.len()));
    let mut input = value.as_bytes().iter().copied();
    while let Some(byte) = input.next() {
        if byte == b'%' {
            let high = input.next().and_then(|byte| (byte as char).to_digit(16));
            let low = input.next().and_then(|byte| (byte as char).to_digit(16));
            let (Some(high), Some(low)) = (high, low) else {
                return Err(Error::invalid(
                    "Proxy credentials have invalid percent encoding",
                ));
            };
            bytes.push((high * 16 + low) as u8);
        } else {
            bytes.push(byte);
        }
    }
    let value = std::str::from_utf8(&bytes)
        .map_err(|_| Error::invalid("Proxy credentials must be valid UTF-8"))?;
    if value.chars().any(char::is_control) {
        return Err(Error::invalid(
            "Proxy credentials contain control characters",
        ));
    }
    Ok(Zeroizing::new(value.to_owned()))
}

pub(super) fn send(
    method: &Method,
    url: &Url,
    headers: &HeaderMap,
    body: Option<&[u8]>,
    proxy: &str,
    timeout: Duration,
    user_agent: &str,
    control: &Control,
    #[cfg(test)] test_peer: Option<SocketAddr>,
) -> std::result::Result<HttpResponse, AttemptFailure> {
    let sent = Arc::new(AtomicBool::new(false));
    let result = (|| {
        safe_target(url)?;
        let proxy = validate_proxy(proxy)?;
        let deadline = Instant::now().checked_add(timeout).ok_or(Error::Timeout)?;
        let connect_deadline = Instant::now()
            .checked_add(timeout.min(Duration::from_secs(20)))
            .ok_or(Error::Timeout)?
            .min(deadline);
        #[cfg(test)]
        let fixed = test_peer
            .map(|address| {
                if url.host_str() != Some("testserver.com")
                    || url.port() != Some(address.port())
                    || proxy.host_str() != Some("127.0.0.1")
                    || proxy.port() != Some(address.port())
                    || proxy.scheme() != "http"
                {
                    return Err(Error::invalid("Proxy fixture escaped its selected peer"));
                }
                Ok((
                    vec![SocketAddr::from(([1, 1, 1, 1], address.port()))],
                    vec![address],
                ))
            })
            .transpose()?;
        #[cfg(test)]
        let (target_addresses, proxy_addresses) = if let Some(fixed) = fixed {
            fixed
        } else {
            (
                addresses(url, false, connect_deadline, control)?,
                addresses(&proxy, true, connect_deadline, control)?,
            )
        };
        #[cfg(not(test))]
        let (target_addresses, proxy_addresses) = (
            addresses(url, false, connect_deadline, control)?,
            addresses(&proxy, true, connect_deadline, control)?,
        );
        let uri: Uri = url
            .as_str()
            .parse()
            .map_err(|_| Error::invalid("Target URI is invalid"))?;
        let proxy_uri = proxy_uri(&proxy)?;
        let roots = RootCerts::PlatformVerifier;
        #[cfg(test)]
        let roots = if test_peer.is_some() {
            RootCerts::new_with_certs(&[ureq::tls::Certificate::from_der(include_bytes!(
                "../../tests/fixtures/proxy_tls/root.der"
            ))])
        } else {
            roots
        };
        let config = Config::builder()
            .proxy(None)
            .https_only(true)
            .http_status_as_error(false)
            .max_redirects(0)
            .max_idle_connections(0)
            .max_idle_connections_per_host(0)
            .timeout_global(Some(stopped(control, deadline)?))
            .timeout_connect(Some(stopped(control, connect_deadline)?))
            .timeout_send_request(Some(timeout))
            .timeout_send_body(Some(timeout))
            .timeout_recv_response(Some(timeout))
            .timeout_recv_body(Some(timeout))
            .input_buffer_size(64 * 1024)
            .output_buffer_size(64 * 1024)
            .user_agent(user_agent)
            .tls_config(
                TlsConfig::builder()
                    .root_certs(roots)
                    .unversioned_rustls_crypto_provider(Arc::new(
                        rustls::crypto::aws_lc_rs::default_provider(),
                    ))
                    .build(),
            )
            .build();
        let resolver = FixedResolver {
            uri: uri.clone(),
            addresses: target_addresses,
        };
        let connector = ProxyConnector {
            proxy,
            proxy_uri,
            proxy_addresses,
            target_uri: uri.clone(),
            deadline,
            connect_deadline,
            control: control.clone(),
            connected: Arc::new(AtomicBool::new(false)),
            sent: sent.clone(),
        };
        let agent = ureq::Agent::with_parts(config, connector, resolver);
        request(&agent, method, uri, headers, body).map_err(|error| {
            if control.is_canceled() {
                Error::Canceled
            } else if Instant::now() >= deadline {
                Error::Timeout
            } else {
                error
            }
        })
    })();
    result.map_err(|error| AttemptFailure {
        error,
        sent: sent.load(Ordering::Acquire),
    })
}

fn network_error(error: ureq::Error) -> Error {
    match error {
        ureq::Error::Timeout(_) => Error::Timeout,
        ureq::Error::Io(error) => {
            let kind = if error.kind() == io::ErrorKind::UnexpectedEof {
                io::ErrorKind::ConnectionAborted
            } else {
                error.kind()
            };
            Error::Io(io::Error::new(kind, "Proxy network I/O failed"))
        }
        ureq::Error::Other(error) => match error.downcast::<Error>() {
            Ok(error) => *error,
            Err(_) => Error::protocol("Pinned proxy connection failed"),
        },
        ureq::Error::HostNotFound | ureq::Error::ConnectionFailed => Error::Io(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "Configured proxy could not establish a connection",
        )),
        _ => Error::protocol(
            "Pinned proxy HTTP request failed; check authentication, framing and TLS",
        ),
    }
}

fn request(
    agent: &ureq::Agent,
    method: &Method,
    uri: Uri,
    headers: &HeaderMap,
    body: Option<&[u8]>,
) -> Result<HttpResponse> {
    let mut request = ureq::http::Request::builder()
        .method(method.as_str())
        .uri(uri);
    for (name, value) in headers {
        if name == reqwest::header::PROXY_AUTHORIZATION || name == reqwest::header::HOST {
            return Err(Error::invalid(
                "Target headers cannot override proxy authentication or TLS authority",
            ));
        }
        request = request.header(name.as_str(), value.as_bytes());
    }
    use ureq::AsSendBody;
    let mut bytes = body.unwrap_or_default();
    let body = if body.is_some() {
        bytes.as_body()
    } else {
        ureq::SendBody::none()
    };
    let request = request
        .header("accept-encoding", "identity")
        .header("connection", "close")
        .body(body)
        .map_err(|_| Error::invalid("HTTP request headers are invalid"))?;
    let response = agent.run(request).map_err(network_error)?;
    let (parts, body) = response.into_parts();
    let status = reqwest::StatusCode::from_u16(parts.status.as_u16())
        .map_err(|_| Error::protocol("HTTP response status is invalid"))?;
    let mut headers = HeaderMap::new();
    for (name, value) in &parts.headers {
        let name = reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes())
            .map_err(|_| Error::protocol("HTTP response header name is invalid"))?;
        let value = reqwest::header::HeaderValue::from_bytes(value.as_bytes())
            .map_err(|_| Error::protocol("HTTP response header value is invalid"))?;
        headers.append(name, value);
    }
    Ok(HttpResponse::streamed(
        status,
        headers,
        ProxyBody(body.into_reader()),
    ))
}

struct ProxyBody<R>(R);

impl<R: io::Read> io::Read for ProxyBody<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.0.read(output).map_err(|error| {
            let kind = if error
                .get_ref()
                .and_then(|cause| cause.downcast_ref::<ureq::Error>())
                .is_some_and(|cause| matches!(cause, ureq::Error::Timeout(_)))
            {
                io::ErrorKind::TimedOut
            } else if error.kind() == io::ErrorKind::UnexpectedEof {
                // Only this network reader knows that EOF came from the connection, not a decoder.
                io::ErrorKind::ConnectionAborted
            } else {
                error.kind()
            };
            io::Error::new(kind, "Proxy HTTP response body failed")
        })
    }
}

#[cfg(test)]
#[path = "proxy_transport_tests.rs"]
mod tests;
