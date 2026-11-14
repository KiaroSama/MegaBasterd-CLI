use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use url::Url;

use super::http::{self, Request};
use crate::error::{Error, Result};
use crate::protocol::dns::{SafeResolver, is_public};
use crate::transfers::control::Control;

#[cfg(test)]
#[path = "connect_peer_tests.rs"]
mod peer_tests;

#[derive(Clone, Copy)]
struct Limits {
    header: Duration,
    idle: Duration,
    lifetime: Duration,
}

pub struct Destination {
    pub host: String,
    pub port: u16,
    pub path: Option<String>,
}

pub fn destination(request: &Request, any_port: bool) -> Result<Destination> {
    let (host, port, path) = if request.method == "CONNECT" {
        let (host, port) = request
            .target
            .rsplit_once(':')
            .ok_or_else(|| Error::invalid("CONNECT needs host:port"))?;
        let port = port
            .parse::<u16>()
            .map_err(|_| Error::invalid("CONNECT port is invalid"))?;
        (host.to_owned(), port, None)
    } else {
        if !matches!(
            request.method.as_str(),
            "GET" | "HEAD" | "POST" | "PUT" | "OPTIONS" | "DELETE"
        ) {
            return Err(Error::invalid("Unsupported proxy method"));
        }
        let url =
            Url::parse(&request.target).map_err(|_| Error::invalid("Proxy target is invalid"))?;
        if url.scheme() != "http"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(Error::invalid(
                "HTTP forwarding requires a credential-free absolute HTTP URL",
            ));
        }
        let path = format!(
            "{}{}",
            url.path(),
            url.query()
                .map(|query| format!("?{query}"))
                .unwrap_or_default()
        );
        (
            url.host_str()
                .ok_or_else(|| Error::invalid("Proxy target has no host"))?
                .to_owned(),
            url.port_or_known_default().unwrap_or(80),
            Some(path),
        )
    };
    let host = host.to_ascii_lowercase();
    if port == 0
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        || !["mega.nz", "mega.co.nz"]
            .iter()
            .any(|base| host == *base || host.ends_with(&format!(".{base}")))
    {
        return Err(Error::invalid(
            "Proxy destination is outside approved MEGA domains",
        ));
    }
    if !any_port
        && (if path.is_none() {
            port != 443
        } else {
            port != 80 && port != 443
        })
    {
        return Err(Error::invalid("Proxy destination port is forbidden"));
    }
    Ok(Destination { host, port, path })
}

pub fn dial(host: &str, port: u16, timeout: Duration, control: &Control) -> Result<TcpStream> {
    dial_endpoint(host, port, timeout, control, false)
}

pub fn probe_proxy(proxy: &str, timeout: Duration, control: &Control) -> Result<TcpStream> {
    let proxy = crate::storage::proxies::validate_proxy(proxy)?;
    let host = match proxy
        .host()
        .ok_or_else(|| Error::invalid("Proxy has no host"))?
    {
        url::Host::Domain(host) => host.to_owned(),
        url::Host::Ipv4(ip) => ip.to_string(),
        url::Host::Ipv6(ip) => ip.to_string(),
    };
    let port = proxy
        .port_or_known_default()
        .ok_or_else(|| Error::invalid("Proxy has no port"))?;
    dial_endpoint(&host, port, timeout, control, true)
}

fn dial_endpoint(
    host: &str,
    port: u16,
    timeout: Duration,
    control: &Control,
    trusted_proxy: bool,
) -> Result<TcpStream> {
    control.checkpoint()?;
    if port == 0 || timeout.is_zero() {
        return Err(Error::invalid("Endpoint port and timeout must be positive"));
    }
    let deadline = Instant::now().checked_add(timeout).ok_or(Error::Timeout)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(crate::protocol::http_wait::interruptible(
        async {
            let addresses = if let Ok(ip) = host.parse::<IpAddr>() {
                if !trusted_proxy && !is_public(ip) {
                    return Err(Error::invalid("Proxy destination address is nonpublic"));
                }
                vec![SocketAddr::new(ip, port)]
            } else {
                let resolver = SafeResolver::new(timeout, trusted_proxy.then(|| host.to_owned()));
                let addresses = resolver
                    .resolve_name(host)
                    .await
                    .map_err(|_| Error::protocol("Proxy destination DNS failed or was refused"))?;
                addresses
                    .take(32)
                    .map(|mut address| {
                        address.set_port(port);
                        address
                    })
                    .collect::<Vec<_>>()
            };
            let mut last = None;
            for (index, address) in addresses.iter().enumerate() {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(Error::Timeout);
                }
                let budget = remaining / (addresses.len() - index) as u32;
                match tokio::time::timeout(budget, tokio::net::TcpStream::connect(*address)).await {
                    Ok(Ok(socket)) => {
                        let socket = socket.into_std()?;
                        socket.set_nonblocking(false)?;
                        return Ok(socket);
                    }
                    Ok(Err(error)) => last = Some(error),
                    Err(_) => {
                        last = Some(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "Proxy address connect timed out",
                        ))
                    }
                }
            }
            Err(last
                .map(Error::Io)
                .unwrap_or_else(|| Error::protocol("Proxy destination has no usable addresses")))
        },
        deadline,
        control,
    ))
}

pub fn serve(
    port: u16,
    password: &str,
    any_port: bool,
    control: &Control,
    diagnostic: impl Fn(&Error) + Sync,
) -> Result<()> {
    if password.is_empty() || password.len() > 4096 || password.contains('\0') {
        return Err(Error::invalid(
            "Local proxy needs a nonempty bounded authentication password",
        ));
    }
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    http::serve(
        listener,
        64,
        32,
        control,
        |socket, _| handle(socket, password, any_port, control),
        diagnostic,
    )
}

fn handle(client: &mut TcpStream, password: &str, any_port: bool, control: &Control) -> Result<()> {
    handle_with(
        client,
        password,
        any_port,
        control,
        Limits {
            header: Duration::from_secs(30),
            idle: Duration::from_secs(300),
            lifetime: Duration::from_secs(3600),
        },
        dial,
    )
}

fn handle_with(
    client: &mut TcpStream,
    password: &str,
    any_port: bool,
    control: &Control,
    limits: Limits,
    dial: impl FnOnce(&str, u16, Duration, &Control) -> Result<TcpStream>,
) -> Result<()> {
    let request = match http::read_head(client, limits.header, control) {
        Ok(request) => request,
        Err(error) => {
            let _ = http::reply(client, 400, &[], b"");
            return Err(error);
        }
    };
    if !http::proxy_password_matches(&request, password) {
        return http::reply(
            client,
            407,
            &[(
                "Proxy-Authenticate",
                "Basic realm=\"megabasterd-cli\"".into(),
            )],
            b"",
        );
    }
    let target = match destination(&request, any_port) {
        Ok(target) => target,
        Err(error) => {
            http::reply(client, 403, &[], b"")?;
            return Err(error);
        }
    };
    let mut upstream = match dial(&target.host, target.port, Duration::from_secs(30), control) {
        Ok(socket) => socket,
        Err(error) => {
            http::reply(client, 502, &[], b"")?;
            return Err(error);
        }
    };
    upstream.set_write_timeout(Some(Duration::from_secs(1)))?;
    if let Some(path) = target.path {
        let mut head = format!(
            "{} {path} {}\r\nHost: {}:{}\r\nConnection: close\r\n",
            request.method, request.version, target.host, target.port
        );
        for (name, value) in request.headers {
            if matches!(
                name.as_str(),
                "proxy-authorization" | "proxy-connection" | "connection" | "host"
            ) {
                continue;
            }
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        head.push_str("\r\n");
        upstream.write_all(head.as_bytes())?;
    } else {
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
        client.flush()?;
    }
    tunnel(client, &mut upstream, control, limits)
}

struct Buffer {
    bytes: Vec<u8>,
    sent: usize,
    eof: bool,
}

fn pump(source: &mut TcpStream, destination: &mut TcpStream, buffer: &mut Buffer) -> Result<bool> {
    let mut moved = false;
    if !buffer.eof && buffer.sent == buffer.bytes.len() {
        buffer.bytes.clear();
        buffer.sent = 0;
        let mut block = [0; 64 * 1024];
        match source.read(&mut block) {
            Ok(0) => {
                buffer.eof = true;
                let _ = destination.shutdown(Shutdown::Write);
            }
            Ok(count) => {
                buffer.bytes.extend_from_slice(&block[..count]);
                moved = true;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error.into()),
        }
    }
    if buffer.sent != buffer.bytes.len() {
        match destination.write(&buffer.bytes[buffer.sent..]) {
            Ok(0) => return Err(Error::protocol("Proxy peer refused remaining bytes")),
            Ok(count) => {
                buffer.sent += count;
                moved = true;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(moved)
}

fn tunnel(
    client: &mut TcpStream,
    upstream: &mut TcpStream,
    control: &Control,
    limits: Limits,
) -> Result<()> {
    client.set_nonblocking(true)?;
    upstream.set_nonblocking(true)?;
    let mut forward = Buffer {
        bytes: Vec::new(),
        sent: 0,
        eof: false,
    };
    let mut reverse = Buffer {
        bytes: Vec::new(),
        sent: 0,
        eof: false,
    };
    let start = Instant::now();
    let deadline = start.checked_add(limits.lifetime).ok_or(Error::Timeout)?;
    let mut activity = start;
    let result = (|| {
        loop {
            let idle_deadline = activity.checked_add(limits.idle).ok_or(Error::Timeout)?;
            control.checkpoint_until(deadline.min(idle_deadline))?;
            let changed =
                pump(client, upstream, &mut forward)? | pump(upstream, client, &mut reverse)?;
            if changed {
                activity = Instant::now();
            }
            if forward.eof
                && reverse.eof
                && forward.sent == forward.bytes.len()
                && reverse.sent == reverse.bytes.len()
            {
                return Ok(());
            }
            if !changed {
                control.wait(Duration::from_millis(10))?;
            }
        }
    })();
    let _ = upstream.shutdown(Shutdown::Both);
    result
}
