use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use base64::{Engine, engine::general_purpose::STANDARD};
use subtle::ConstantTimeEq;

use crate::error::{Error, Result, poisoned};
use crate::transfers::control::Control;

pub const MAX_HEADER_BYTES: usize = 64 * 1024;

pub struct Request {
    pub method: String,
    pub target: String,
    pub version: String,
    pub headers: BTreeMap<String, String>,
}

impl Request {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_HEADER_BYTES || !bytes.ends_with(b"\r\n\r\n") {
            return Err(Error::invalid(
                "HTTP request head is incomplete or oversized",
            ));
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|_| Error::invalid("HTTP request head is not UTF-8"))?;
        let mut lines = text[..text.len() - 4].split("\r\n");
        let line = lines
            .next()
            .ok_or_else(|| Error::invalid("HTTP request line is missing"))?;
        if line.len() > 8192 {
            return Err(Error::invalid("HTTP request line is too long"));
        }
        let fields: Vec<_> = line.split(' ').collect();
        if fields.len() != 3
            || fields[0].is_empty()
            || fields[1].is_empty()
            || !matches!(fields[2], "HTTP/1.0" | "HTTP/1.1")
            || fields
                .iter()
                .any(|field| field.chars().any(char::is_control))
        {
            return Err(Error::invalid("HTTP request line is malformed"));
        }
        let mut headers = BTreeMap::new();
        for line in lines {
            if headers.len() >= 50 || line.len() > 8192 || line.starts_with([' ', '\t']) {
                return Err(Error::invalid(
                    "HTTP headers exceed their bounds or contain folding",
                ));
            }
            let (name, value) = line
                .split_once(':')
                .ok_or_else(|| Error::invalid("HTTP header has no separator"))?;
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                || value
                    .chars()
                    .any(|character| character.is_control() && character != '\t')
            {
                return Err(Error::invalid("HTTP header name or value is invalid"));
            }
            if headers
                .insert(name.to_ascii_lowercase(), value.trim().to_owned())
                .is_some()
            {
                return Err(Error::invalid("Duplicate HTTP header was refused"));
            }
        }
        if headers.contains_key("transfer-encoding") {
            return Err(Error::invalid("Chunked local requests are unsupported"));
        }
        Ok(Self {
            method: fields[0].into(),
            target: fields[1].into(),
            version: fields[2].into(),
            headers,
        })
    }
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }
}

pub fn read_head(stream: &mut TcpStream, timeout: Duration, control: &Control) -> Result<Request> {
    let deadline = Instant::now().checked_add(timeout).ok_or(Error::Timeout)?;
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        control.checkpoint_until(deadline)?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Error::Timeout);
        }
        stream.set_read_timeout(Some(remaining.min(Duration::from_millis(100))))?;
        let mut byte = [0];
        match stream.read(&mut byte) {
            Ok(0) => return Err(Error::invalid("HTTP peer closed before its request head")),
            Ok(_) => bytes.push(byte[0]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error.into()),
        }
        if bytes.len() > MAX_HEADER_BYTES {
            return Err(Error::invalid("HTTP request head exceeds 64 KiB"));
        }
    }
    Request::parse(&bytes)
}

fn equal(left: &str, right: &str) -> bool {
    bool::from(left.as_bytes().ct_eq(right.as_bytes()))
}

pub fn bearer_matches(request: &Request, expected: Option<&str>, query_allowed: bool) -> bool {
    let Some(expected) = expected.filter(|token| !token.is_empty()) else {
        return true;
    };
    if let Some(supplied) = request
        .header("authorization")
        .and_then(|value| value.strip_prefix("Bearer "))
    {
        return equal(supplied.trim(), expected);
    }
    if query_allowed
        && let Some((_, query)) = request.target.split_once('?')
        && let Some((_, value)) = url::form_urlencoded::parse(query.as_bytes())
            .find(|(key, _)| matches!(key.as_ref(), "token" | "access_token"))
    {
        return equal(&value, expected);
    }
    false
}

pub fn proxy_password_matches(request: &Request, expected: &str) -> bool {
    let Some(encoded) = request
        .header("proxy-authorization")
        .and_then(|value| value.strip_prefix("Basic "))
    else {
        return false;
    };
    if encoded.len() > 8192 {
        return false;
    }
    let Ok(bytes) = STANDARD.decode(encoded) else {
        return false;
    };
    let Ok(value) = std::str::from_utf8(&bytes) else {
        return false;
    };
    value
        .split_once(':')
        .is_some_and(|(_, password)| equal(password, expected))
}

pub fn reply(
    stream: &mut TcpStream,
    code: u16,
    headers: &[(&str, String)],
    body: &[u8],
) -> Result<()> {
    let reason = match code {
        200 => "OK",
        206 => "Partial Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        405 => "Method Not Allowed",
        407 => "Proxy Authentication Required",
        416 => "Range Not Satisfiable",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let mut head = format!("HTTP/1.1 {code} {reason}\r\nConnection: close\r\n");
    for (name, value) in headers {
        if name.contains(['\r', '\n']) || value.contains(['\r', '\n']) {
            return Err(Error::invalid("HTTP response header contains a newline"));
        }
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    if !headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("Content-Length"))
    {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;
    Ok(())
}

/// Retain the exact write offset while bounding idle time and the full stream lifetime.
pub(super) fn write_body(
    stream: &mut TcpStream,
    mut bytes: &[u8],
    control: &Control,
    deadline: Instant,
    idle: Duration,
) -> Result<()> {
    let mut idle_deadline = Instant::now().checked_add(idle).ok_or(Error::Timeout)?;
    while !bytes.is_empty() {
        control.checkpoint_until(deadline.min(idle_deadline))?;
        let remaining = deadline
            .min(idle_deadline)
            .saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Error::Timeout);
        }
        stream.set_write_timeout(Some(remaining.min(Duration::from_millis(100))))?;
        match stream.write(bytes) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "HTTP peer refused remaining body bytes",
                )
                .into());
            }
            Ok(count) => {
                bytes = &bytes[count..];
                idle_deadline = Instant::now().checked_add(idle).ok_or(Error::Timeout)?;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) => {}
            Err(_) if control.is_canceled() => return Err(Error::Canceled),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[path = "http_refusal.rs"]
mod refusal;

struct Active {
    sockets: HashMap<u64, TcpStream>,
    peers: HashMap<IpAddr, usize>,
}
impl Active {
    fn can_accept(&self, peer: IpAddr, workers: usize, per_peer: usize) -> bool {
        self.sockets.len() < workers && self.peers.get(&peer).copied().unwrap_or(0) < per_peer
    }
}
struct Connection {
    socket: TcpStream,
    peer: IpAddr,
    id: u64,
    active: Arc<Mutex<Active>>,
}
impl Drop for Connection {
    fn drop(&mut self) {
        let _ = self.socket.shutdown(Shutdown::Both);
        if let Ok(mut active) = self.active.lock() {
            active.sockets.remove(&self.id);
            if let Some(count) = active.peers.get_mut(&self.peer) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    active.peers.remove(&self.peer);
                }
            }
        }
    }
}

/// Fixed workers, no detached per-peer threads. Cancellation closes all accepted sockets before join.
pub fn serve(
    listener: TcpListener,
    workers: usize,
    per_peer: usize,
    control: &Control,
    handler: impl Fn(&mut TcpStream, SocketAddr) -> Result<()> + Sync,
    diagnostic: impl Fn(&Error) + Sync,
) -> Result<()> {
    serve_with_accept(
        listener,
        workers,
        per_peer,
        control,
        handler,
        diagnostic,
        TcpListener::accept,
    )
}

fn serve_with_accept(
    listener: TcpListener,
    workers: usize,
    per_peer: usize,
    control: &Control,
    handler: impl Fn(&mut TcpStream, SocketAddr) -> Result<()> + Sync,
    diagnostic: impl Fn(&Error) + Sync,
    mut accept: impl FnMut(&TcpListener) -> std::io::Result<(TcpStream, SocketAddr)>,
) -> Result<()> {
    if workers == 0 || workers > 64 || per_peer == 0 || per_peer > workers {
        return Err(Error::invalid("Local server worker limits are invalid"));
    }
    listener.set_nonblocking(true)?;
    let active = Arc::new(Mutex::new(Active {
        sockets: HashMap::new(),
        peers: HashMap::new(),
    }));
    let (sender, receiver) = mpsc::sync_channel::<(Connection, SocketAddr)>(workers);
    let receiver = Mutex::new(receiver);
    std::thread::scope(|scope| -> Result<()> {
        let mut threads = Vec::new();
        for index in 0..workers {
            let receiver = &receiver;
            let handler = &handler;
            let diagnostic = &diagnostic;
            let spawned = std::thread::Builder::new()
                .name(format!("local-peer-{index}"))
                .spawn_scoped(scope, move || {
                    loop {
                        let received = receiver
                            .lock()
                            .map_err(poisoned)?
                            .recv_timeout(Duration::from_millis(100));
                        match received {
                            Ok((mut connection, peer)) => {
                                let result =
                                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                        handler(&mut connection.socket, peer)
                                    }))
                                    .unwrap_or_else(|_| {
                                        Err(Error::protocol("Local peer worker was interrupted"))
                                    });
                                if let Err(error) = result {
                                    diagnostic(&error);
                                }
                            }
                            Err(mpsc::RecvTimeoutError::Timeout) if !control.is_canceled() => {
                                continue;
                            }
                            Err(_) => return Ok::<_, Error>(()),
                        }
                    }
                });
            match spawned {
                Ok(thread) => threads.push(thread),
                Err(error) => {
                    control.cancel();
                    drop(sender);
                    for thread in threads {
                        let _ = thread.join();
                    }
                    return Err(error.into());
                }
            }
        }
        let outcome = (|| {
            let mut sequence = 0u64;
            let mut refusals = refusal::Refusals::default();
            while !control.is_canceled() {
                refusals.poll();
                match accept(&listener) {
                    Ok((socket, peer)) => {
                        socket.set_nonblocking(false)?;
                        socket.set_write_timeout(Some(Duration::from_secs(1)))?;
                        let mut state = active.lock().map_err(poisoned)?;
                        if !state.can_accept(peer.ip(), workers, per_peer) {
                            drop(state);
                            refusals.push(socket);
                            continue;
                        }
                        sequence = sequence.checked_add(1).ok_or_else(|| {
                            Error::protocol("Server connection sequence exhausted")
                        })?;
                        state.sockets.insert(sequence, socket.try_clone()?);
                        *state.peers.entry(peer.ip()).or_default() += 1;
                        drop(state);
                        let connection = Connection {
                            socket,
                            peer: peer.ip(),
                            id: sequence,
                            active: active.clone(),
                        };
                        if sender.try_send((connection, peer)).is_err() {
                            return Err(Error::protocol(
                                "Server worker queue refused an owned connection",
                            ));
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        match control.wait(Duration::from_millis(20)) {
                            Err(Error::Canceled) => break,
                            result => result?,
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error.into()),
                }
            }
            Ok(())
        })();
        if outcome.is_err() {
            control.cancel();
        }
        if let Ok(state) = active.lock() {
            for socket in state.sockets.values() {
                let _ = socket.shutdown(Shutdown::Both);
            }
        }
        drop(sender);
        let mut failure = None;
        for thread in threads {
            match thread.join() {
                Ok(Ok(())) => (),
                Ok(Err(error)) => {
                    if failure.is_none() {
                        failure = Some(error);
                    }
                }
                Err(_) => {
                    if failure.is_none() {
                        failure = Some(Error::protocol("Server worker could not be reaped"));
                    }
                }
            }
        }
        match failure {
            Some(error) => Err(error),
            None => outcome,
        }
    })
}

#[cfg(test)]
#[path = "http_body_tests.rs"]
mod body_tests;
#[cfg(test)]
#[path = "http_peer_tests.rs"]
mod peer_tests;
