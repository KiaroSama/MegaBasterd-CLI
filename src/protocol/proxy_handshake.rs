use std::{
    io::{Read, Write},
    net::SocketAddr,
};

use base64::{Engine, engine::general_purpose::STANDARD};
use zeroize::Zeroizing;

use super::dns::is_public;
use crate::error::{Error, Result};

fn destination(target: SocketAddr) -> Result<()> {
    if target.port() == 0 || !is_public(target.ip()) {
        return Err(Error::invalid(
            "Proxy tunnel requires a public numeric destination and nonzero port",
        ));
    }
    Ok(())
}

pub fn connect(
    stream: &mut (impl Read + Write),
    target: SocketAddr,
    credentials: Option<(&str, &str)>,
) -> Result<()> {
    destination(target)?;
    let mut head = Zeroizing::new(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n"));
    if let Some((user, password)) = credentials {
        if user.contains(':')
            || user.len().saturating_add(password.len()) > 4096
            || user.chars().chain(password.chars()).any(char::is_control)
        {
            return Err(Error::invalid(
                "Proxy credentials are unsupported or oversized",
            ));
        }
        let raw = Zeroizing::new(format!("{user}:{password}"));
        let encoded = Zeroizing::new(STANDARD.encode(raw.as_bytes()));
        head.push_str("Proxy-Authorization: Basic ");
        head.push_str(&encoded);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    stream.flush()?;
    let mut reply = Zeroizing::new(Vec::new());
    while !reply.ends_with(b"\r\n\r\n") {
        if reply.len() >= 64 * 1024 {
            return Err(Error::protocol(
                "CONNECT proxy response header exceeds its bound",
            ));
        }
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        reply.push(byte[0]);
    }
    let reply = std::str::from_utf8(&reply)
        .map_err(|_| Error::protocol("CONNECT proxy response is not UTF-8"))?;
    let mut lines = reply.split("\r\n");
    let mut status = lines.next().unwrap_or("").split_whitespace();
    if !matches!(status.next(), Some("HTTP/1.0" | "HTTP/1.1")) {
        return Err(Error::protocol("CONNECT proxy status is malformed"));
    }
    match status.next() {
        Some("200") => (),
        Some("407") => {
            return Err(Error::Auth(
                "CONNECT proxy authentication was rejected".into(),
            ));
        }
        _ => return Err(Error::protocol("CONNECT proxy refused the tunnel")),
    }
    let mut count = 0;
    for line in lines.take_while(|line| !line.is_empty()) {
        count += 1;
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| Error::protocol("CONNECT proxy header is malformed"))?;
        if count > 50
            || line.len() > 8192
            || reqwest::header::HeaderName::from_bytes(name.as_bytes()).is_err()
            || reqwest::header::HeaderValue::from_bytes(value.trim().as_bytes()).is_err()
            || line.contains(['\r', '\n'])
            || name.eq_ignore_ascii_case("transfer-encoding")
            || (name.eq_ignore_ascii_case("content-length") && value.trim() != "0")
        {
            return Err(Error::protocol(
                "CONNECT proxy response framing is unsupported",
            ));
        }
    }
    Ok(())
}

pub fn socks5(
    stream: &mut (impl Read + Write),
    target: SocketAddr,
    credentials: Option<(&str, &str)>,
) -> Result<()> {
    destination(target)?;
    if let Some((user, password)) = credentials
        && (user.is_empty()
            || password.is_empty()
            || user.len() > 255
            || password.len() > 255
            || user.chars().chain(password.chars()).any(char::is_control))
    {
        return Err(Error::invalid(
            "SOCKS credentials require 1..255 bytes without control characters",
        ));
    }
    let method = if credentials.is_some() { 2 } else { 0 };
    stream.write_all(&[5, 1, method])?;
    stream.flush()?;
    let mut selected = [0; 2];
    stream.read_exact(&mut selected)?;
    if selected != [5, method] {
        return Err(Error::protocol(
            "SOCKS proxy refused the required authentication method",
        ));
    }
    if let Some((user, password)) = credentials {
        let user_size = u8::try_from(user.len())
            .map_err(|_| Error::invalid("SOCKS username exceeds255bytes"))?;
        let pass_size = u8::try_from(password.len())
            .map_err(|_| Error::invalid("SOCKS password exceeds255bytes"))?;
        if user_size == 0 || pass_size == 0 {
            return Err(Error::invalid(
                "SOCKS authentication requires nonempty username and password",
            ));
        }
        let mut auth = Zeroizing::new(vec![1, user_size]);
        auth.extend_from_slice(user.as_bytes());
        auth.push(pass_size);
        auth.extend_from_slice(password.as_bytes());
        stream.write_all(&auth)?;
        stream.flush()?;
        let mut response = [0; 2];
        stream.read_exact(&mut response)?;
        if response != [1, 0] {
            return Err(Error::Auth(
                "SOCKS proxy authentication was rejected".into(),
            ));
        }
    }
    let mut request = vec![5, 1, 0];
    match target.ip() {
        std::net::IpAddr::V4(ip) => {
            request.push(1);
            request.extend(ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            request.push(4);
            request.extend(ip.octets());
        }
    }
    request.extend(target.port().to_be_bytes());
    stream.write_all(&request)?;
    stream.flush()?;
    let mut response = [0; 4];
    stream.read_exact(&mut response)?;
    if response[..3] != [5, 0, 0] {
        return Err(Error::protocol("SOCKS proxy refused the numeric tunnel"));
    }
    let size = match response[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut size = [0];
            stream.read_exact(&mut size)?;
            if size[0] == 0 {
                return Err(Error::protocol(
                    "SOCKS proxy returned an empty bound hostname",
                ));
            }
            usize::from(size[0])
        }
        _ => {
            return Err(Error::protocol(
                "SOCKS proxy returned an invalid address family",
            ));
        }
    };
    let mut bound = vec![0; size + 2];
    stream.read_exact(&mut bound)?;
    Ok(())
}
