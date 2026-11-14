use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use reqwest::{
    Method,
    header::{HeaderMap, HeaderValue, RANGE},
};
use url::Url;

use super::http;
use crate::crypto::{keys, wire};
use crate::error::{Error, Result, poisoned};
use crate::protocol::{
    api::Api,
    metadata::{self, FileInfo},
    ranges,
};
use crate::transfers::control::Control;

struct Source {
    api: Api,
    info: FileInfo,
    generation: u64,
}

pub struct StreamServer {
    listener: TcpListener,
    source: Mutex<Source>,
    token: Option<zeroize::Zeroizing<String>>,
    query_token: bool,
}

pub fn loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .trim_matches(['[', ']'])
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

pub fn dialable(address: SocketAddr) -> String {
    let ip = if address.ip().is_unspecified() {
        if address.is_ipv6() {
            IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
        } else {
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        }
    } else {
        address.ip()
    };
    format!("http://{}/", SocketAddr::new(ip, address.port()))
}

pub fn content_disposition(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|character| {
            if character.is_control() || character == '\\' {
                '_'
            } else {
                character
            }
        })
        .collect();
    let ascii: String = cleaned.chars().filter(char::is_ascii).collect();
    let ascii = if ascii.is_empty() { "download" } else { &ascii };
    let ascii = ascii.replace('"', "\\\"");
    let encoded: String = url::form_urlencoded::byte_serialize(cleaned.as_bytes()).collect();
    let encoded = encoded
        .replace('+', "%20")
        .replace('*', "%2A")
        .replace("%7E", "~");
    format!("inline; filename=\"{ascii}\"; filename*=UTF-8''{encoded}")
}

impl StreamServer {
    pub fn bind(
        host: &str,
        port: u16,
        api: Api,
        info: FileInfo,
        token: Option<String>,
        query_token: bool,
    ) -> Result<Self> {
        if token
            .as_ref()
            .is_some_and(|token| token.len() > 8192 || token.chars().any(char::is_control))
        {
            return Err(Error::invalid(
                "Stream token is oversized or contains controls",
            ));
        }
        let token = token.filter(|value| !value.is_empty());
        if !loopback_host(host) && token.as_ref().is_none_or(|value| value.trim().is_empty()) {
            return Err(Error::invalid(
                "A non-loopback stream requires an access token before binding",
            ));
        }
        let listener = TcpListener::bind((host.trim_matches(['[', ']']), port))?;
        Ok(Self {
            listener,
            source: Mutex::new(Source {
                api,
                info,
                generation: 0,
            }),
            token: token.map(zeroize::Zeroizing::new),
            query_token,
        })
    }
    pub fn address(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }
    pub fn serve(self, control: &Control, diagnostic: impl Fn(&Error) + Sync) -> Result<()> {
        let listener = self.listener.try_clone()?;
        http::serve(
            listener,
            16,
            8,
            control,
            |stream, _| self.handle(stream, control),
            diagnostic,
        )
    }
    fn handle(&self, stream: &mut TcpStream, control: &Control) -> Result<()> {
        self.handle_with(stream, control, |range| self.open(range, control))
    }
    fn handle_with(
        &self,
        stream: &mut TcpStream,
        control: &Control,
        open: impl FnOnce(ranges::ByteRange) -> Result<crate::protocol::transport::Reply>,
    ) -> Result<()> {
        let request = match http::read_head(stream, Duration::from_secs(15), control) {
            Ok(request) => request,
            Err(error) => {
                let _ = http::reply(stream, 400, &[], b"");
                return Err(error);
            }
        };
        if !http::bearer_matches(
            &request,
            self.token.as_deref().map(String::as_str),
            self.query_token,
        ) {
            return http::reply(
                stream,
                401,
                &[(
                    "WWW-Authenticate",
                    "Bearer realm=\"megabasterd-cli\"".into(),
                )],
                b"",
            );
        }
        if !matches!(request.method.as_str(), "GET" | "HEAD") {
            return http::reply(stream, 405, &[("Allow", "GET, HEAD".into())], b"");
        }
        if request
            .header("content-length")
            .is_some_and(|length| length != "0")
        {
            return http::reply(stream, 400, &[], b"");
        }
        stream.set_write_timeout(Some(Duration::from_secs(60)))?;
        let info = self.source.lock().map_err(poisoned)?.info.clone();
        let mut headers = vec![
            ("Content-Type", media_type(&info.name).to_owned()),
            ("Accept-Ranges", "bytes".into()),
        ];
        headers.push(("Content-Disposition", content_disposition(&info.name)));
        if request.method == "HEAD" {
            headers.push(("Content-Length", info.size.to_string()));
            return http::reply(stream, 200, &headers, b"");
        }
        let range = match ranges::request_range(request.header("range"), info.size) {
            Ok(range) => range,
            Err(ranges::RequestRangeError::Malformed) => {
                return http::reply(stream, 400, &headers, b"");
            }
            Err(ranges::RequestRangeError::Unsatisfiable) => {
                headers.push(("Content-Range", format!("bytes */{}", info.size)));
                return http::reply(stream, 416, &headers, b"");
            }
        };
        let Some(range) = range else {
            return http::reply(stream, 200, &headers, b"");
        };
        let mut upstream = match open(range) {
            Ok(reply) => reply,
            Err(error) => {
                http::reply(stream, 502, &[], b"Upstream stream unavailable")?;
                return Err(error);
            }
        };
        let key = keys::unpack_file_key(&wire::bytes_to_a32(&info.raw_key))?;
        let mut cipher = wire::MegaCtr::at_offset(key.aes_key.as_slice(), &key.nonce, range.start)?;
        let partial = request
            .header("range")
            .is_some_and(|header| !header.is_empty());
        let length = range.length()?;
        headers.push(("Content-Length", length.to_string()));
        if partial {
            headers.push((
                "Content-Range",
                format!("bytes {}-{}/{}", range.start, range.end, info.size),
            ));
        }
        http::reply(stream, if partial { 206 } else { 200 }, &headers, b"")?;
        let deadline = Instant::now() + Duration::from_secs(3600);
        pump(
            &mut upstream.response,
            &mut cipher,
            length,
            control,
            deadline,
            |bytes| http::write_body(stream, bytes, control, deadline, Duration::from_secs(60)),
        )?;
        upstream.credit()?;
        stream.flush()?;
        Ok(())
    }
    fn open(
        &self,
        range: ranges::ByteRange,
        control: &Control,
    ) -> Result<crate::protocol::transport::Reply> {
        self.open_with(
            range,
            control,
            |transport, url, headers| transport.send(Method::GET, url, headers, None, false),
            metadata::refresh,
        )
    }
    fn open_with(
        &self,
        range: ranges::ByteRange,
        control: &Control,
        mut send: impl FnMut(
            &crate::protocol::transport::Transport,
            Url,
            HeaderMap,
        ) -> Result<crate::protocol::transport::Reply>,
        mut refresh: impl FnMut(&mut Api, &FileInfo) -> Result<String>,
    ) -> Result<crate::protocol::transport::Reply> {
        for attempt in 0..2 {
            control.checkpoint()?;
            let (transport, url, generation, size) = {
                let source = self.source.lock().map_err(poisoned)?;
                (
                    source.api.transport.clone(),
                    source.info.url.clone(),
                    source.generation,
                    source.info.size,
                )
            };
            let mut headers = HeaderMap::new();
            headers.insert(
                RANGE,
                HeaderValue::from_str(&range.header())
                    .map_err(|_| Error::invalid("Range header is invalid"))?,
            );
            let reply = send(
                &transport,
                Url::parse(&url).map_err(|_| Error::protocol("CDN URL is invalid"))?,
                headers,
            )?;
            let status = reply.response.status().as_u16();
            if attempt == 0 && matches!(status, 403 | 404 | 410 | 509) {
                drop(reply);
                let mut source = self.source.lock().map_err(poisoned)?;
                if source.generation == generation {
                    let info = source.info.clone();
                    source.info.url = refresh(&mut source.api, &info)?;
                    source.generation = source
                        .generation
                        .checked_add(1)
                        .ok_or_else(|| Error::protocol("CDN generation exhausted"))?;
                }
                continue;
            }
            ranges::validate_response(status, reply.response.headers(), range, size)?;
            if reply
                .response
                .headers()
                .get(reqwest::header::CONTENT_ENCODING)
                .is_some_and(|value| value != "identity")
            {
                return Err(Error::protocol(
                    "CDN stream unexpectedly uses content encoding",
                ));
            }
            return Ok(reply);
        }
        Err(Error::protocol(
            "CDN stream refresh did not produce a usable URL",
        ))
    }
}

fn pump(
    upstream: &mut impl Read,
    cipher: &mut wire::MegaCtr,
    length: u64,
    control: &Control,
    deadline: Instant,
    mut write: impl FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    let mut remaining = length;
    let mut buffer = zeroize::Zeroizing::new(vec![0; 64 * 1024]);
    while remaining != 0 {
        control.checkpoint_until(deadline)?;
        if Instant::now() >= deadline {
            return Err(Error::Timeout);
        }
        let wanted = remaining.min(buffer.len() as u64) as usize;
        let count = match upstream.read(&mut buffer[..wanted]) {
            Ok(count) => count,
            Err(_) if control.is_canceled() => return Err(Error::Canceled),
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(Error::protocol(format!(
                    "Upstream stream ended early: expected {length} bytes, received {}",
                    length - remaining
                )));
            }
            Err(error) => return Err(error.into()),
        };
        if count == 0 {
            return Err(Error::protocol(format!(
                "Upstream stream ended early: expected {length} bytes, received {}",
                length - remaining
            )));
        }
        cipher.apply(&mut buffer[..count])?;
        write(&buffer[..count])?;
        remaining -= count as u64;
    }
    if upstream.read(&mut [0])? != 0 {
        return Err(Error::protocol(
            "Upstream stream exceeded its declared byte count",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "streaming_peer_tests.rs"]
mod peer_tests;

fn media_type(name: &str) -> &'static str {
    match std::path::Path::new(name)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "mp4" | "m4v" => "video/mp4",
        "mkv" => "video/x-matroska",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        "flac" => "audio/flac",
        "ogg" | "opus" => "audio/ogg",
        "wav" => "audio/wav",
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        _ => "application/octet-stream",
    }
}
