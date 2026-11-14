//! Proxy-list decoding bounds apply after decompression, before any pool mutation.
#![allow(clippy::unwrap_used)]

use std::io::{self, Cursor, Read, Write};

use reqwest::{
    StatusCode,
    header::{CONTENT_ENCODING, HeaderMap, HeaderValue},
};

use super::read_fetch_response;
use crate::{error::Error, protocol::http_response::HttpResponse};

fn response(encoding: Option<HeaderValue>, body: impl Read + Send + 'static) -> HttpResponse {
    let mut headers = HeaderMap::new();
    if let Some(value) = encoding {
        headers.insert(CONTENT_ENCODING, value);
    }
    HttpResponse::streamed(StatusCode::OK, headers, body)
}

#[test]
fn proxy_reader_decodes_identity_and_gzip_without_changing_utf8_or_complete_lines() {
    let plain = "# source\n1.2.3.4:8080\n# Persian: فارسی\n";
    for encoding in [None, Some("identity"), Some("gzip"), Some("GZIP")] {
        let bytes = if encoding.is_some_and(|value| value.eq_ignore_ascii_case("gzip")) {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            encoder.write_all(plain.as_bytes()).unwrap();
            encoder.finish().unwrap()
        } else {
            plain.as_bytes().to_vec()
        };
        let mut reply = response(
            encoding.map(|value| HeaderValue::from_str(value).unwrap()),
            Cursor::new(bytes),
        );
        let (actual, truncated) = read_fetch_response(&mut reply).unwrap();
        assert_eq!(actual, plain);
        assert!(!truncated);
    }
}

#[test]
fn proxy_gzip_expansion_is_capped_at_decoded_bytes_and_discards_the_partial_last_line() {
    let prefix = b"1.2.3.4:8080\n#";
    // A finite streamed compressor avoids allocating the eight-MiB decoded body.
    let source = Cursor::new(prefix.to_vec()).chain(io::repeat(b'x').take(8 * 1024 * 1024));
    let gzip = flate2::read::GzEncoder::new(source, flate2::Compression::fast());
    let mut reply = response(Some(HeaderValue::from_static("gzip")), gzip);
    let (actual, truncated) = read_fetch_response(&mut reply).unwrap();
    assert!(truncated);
    assert_eq!(actual, "1.2.3.4:8080");
}

#[test]
fn proxy_reader_refuses_unknown_or_invalid_encoding_before_reading_and_rejects_bad_text_or_gzip() {
    struct ForbiddenRead;
    impl Read for ForbiddenRead {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("unsupported encoding reached the body reader")
        }
    }
    for encoding in [
        HeaderValue::from_static("br"),
        HeaderValue::from_bytes(b"\xff").unwrap(),
    ] {
        let mut reply = response(Some(encoding), ForbiddenRead);
        assert!(matches!(
            read_fetch_response(&mut reply),
            Err(Error::Protocol(_))
        ));
    }
    let mut reply = response(None, Cursor::new(vec![0xff, 0xfe]));
    assert!(
        matches!(read_fetch_response(&mut reply), Err(Error::Protocol(message)) if message.contains("UTF-8"))
    );
    let mut reply = response(
        Some(HeaderValue::from_static("gzip")),
        Cursor::new(b"not gzip".to_vec()),
    );
    assert!(matches!(read_fetch_response(&mut reply), Err(Error::Io(_))));
}
