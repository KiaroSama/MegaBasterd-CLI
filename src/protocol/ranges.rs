use reqwest::header::HeaderMap;

use crate::error::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteRange {
    pub start: u64,
    pub end: u64,
}

impl ByteRange {
    pub fn length(self) -> Result<u64> {
        self.end
            .checked_sub(self.start)
            .and_then(|n| n.checked_add(1))
            .ok_or_else(|| Error::invalid("Byte range is invalid or overflows"))
    }
    pub fn header(self) -> String {
        format!("bytes={}-{}", self.start, self.end)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestRangeError {
    Malformed,
    Unsatisfiable,
}

fn number(value: &str) -> std::result::Result<u64, RequestRangeError> {
    let value = value.trim();
    let negative = value.starts_with('-');
    let value = value
        .strip_prefix('+')
        .or_else(|| value.strip_prefix('-'))
        .unwrap_or(value);
    let mut result = 0_u64;
    let mut digit_before = false;
    for character in value.chars() {
        if character == '_' && digit_before {
            digit_before = false;
            continue;
        }
        let digit =
            crate::transfers::selection::decimal(character).ok_or(RequestRangeError::Malformed)?;
        result = result
            .checked_mul(10)
            .and_then(|n| n.checked_add(u64::from(digit)))
            .ok_or(RequestRangeError::Malformed)?;
        digit_before = true;
    }
    if !digit_before {
        return Err(RequestRangeError::Malformed);
    }
    if negative && result != 0 {
        return Err(RequestRangeError::Unsatisfiable);
    }
    Ok(result)
}

pub fn request_range(
    header: Option<&str>,
    size: u64,
) -> std::result::Result<Option<ByteRange>, RequestRangeError> {
    let header = header.filter(|header| !header.is_empty());
    if size == 0 {
        return if header.is_none() {
            Ok(None)
        } else {
            Err(RequestRangeError::Unsatisfiable)
        };
    }
    let Some(header) = header else {
        return Ok(Some(ByteRange {
            start: 0,
            end: size - 1,
        }));
    };
    let value = header
        .strip_prefix("bytes=")
        .ok_or(RequestRangeError::Malformed)?;
    if value.contains(',') {
        return Err(RequestRangeError::Malformed);
    }
    let (start, end) = value.split_once('-').ok_or(RequestRangeError::Malformed)?;
    let (start, end) = if start.is_empty() {
        let suffix = number(end)?;
        if suffix == 0 {
            return Err(RequestRangeError::Unsatisfiable);
        }
        (size.saturating_sub(suffix), size - 1)
    } else {
        let start = number(start)?;
        let end = if end.is_empty() {
            size - 1
        } else {
            number(end)?.min(size - 1)
        };
        (start, end)
    };
    if start > end || start >= size {
        return Err(RequestRangeError::Unsatisfiable);
    }
    Ok(Some(ByteRange { start, end }))
}

pub fn parse_request(header: Option<&str>, size: u64) -> Result<Option<ByteRange>> {
    request_range(header, size).map_err(|error| {
        Error::invalid(match error {
            RequestRangeError::Malformed => {
                "Range syntax is malformed or exceeds its integer bound"
            }
            RequestRangeError::Unsatisfiable => "Range is outside the file",
        })
    })
}

pub fn validate_response(
    status: u16,
    headers: &HeaderMap,
    range: ByteRange,
    size: u64,
) -> Result<()> {
    let length = range.length()?;
    if size == 0 || range.end >= size {
        return Err(Error::invalid("Requested range is outside the file"));
    }
    if status == 200 && range.start == 0 && range.end == size - 1 {
        if let Some(declared) = headers.get(reqwest::header::CONTENT_LENGTH)
            && declared
                .to_str()
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                != Some(length)
        {
            return Err(Error::protocol(
                "Full CDN response Content-Length differs from requested size",
            ));
        }
        return Ok(());
    }
    if status != 206 {
        return Err(Error::protocol(
            "CDN did not honor the exact requested Range",
        ));
    }
    let content = headers
        .get(reqwest::header::CONTENT_RANGE)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| Error::protocol("CDN range reply has no Content-Range"))?;
    let (unit, value) = content
        .split_once(' ')
        .ok_or_else(|| Error::protocol("Content-Range is malformed"))?;
    if !unit.eq_ignore_ascii_case("bytes") {
        return Err(Error::protocol("Content-Range does not describe bytes"));
    }
    let (window, total) = value
        .trim()
        .split_once('/')
        .ok_or_else(|| Error::protocol("Content-Range total is missing"))?;
    let (start, end) = window
        .split_once('-')
        .ok_or_else(|| Error::protocol("Content-Range window is missing"))?;
    let number = |s: &str| {
        s.trim()
            .parse::<u64>()
            .map_err(|_| Error::protocol("Content-Range number is invalid"))
    };
    if number(start)? != range.start || number(end)? != range.end || number(total)? != size {
        return Err(Error::protocol(
            "Content-Range differs from requested offset/length/total",
        ));
    }
    if let Some(header) = headers.get(reqwest::header::CONTENT_LENGTH) {
        let declared = header
            .to_str()
            .map_err(|_| Error::protocol("Content-Length is invalid"))?;
        if number(declared)? != length {
            return Err(Error::protocol(
                "Content-Length differs from requested range",
            ));
        }
    }
    Ok(())
}
