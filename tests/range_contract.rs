#![allow(clippy::unwrap_used)]
use megabasterd_cli::protocol::ranges::{ByteRange, parse_request, validate_response};
use reqwest::header::{CONTENT_LENGTH, CONTENT_RANGE, HeaderMap, HeaderValue};

#[test]
fn malformed_and_unsatisfiable_stream_ranges_have_distinct_statuses() {
    use megabasterd_cli::protocol::ranges::{RequestRangeError, request_range};
    for header in ["items=0-1", "bytes=bad-3", "bytes=0-1,4-5", "bytes=3"] {
        assert_eq!(
            request_range(Some(header), 10),
            Err(RequestRangeError::Malformed)
        );
    }
    for header in ["bytes=20-30", "bytes=5-3", "bytes=-0"] {
        assert_eq!(
            request_range(Some(header), 10),
            Err(RequestRangeError::Unsatisfiable)
        );
    }
    assert_eq!(
        request_range(Some("bytes=0-0"), 0),
        Err(RequestRangeError::Unsatisfiable)
    );
    assert_eq!(
        request_range(Some("bytes=+۴-۹"), 10).unwrap(),
        Some(ByteRange { start: 4, end: 9 })
    );
    assert_eq!(
        request_range(Some("bytes=3-1_0"), 10).unwrap(),
        Some(ByteRange { start: 3, end: 9 })
    );
}

#[test]
fn exact_source_range_policy_rejects_wrong_windows_totals_lengths_and_missing_partial_headers() {
    let total = 4 * 1024 * 1024;
    let range = ByteRange {
        start: 1024,
        end: 2047,
    };
    for (status, content_range, length, accepted) in [
        (200, None, Some(total.to_string()), false),
        (
            206,
            Some(format!("bytes 2048-3071/{total}")),
            Some("1024".into()),
            false,
        ),
        (206, None, Some("1024".into()), false),
        (206, Some("bytes 1024-2047/*".into()), None, false),
        (
            206,
            Some(format!("bytes 1024-2047/{total}")),
            Some("99".into()),
            false,
        ),
        (
            206,
            Some(format!("bytes 1024-2047/{total}")),
            Some("1024".into()),
            true,
        ),
    ] {
        let mut headers = HeaderMap::new();
        if let Some(value) = content_range {
            headers.insert(CONTENT_RANGE, HeaderValue::from_str(&value).unwrap());
        }
        if let Some(value) = length {
            headers.insert(CONTENT_LENGTH, HeaderValue::from_str(&value).unwrap());
        }
        assert_eq!(
            validate_response(status, &headers, range, total).is_ok(),
            accepted
        );
    }
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_LENGTH,
        HeaderValue::from_str(&total.to_string()).unwrap(),
    );
    assert!(
        validate_response(
            200,
            &headers,
            ByteRange {
                start: 0,
                end: total - 1
            },
            total
        )
        .is_ok()
    );
}

#[test]
fn full_file_success_cannot_claim_an_incorrect_declared_size() {
    let range = ByteRange { start: 0, end: 9 };
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_LENGTH, HeaderValue::from_static("9"));
    assert!(validate_response(200, &headers, range, 10).is_err());
    headers.insert(CONTENT_LENGTH, HeaderValue::from_static("10"));
    assert!(validate_response(200, &headers, range, 10).is_ok());
}

#[test]
fn range_requests_and_upstream_offset_contract_are_exact() {
    assert_eq!(
        parse_request(Some("bytes=-3"), 10).unwrap(),
        Some(ByteRange { start: 7, end: 9 })
    );
    assert_eq!(
        parse_request(Some("bytes=4-"), 10).unwrap(),
        Some(ByteRange { start: 4, end: 9 })
    );
    assert!(parse_request(Some("bytes=20-30"), 10).is_err());
    assert!(parse_request(Some("bytes=0-1,4-5"), 10).is_err());
    assert!(parse_request(Some("bytes=0-0"), 0).is_err());
    let range = ByteRange { start: 3, end: 5 };
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_RANGE, HeaderValue::from_static("bytes 3-5/10"));
    headers.insert(CONTENT_LENGTH, HeaderValue::from_static("3"));
    assert!(validate_response(206, &headers, range, 10).is_ok());
    assert!(validate_response(200, &headers, range, 10).is_err());
    headers.insert(CONTENT_RANGE, HeaderValue::from_static("bytes 0-2/10"));
    assert!(validate_response(206, &headers, range, 10).is_err());
    headers.insert(CONTENT_RANGE, HeaderValue::from_static("bytes 3-5/*"));
    assert!(validate_response(206, &headers, range, 10).is_err());
}
