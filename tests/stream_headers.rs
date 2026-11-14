#![allow(clippy::unwrap_used)]

use megabasterd_cli::services::streaming::content_disposition;

#[test]
fn streaming_filename_preserves_double_spaces_and_encodes_unicode_without_header_injection() {
    assert_eq!(
        content_disposition("OAD -  09v2.mkv"),
        "inline; filename=\"OAD -  09v2.mkv\"; filename*=UTF-8''OAD%20-%20%2009v2.mkv"
    );
    assert_eq!(
        content_disposition("a+*~.txt"),
        "inline; filename=\"a+*~.txt\"; filename*=UTF-8''a%2B%2A~.txt"
    );
    assert_eq!(
        content_disposition("é.txt"),
        "inline; filename=\".txt\"; filename*=UTF-8''%C3%A9.txt"
    );
    assert_eq!(
        content_disposition("evil\"\r\n\\.txt"),
        "inline; filename=\"evil\\\"___.txt\"; filename*=UTF-8''evil%22___.txt"
    );
    let exact_source = content_disposition("bad\"name\r\n.mkv");
    assert!(!exact_source.contains(['\r', '\n']));
    assert!(exact_source.contains("filename=\"bad\\\"name__.mkv\""));
    assert!(exact_source.contains("filename*="));
    let header = content_disposition("é");
    assert!(header.contains("filename=\"download\""));
    assert!(!header.contains(['\r', '\n']));
}
