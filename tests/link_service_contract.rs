#![allow(clippy::unwrap_used)]

use megabasterd_cli::protocol::{
    link_services::megacrypter_download_request, links::parse_link, metadata::download_ticket,
};
use serde_json::json;

#[test]
fn megacrypter_request_contains_only_server_required_fields() {
    let link = parse_link("mc://service.example/token").unwrap();
    let request =
        megacrypter_download_request(&link, Some("expiry-sentinel"), Some("session-sentinel"))
            .unwrap();
    assert_eq!(
        request,
        json!({
            "m": "dl", "link": "mc://service.example/token",
            "noexpire": "expiry-sentinel", "sid": "session-sentinel"
        })
    );
    assert!(request.get("pass").is_none());
    assert!(request.get("password").is_none());
    assert!(request.get("key").is_none());
    assert_eq!(
        megacrypter_download_request(&link, None, None).unwrap(),
        json!({"m":"dl", "link":"mc://service.example/token"})
    );
    let public =
        parse_link("https://mega.nz/file/abcdefgh#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            .unwrap();
    assert!(megacrypter_download_request(&public, None, None).is_err());
}

#[test]
fn initial_and_refreshed_download_tickets_request_https() {
    assert_eq!(
        download_ticket("abcdefgh", false),
        json!({"a":"g", "g":1, "ssl":2, "p":"abcdefgh"})
    );
    assert_eq!(
        download_ticket("abcdefgh", true),
        json!({"a":"g", "g":1, "ssl":2, "n":"abcdefgh"})
    );
}
