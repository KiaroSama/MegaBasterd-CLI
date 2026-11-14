#![allow(clippy::unwrap_used)]

use megabasterd_cli::{
    error::Error,
    protocol::{
        api::Api,
        containers, links,
        metadata::{self, FileInfo},
        transport::Transport,
    },
    storage::proxies::Routing,
    transfers::control::Control,
};
use serde_json::{Value, json};
use std::time::Duration;

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/link-vectors.json")).unwrap()
}

#[test]
fn direct_megacrypter_metadata_retains_the_source_decryption_key_and_identity() {
    let data = fixture();
    let vector = &data["megacrypter"];
    let info =
        containers::decrypt_megacrypter_info(&vector["body"], vector["password"].as_str()).unwrap();
    let link = links::parse_link("mc://service.example/token").unwrap();
    let file = FileInfo::megacrypter(
        link.clone(),
        info,
        vector["download_url"].as_str().unwrap().into(),
    )
    .unwrap();
    assert_eq!(file.size, 1234);
    assert_eq!(file.name, "folder/نام.mkv");
    assert_eq!(file.raw_key.len(), 32);
    assert_eq!(
        serde_json::from_str::<Value>(&file.source_identity().unwrap()).unwrap(),
        json!(["megacrypter", "service.example", "token"])
    );
    let missing =
        containers::decrypt_megacrypter_info(&json!({"name":"file","size":1}), None).unwrap();
    assert!(
        FileInfo::megacrypter(link.clone(), missing, "https://cdn.example/file".into()).is_err()
    );
    let info =
        containers::decrypt_megacrypter_info(&vector["body"], vector["password"].as_str()).unwrap();
    assert!(FileInfo::megacrypter(link, info, "https://127.0.0.1/file".into()).is_err());
}

#[test]
fn canceled_megacrypter_refresh_stops_before_proxy_io() {
    let data = fixture();
    let vector = &data["megacrypter"];
    let info =
        containers::decrypt_megacrypter_info(&vector["body"], vector["password"].as_str()).unwrap();
    let file = FileInfo::megacrypter(
        links::parse_link("mc://service.example/token").unwrap(),
        info,
        vector["download_url"].as_str().unwrap().into(),
    )
    .unwrap();
    let control = Control::new();
    control.cancel();
    let transport = Transport::new(
        Routing {
            explicit: Some("http://127.0.0.1:9".into()),
            pool: None,
            force: true,
        },
        Duration::from_millis(100),
        "contract".into(),
        control.clone(),
    )
    .unwrap();
    let mut api = Api::new(transport, control).unwrap();
    // Cancellation must be honored before DNS/proxy access for the retained source route.
    assert!(matches!(
        metadata::refresh(&mut api, &file),
        Err(Error::Canceled)
    ));
}
