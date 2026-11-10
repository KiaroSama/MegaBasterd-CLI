//! Account listing keeps unavailable-key metadata without weakening public-share decoding.
#![allow(clippy::unwrap_used)]

use serde_json::{Value, json};

use super::{
    api::Api,
    auth::Session,
    cloud::Cloud,
    test_peer::{self, Response},
};
use crate::crypto::wire;

#[test]
fn unavailable_sibling_does_not_block_owned_node_lookup_or_cached_root() {
    let master = [1; 16];
    let key = [7; 16];
    let listing = json!({"f":[
        {"h":"ROOT0001","t":2},
        {"h":"OPAQUE01","p":"ROOT0001","t":1,"s":10,"ts":5},
        {"h":"OWNED001","p":"ROOT0001","t":1,
         "k":format!("owner:{}",wire::b64_url_encode(&wire::aes_key_wrap_encrypt(&key,&master).unwrap())),
         "a":wire::b64_url_encode(&wire::encrypt_attributes(&json!({"n":"Owned  folder"}),&key).unwrap())},
    ]});
    let (_, requests) = test_peer::with_peer(
        |request| {
            assert_eq!(request.method, "POST");
            let commands: Value = serde_json::from_slice(&request.body).unwrap();
            assert_eq!(commands, json!([{"a":"f","c":1}]));
            Some(Response {
                status: 200,
                headers: vec![("Content-Type".into(), "application/json".into())],
                body: serde_json::to_vec(&json!([listing])).unwrap(),
            })
        },
        |address| {
            let mut cloud = Cloud::new(
                Api::test_peer(address).unwrap(),
                Session {
                    sid: "synthetic-session".into(),
                    master_key: master,
                    rsa_private_key: None,
                    user_handle: "testuser".into(),
                    email: "fixture@example.invalid".into(),
                },
            );
            assert_eq!(cloud.root().unwrap(), "ROOT0001");
            assert_eq!(cloud.tree().unwrap().children("ROOT0001").len(), 2);
            let opaque = cloud.find("OPAQUE01").unwrap();
            assert!(opaque.name.is_empty());
            assert!(opaque.key().is_err());
            assert!(
                cloud.export("OPAQUE01", None).is_err(),
                "unusable key must refuse before publishing a link"
            );
            assert_eq!((opaque.size, opaque.timestamp), (10, 5));
            let owned = cloud.find("Owned  folder").unwrap();
            assert_eq!(owned.handle, "OWNED001");
            assert_eq!(owned.key().unwrap(), &key);
            assert!(cloud.find("Owned folder").is_err());
            assert_eq!(cloud.tree().unwrap().nodes.len(), 3);
        },
    );
    assert_eq!(
        requests.len(),
        1,
        "the complete retained listing must be cached"
    );
}
