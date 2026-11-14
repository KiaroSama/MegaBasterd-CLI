#![allow(clippy::unwrap_used)]
use megabasterd_cli::protocol::api::is_mutating;
use serde_json::json;

#[test]
fn only_known_readonly_actions_are_replayable() {
    for action in ["ug", "uq", "g", "f", "us0", "us"] {
        assert!(!is_mutating(&json!({"a": action})));
    }
    for action in ["p", "d", "m", "a", "l", "u", "sml", "future_action"] {
        assert!(is_mutating(&json!({"a": action})));
    }
    for command in [
        json!({"a":"p","t":"parent","n":[{"h":"tok","t":0,"a":"x","k":"y"}]}),
        json!({"a":"p","t":"parent","n":[{"h":"xxxxxxxx","t":1,"a":"x","k":"y"}]}),
        json!({"a":"d","n":"handle"}),
        json!({"a":"m","n":"handle","t":"newparent"}),
        json!({"a":"a","n":"handle","attr":"x","key":"y"}),
        json!({"a":"l","n":"handle"}),
        json!({"a":"p","t":"parent","n":[{"h":"src","t":0,"a":"x","k":"y"}]}),
        json!({"a":"sml"}),
        json!({"a":"u","s":1024}),
    ] {
        assert!(is_mutating(&command));
    }
    for command in [
        json!({"a":"ug"}),
        json!({"a":"uq","strg":1}),
        json!({"a":"g","g":1,"p":"id"}),
        json!({"a":"f","c":1}),
    ] {
        assert!(!is_mutating(&command));
    }
    assert!(is_mutating(&json!([{"a":"ug"},{"a":"d","n":"handle"}])));
    assert!(!is_mutating(&json!([{"a":"ug"},{"a":"uq"}])));
    assert!(is_mutating(&json!({"a":"brand_new_command"})));
    assert!(is_mutating(&json!({"no_action_key":1})));
    assert!(is_mutating(&json!("not even a dict")));
    assert!(is_mutating(&json!([{"a":"g"},{"a":"p"}])));
    assert!(is_mutating(&json!({})));
    assert!(is_mutating(&json!([])));
}
