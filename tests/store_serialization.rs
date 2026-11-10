//! Saved JSON retains valid values and refuses ambiguous or malformed input without data loss.
#![allow(clippy::unwrap_used)]

use std::{cell::Cell, collections::BTreeMap, fs, path::Path, time::Duration};

use megabasterd_cli::{error::Error, storage::files::Store};
use serde::{
    Serialize, Serializer,
    ser::{Error as _, SerializeStruct},
};
use serde_json::{Value, json};

#[test]
fn saved_json_preserves_unique_values_and_rejects_duplicates_or_incomplete_documents() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/store-serialization");
    fs::create_dir_all(&base).unwrap();
    let scratch = private_tempfile::tempdir_in(&base).unwrap();
    let path = scratch.path().join("private/document.json");
    let store = Store::new(&path);
    let locked = store.lock().unwrap();
    let values = json!({
        "integers": [i64::MIN, 0, u64::MAX],
        "floats": [-1.25, 2.5e3],
        "scalars": [true, false, null, "雪", "\"key\":1,\"key\":2"],
        "siblings": [{"key":1}, {"key":2}],
        "empty": [{}, [], ""],
        "distinct": {"Key":1, "key":2, "é":3, "e\u{301}":4}
    });
    locked.save(&values).unwrap();
    assert_eq!(locked.load::<Value>().unwrap().unwrap(), values);
    let escaped = r#"{"version":2,"data":{"雪":"雪","array":[{"key":1},{"key":2}]}}"#.as_bytes();
    locked.write_bytes(escaped).unwrap();
    assert_eq!(
        locked.load::<Value>().unwrap().unwrap(),
        json!({"雪":"雪","array":[{"key":1},{"key":2}]})
    );
    assert_eq!(fs::read(&path).unwrap(), escaped);
    let mut invalid = vec![
        br#"{"version":2,"data":{"key":1,"key":2}}"#.to_vec(),
        br#"{"version":2,"data":[{"key":1,"key":2}]}"#.to_vec(),
        r#"{"version":2,"data":{"雪":1,"雪":2}}"#.as_bytes().to_vec(),
        br#"{"version":2,"data":null} {}"#.to_vec(),
        br#"{"version":2,"data":{"unfinished":true}"#.to_vec(),
        br#"{"version":2,"data":1e999}"#.to_vec(),
    ];
    invalid.push(
        format!(
            "{{\"version\":2,\"data\":{}0{}}}",
            "[".repeat(128),
            "]".repeat(128)
        )
        .into_bytes(),
    );
    for bytes in invalid {
        locked.write_bytes(&bytes).unwrap();
        let error = locked.load::<Value>().unwrap_err();
        assert!(matches!(error, Error::Corrupt(_)));
        assert_eq!(error.code(), "storage_corrupt");
        assert_eq!(error.exit_code(), 1);
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }
    locked.save(&values).unwrap();
    assert_eq!(locked.load::<Value>().unwrap().unwrap(), values);
    let mut names = fs::read_dir(path.parent().unwrap())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(
        names,
        ["document.json", "document.json.lock"].map(std::ffi::OsString::from)
    );
}

struct Refused<'a>(&'a Cell<bool>);

impl Serialize for Refused<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.set(true);
        let mut fields = serializer.serialize_struct("Refused", 2)?;
        fields.serialize_field("max_workers", &9)?;
        Err(S::Error::custom("controlled encoding refusal"))
    }
}

#[test]
fn failed_serialization_preserves_existing_or_absent_documents_without_staging_or_panic() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/store-serialization");
    fs::create_dir_all(&base).unwrap();
    for existing in [false, true] {
        let scratch = private_tempfile::tempdir_in(&base).unwrap();
        let path = scratch.path().join("private/config.json");
        let store = Store::new(&path);
        let locked = store.lock().unwrap();
        if existing {
            locked.save(&json!({"max_workers":7})).unwrap();
            assert_eq!(
                fs::read(&path).unwrap(),
                br#"{"version":2,"data":{"max_workers":7}}"#
            );
        }
        let original = fs::read(&path).ok();
        let entered = Cell::new(false);
        assert!(matches!(
            locked.save(&Refused(&entered)),
            Err(Error::Json(error)) if error.to_string().contains("controlled encoding refusal")
        ));
        assert!(entered.get(), "Fixture must reach the real serializer");
        let unsupported_key = BTreeMap::from([([1u8, 2u8], 3u8)]);
        assert!(matches!(locked.save(&unsupported_key), Err(Error::Json(_))));
        assert_eq!(fs::read(&path).ok(), original);
        let mut names: Vec<_> = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        names.sort();
        let mut expected = vec![std::ffi::OsString::from("config.json.lock")];
        if existing {
            expected.insert(0, std::ffi::OsString::from("config.json"));
        }
        assert_eq!(names, expected);
        assert!(matches!(
            Store::new(&path).with_timeout(Duration::ZERO).lock(),
            Err(Error::Busy(_))
        ));
        locked.save(&json!({"max_workers":9})).unwrap();
        assert_eq!(
            fs::read(&path).unwrap(),
            br#"{"version":2,"data":{"max_workers":9}}"#
        );
        drop(locked);
        let reloaded = store.lock().unwrap().load::<Value>().unwrap().unwrap();
        assert_eq!(reloaded, json!({"max_workers":9}));
        assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 2);
    }
}

#[path = "common/private_tempfile.rs"]
mod private_tempfile;
