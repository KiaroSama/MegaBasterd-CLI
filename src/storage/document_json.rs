use std::fmt;

use serde::{
    Deserialize, Deserializer,
    de::{Error, IgnoredAny, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Number, Value};

pub(super) fn parse(bytes: &[u8]) -> serde_json::Result<Value> {
    serde_json::from_slice::<DocumentValue>(bytes).map(|value| value.0)
}

/// Diagnostic only: a repeated version must not hide a newer application's document.
pub(super) fn has_future_version(bytes: &[u8]) -> bool {
    struct Versions;

    impl<'de> Visitor<'de> for Versions {
        type Value = bool;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a saved JSON envelope")
        }

        fn visit_map<A: MapAccess<'de>>(self, mut object: A) -> Result<bool, A::Error> {
            let mut future = false;
            while let Some(key) = object.next_key::<String>()? {
                if key == "version" {
                    future |= object
                        .next_value::<Value>()?
                        .as_u64()
                        .is_some_and(|version| version > super::files::STORE_VERSION);
                } else {
                    object.next_value::<IgnoredAny>()?;
                }
            }
            Ok(future)
        }
    }

    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    decoder
        .deserialize_map(Versions)
        .and_then(|future| decoder.end().map(|()| future))
        .unwrap_or(false)
}

struct DocumentValue(Value);

impl<'de> Deserialize<'de> for DocumentValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(DocumentVisitor)
    }
}

struct DocumentVisitor;

impl<'de> Visitor<'de> for DocumentVisitor {
    type Value = DocumentValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON with unique object keys")
    }

    fn visit_unit<E: Error>(self) -> Result<Self::Value, E> {
        Ok(DocumentValue(Value::Null))
    }

    fn visit_bool<E: Error>(self, value: bool) -> Result<Self::Value, E> {
        Ok(DocumentValue(Value::Bool(value)))
    }

    fn visit_i64<E: Error>(self, value: i64) -> Result<Self::Value, E> {
        Ok(DocumentValue(Value::Number(value.into())))
    }

    fn visit_u64<E: Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok(DocumentValue(Value::Number(value.into())))
    }

    fn visit_f64<E: Error>(self, value: f64) -> Result<Self::Value, E> {
        Number::from_f64(value)
            .map(|number| DocumentValue(Value::Number(number)))
            .ok_or_else(|| E::custom("Saved JSON number is not finite"))
    }

    fn visit_str<E: Error>(self, value: &str) -> Result<Self::Value, E> {
        self.visit_string(value.to_owned())
    }

    fn visit_string<E: Error>(self, value: String) -> Result<Self::Value, E> {
        Ok(DocumentValue(Value::String(value)))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<DocumentValue>()? {
            values.push(value.0);
        }
        Ok(DocumentValue(Value::Array(values)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut object: A) -> Result<Self::Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            // Compare decoded keys before consuming a second value, including escaped spellings.
            if values.contains_key(&key) {
                return Err(A::Error::custom("Saved JSON has duplicate object keys"));
            }
            values.insert(key, object.next_value::<DocumentValue>()?.0);
        }
        Ok(DocumentValue(Value::Object(values)))
    }
}
