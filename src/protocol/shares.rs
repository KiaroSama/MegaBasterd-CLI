use serde_json::{Value, json};

use super::{
    cloud::{BatchOutcome, Cloud, first_handle},
    nodes::{Node, Tree},
};
use crate::{
    crypto::wire,
    error::{Error, Result},
};
use std::collections::HashMap;

#[cfg(test)]
#[path = "share_listing_tests.rs"]
mod listing_tests;
#[cfg(test)]
#[path = "share_peer_tests.rs"]
mod peer_tests;

pub struct ImportListing {
    pub tree: Tree,
    pub skipped: Vec<String>,
}

pub fn decode_import_listing(listing: &Value, share_key: &[u8]) -> Result<ImportListing> {
    if share_key.len() != 16 {
        return Err(Error::invalid("Share wrapping key must have 16 bytes"));
    }
    let raw = listing
        .get("f")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::protocol("Share listing is not an array"))?;
    if raw.len() > 200_000 {
        return Err(Error::protocol("Share listing exceeds its node bound"));
    }
    let mut nodes = Vec::with_capacity(raw.len());
    let mut skipped = Vec::new();
    for raw in raw {
        // Tolerant account decoding validates field types before classifying key availability.
        let node = super::nodes::decode_account(raw, share_key)?;
        if node.node_type < 2 && node.raw_key.is_none() {
            let width = if node.is_file() { 32 } else { 16 };
            let has_wrapped_key = raw["k"].as_str().unwrap_or("").split('/').any(|candidate| {
                let encoded = candidate.split_once(':').map_or(candidate, |(_, key)| key);
                wire::b64_url_decode(encoded).is_ok_and(|key| key.len() == width)
            });
            if has_wrapped_key {
                // A structurally valid wrapped key with unusable attributes is not a skipped key.
                super::nodes::decode(raw, share_key)?;
            }
            skipped.push(node.handle.clone());
        }
        nodes.push(node);
    }
    // Validate duplicates and cycles even in skipped nodes, before any caller can mutate remotely.
    let tree = Tree::new(nodes)?;
    let nodes = tree
        .nodes
        .into_iter()
        .filter(|node| node.raw_key.is_some())
        .collect();
    Ok(ImportListing {
        tree: Tree::new(nodes)?,
        skipped,
    })
}

pub fn import_request(node: &Node, parent: &str, master_key: &[u8]) -> Result<Value> {
    if parent.is_empty() || !matches!(node.node_type, 0 | 1) {
        return Err(Error::invalid(
            "Share import requires a destination and a file or folder node",
        ));
    }
    let raw_key = node.key()?;
    if raw_key.len() != if node.is_file() { 32 } else { 16 } {
        return Err(Error::integrity(
            "Shared node key width does not match its type",
        ));
    }
    let attribute_key = node.attribute_key()?;
    let attributes = match &node.encrypted_attrs {
        Some(encoded) => {
            let original = wire::b64_url_decode(encoded)?;
            if wire::decrypt_attributes(&original, &attribute_key)? != node.attrs {
                return Err(Error::integrity(
                    "Shared node attributes changed before import",
                ));
            }
            encoded.clone()
        }
        None => wire::b64_url_encode(&wire::encrypt_attributes(&node.attrs, &attribute_key)?),
    };
    let wrapped = wire::aes_key_wrap_encrypt(raw_key, master_key)?;
    Ok(
        json!({"a":"p", "t":parent, "sm":1, "n":[{"h":node.handle, "t":node.node_type,
        "a":attributes, "k":wire::b64_url_encode(&wrapped)}]}),
    )
}

impl Cloud {
    pub fn import_nodes(
        &mut self,
        tree: &Tree,
        root: &str,
        destination: &str,
        share: &str,
    ) -> Result<BatchOutcome> {
        if destination.is_empty() || share.is_empty() {
            return Err(Error::invalid(
                "Share import requires a destination and share handle",
            ));
        }
        let ordered = tree.descendants(root)?;
        let result = (|| {
            let mut outcome = BatchOutcome::default();
            let mut imported: HashMap<String, String> = HashMap::new();
            for node in ordered {
                self.api.control.checkpoint()?;
                let parent = if node.handle == root {
                    destination.to_owned()
                } else if let Some(parent) = imported.get(&node.parent) {
                    parent.clone()
                } else {
                    // The source imports surviving descendants into the explicitly selected target.
                    destination.to_owned()
                };
                let request = import_request(node, &parent, &self.session.master_key)?;
                match self.api.request(request, &[("n", share)]) {
                    Ok(value) => {
                        let handle =
                            first_handle(&value).map_err(|_| Error::AmbiguousMutation("p"))?;
                        imported.insert(node.handle.clone(), handle.clone());
                        outcome.completed.push(handle);
                    }
                    Err(error @ Error::Mega { .. }) => outcome.rejections.push(error),
                    Err(error) => return Err(error),
                }
            }
            self.api.control.checkpoint()?;
            Ok(outcome)
        })();
        self.invalidate();
        result
    }
}
