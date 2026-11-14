use std::collections::{HashMap, HashSet};

use serde_json::Value;
use zeroize::Zeroizing;

use super::api::{field, string};
use crate::crypto::{keys, wire};
use crate::error::{Error, Result};

#[derive(Clone)]
pub struct Node {
    pub handle: String,
    pub parent: String,
    pub node_type: u8,
    pub size: u64,
    pub timestamp: u64,
    pub name: String,
    pub raw_key: Option<Zeroizing<Vec<u8>>>,
    pub attrs: Value,
    pub encrypted_attrs: Option<String>,
}

impl Node {
    pub fn is_file(&self) -> bool {
        self.node_type == 0
    }
    pub fn is_folder(&self) -> bool {
        matches!(self.node_type, 1..=4)
    }
    pub fn key(&self) -> Result<&[u8]> {
        self.raw_key
            .as_ref()
            .map(|key| key.as_slice())
            .ok_or_else(|| Error::protocol("Cannot access node content: missing node key"))
    }
    pub fn attribute_key(&self) -> Result<Zeroizing<Vec<u8>>> {
        if self.is_file() {
            Ok(Zeroizing::new(
                keys::unpack_file_key(&wire::bytes_to_a32(self.key()?))?
                    .aes_key
                    .to_vec(),
            ))
        } else {
            Ok(Zeroizing::new(self.key()?.to_vec()))
        }
    }
}

pub fn decode(raw: &Value, wrapping_key: &[u8]) -> Result<Node> {
    decode_node(raw, wrapping_key, false)
}

/// Account listings retain unavailable-key metadata; content and public shares remain strict.
pub fn decode_account(raw: &Value, wrapping_key: &[u8]) -> Result<Node> {
    decode_node(raw, wrapping_key, true)
}

fn optional_string<'a>(raw: &'a Value, name: &str) -> Result<&'a str> {
    match raw.get(name) {
        Some(value) => value
            .as_str()
            .ok_or_else(|| Error::protocol(format!("Node {name} is not text"))),
        None => Ok(""),
    }
}

fn optional_number(raw: &Value, name: &str) -> Result<u64> {
    match raw.get(name) {
        Some(value) => value
            .as_u64()
            .ok_or_else(|| Error::protocol(format!("Node {name} is not an unsigned integer"))),
        None => Ok(0),
    }
}

fn decode_node(raw: &Value, wrapping_key: &[u8], allow_unavailable: bool) -> Result<Node> {
    if wrapping_key.len() != 16 {
        return Err(Error::invalid("Node wrapping key must have 16 bytes"));
    }
    let kind = field(raw, "t")?
        .as_u64()
        .filter(|v| *v <= 4)
        .ok_or_else(|| Error::protocol("Node type is invalid"))? as u8;
    let handle = string(raw, "h")?.to_owned();
    if handle.is_empty() || handle.len() > 64 {
        return Err(Error::protocol("Node handle is invalid"));
    }
    let parent = optional_string(raw, "p")?.to_owned();
    optional_string(raw, "u")?;
    let encoded = optional_string(raw, "k")?;
    let original_attributes = optional_string(raw, "a")?;
    if encoded.len() > wire::MAX_ATTRIBUTE_BYTES * 2
        || original_attributes.len() > wire::MAX_ATTRIBUTE_BYTES * 2
    {
        return Err(Error::protocol(
            "Node key or attributes exceed their size bound",
        ));
    }
    let attributes = wire::b64_url_decode(original_attributes)?;
    let size = optional_number(raw, "s")?;
    let timestamp = optional_number(raw, "ts")?;
    if kind >= 2 {
        return Ok(Node {
            handle,
            parent,
            node_type: kind,
            size,
            timestamp,
            name: String::new(),
            raw_key: None,
            attrs: Value::Object(Default::default()),
            encrypted_attrs: None,
        });
    }
    let expected = if kind == 0 { 32 } else { 16 };
    for candidate in encoded.split('/') {
        let candidate = candidate
            .split_once(':')
            .map_or(candidate, |(_, value)| value);
        let decoded = match wire::b64_url_decode(candidate) {
            Ok(decoded) => decoded,
            Err(_) => continue,
        };
        if decoded.len() != expected {
            continue;
        }
        let key = Zeroizing::new(wire::aes_key_wrap_decrypt(&decoded, wrapping_key)?);
        let attribute_key = if kind == 0 {
            keys::unpack_file_key(&wire::bytes_to_a32(&key))?
                .aes_key
                .to_vec()
        } else {
            key.to_vec()
        };
        let attribute_key = Zeroizing::new(attribute_key);
        if let Ok(attrs) = wire::decrypt_attributes(&attributes, &attribute_key) {
            let Some(name) = attrs
                .get("n")
                .and_then(Value::as_str)
                .filter(|n| !n.is_empty())
            else {
                if allow_unavailable {
                    continue;
                }
                return Err(Error::protocol("Node has no valid filename"));
            };
            let name = name.to_owned();
            return Ok(Node {
                handle,
                parent,
                node_type: kind,
                size,
                timestamp,
                name,
                raw_key: Some(key),
                attrs,
                encrypted_attrs: Some(string(raw, "a")?.to_owned()),
            });
        }
    }
    if allow_unavailable {
        return Ok(Node {
            handle,
            parent,
            node_type: kind,
            size,
            timestamp,
            name: String::new(),
            raw_key: None,
            attrs: Value::Object(Default::default()),
            encrypted_attrs: (!original_attributes.is_empty())
                .then(|| original_attributes.to_owned()),
        });
    }
    Err(Error::integrity(
        "Node key or encrypted attributes are unusable",
    ))
}

pub struct Tree {
    pub nodes: Vec<Node>,
    by_handle: HashMap<String, usize>,
    children: HashMap<String, Vec<usize>>,
}

impl Tree {
    pub fn new(nodes: Vec<Node>) -> Result<Self> {
        if nodes.len() > 200_000 {
            return Err(Error::protocol("Node listing exceeds its node bound"));
        }
        let mut by_handle = HashMap::new();
        let mut children: HashMap<String, Vec<usize>> = HashMap::new();
        for (index, node) in nodes.iter().enumerate() {
            if by_handle.insert(node.handle.clone(), index).is_some() {
                return Err(Error::protocol("Node listing has duplicate handles"));
            }
            children.entry(node.parent.clone()).or_default().push(index);
        }
        let tree = Self {
            nodes,
            by_handle,
            children,
        };
        // Mark completed walks once so large deep trees are linear, not quadratic.
        let mut completed = HashSet::new();
        for node in &tree.nodes {
            let mut path = HashSet::new();
            let mut current = Some(node);
            while let Some(node) = current {
                if completed.contains(&node.handle) {
                    break;
                }
                if !path.insert(node.handle.clone()) {
                    return Err(Error::protocol("Node graph contains a parent cycle"));
                }
                current = tree.node(&node.parent);
            }
            completed.extend(path);
        }
        Ok(tree)
    }

    pub fn decode(listing: &Value, key: &[u8]) -> Result<Self> {
        let raw = field(listing, "f")?
            .as_array()
            .ok_or_else(|| Error::protocol("Node listing is not an array"))?;
        if raw.len() > 200_000 {
            return Err(Error::protocol("Node listing exceeds its node bound"));
        }
        Self::new(
            raw.iter()
                .map(|node| decode(node, key))
                .collect::<Result<_>>()?,
        )
    }
    pub fn decode_account(listing: &Value, key: &[u8]) -> Result<Self> {
        let listing = listing
            .as_object()
            .ok_or_else(|| Error::protocol("Account listing is not an object"))?;
        let Some(raw) = listing.get("f") else {
            return Self::new(Vec::new());
        };
        let raw = raw
            .as_array()
            .ok_or_else(|| Error::protocol("Node listing is not an array"))?;
        if raw.len() > 200_000 {
            return Err(Error::protocol("Node listing exceeds its node bound"));
        }
        Self::new(
            raw.iter()
                .map(|node| decode_account(node, key))
                .collect::<Result<_>>()?,
        )
    }

    pub fn node(&self, handle: &str) -> Option<&Node> {
        self.by_handle.get(handle).map(|index| &self.nodes[*index])
    }
    pub fn root(&self, kind: u8) -> Result<&Node> {
        self.nodes
            .iter()
            .find(|n| n.node_type == kind)
            .ok_or_else(|| Error::protocol("Cloud root is missing"))
    }
    pub fn children(&self, parent: &str) -> Vec<&Node> {
        self.children
            .get(parent)
            .into_iter()
            .flatten()
            .map(|index| &self.nodes[*index])
            .collect()
    }
    pub fn find(&self, target: &str) -> Result<&Node> {
        if let Some(node) = self.node(target) {
            return Ok(node);
        }
        let mut node = self.root(2)?;
        let normalized = target.replace('\\', "/");
        for part in normalized.split('/').filter(|part| !part.is_empty()) {
            node = self
                .children(&node.handle)
                .into_iter()
                .find(|child| child.name == part)
                .ok_or_else(|| Error::invalid("Node not found at the selected cloud path"))?;
        }
        Ok(node)
    }
    pub fn search(&self, pattern: &str, regex: bool) -> Result<Vec<&Node>> {
        let expression = if regex {
            Some(
                regex::RegexBuilder::new(pattern)
                    .case_insensitive(true)
                    .build()
                    .map_err(|_| Error::invalid("Search regular expression is invalid"))?,
            )
        } else {
            None
        };
        let needle = pattern.to_lowercase();
        Ok(self
            .nodes
            .iter()
            .filter(|node| {
                !node.name.is_empty()
                    && match &expression {
                        Some(expression) => expression.is_match(&node.name),
                        None => node.name.to_lowercase().contains(&needle),
                    }
            })
            .collect())
    }

    pub fn descendants(&self, handle: &str) -> Result<Vec<&Node>> {
        let root = self
            .node(handle)
            .ok_or_else(|| Error::invalid("Shared node was not found"))?;
        let mut result = Vec::new();
        let mut pending = std::collections::VecDeque::from([root]);
        while let Some(node) = pending.pop_front() {
            result.push(node);
            pending.extend(self.children(&node.handle));
        }
        Ok(result)
    }
}
