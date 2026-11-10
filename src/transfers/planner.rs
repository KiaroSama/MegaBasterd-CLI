use std::path::{Path, PathBuf};

pub use super::folder_filter::Filter;

use crate::error::{Error, Result};
use crate::protocol::nodes::{Node, Tree};

pub fn filename(name: &str) -> String {
    let mut cleaned: String = name
        .chars()
        .map(|c| {
            if c <= '\u{1f}' || matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*') {
                '_'
            } else {
                c
            }
        })
        .collect();
    cleaned = cleaned.trim().trim_end_matches([' ', '.']).to_owned();
    if cleaned.is_empty() {
        cleaned = "unnamed".into()
    }
    let base = cleaned.split('.').next().unwrap_or("").to_ascii_uppercase();
    if matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ((base.starts_with("COM") || base.starts_with("LPT"))
            && base.len() == 4
            && matches!(base.as_bytes()[3], b'1'..=b'9'))
    {
        cleaned.insert(0, '_');
    }
    if cleaned.len() > 240 {
        let suffix = Path::new(&cleaned)
            .extension()
            .and_then(|v| v.to_str())
            .map(|s| format!(".{s}"));
        let suffix = suffix.filter(|s| s.len() < 32).unwrap_or_default();
        let limit = 240 - suffix.len();
        let mut end = limit;
        while !cleaned.is_char_boundary(end) {
            end -= 1;
        }
        cleaned.truncate(end);
        cleaned = format!("{}{suffix}", cleaned.trim_end_matches([' ', '.']));
    }
    let cleaned = cleaned.trim_end_matches([' ', '.']);
    if cleaned.is_empty() {
        "unnamed".into()
    } else {
        cleaned.to_owned()
    }
}

#[derive(Clone)]
pub struct Job {
    pub node: Node,
    pub relative: PathBuf,
}

pub fn plan(tree: &Tree, selected: Option<&str>) -> Result<Vec<Job>> {
    let selected_node = selected
        .map(|handle| {
            tree.node(handle)
                .ok_or_else(|| Error::invalid("Selected folder node was not found"))
        })
        .transpose()?;
    let nodes: Vec<&Node> = match selected_node {
        Some(node) if node.is_file() => vec![node],
        Some(node) => tree.descendants(&node.handle)?,
        None => tree.nodes.iter().collect(),
    };
    let stop_parent = selected_node
        .filter(|n| !n.is_file())
        .map(|n| n.parent.as_str());
    let mut jobs = Vec::new();
    for node in nodes.into_iter().filter(|n| n.is_file()) {
        let mut parts = vec![filename(&node.name)];
        let mut parent = node.parent.as_str();
        let mut depth = 0;
        while Some(parent) != stop_parent {
            let Some(ancestor) = tree.node(parent) else {
                break;
            };
            if ancestor.node_type >= 2 {
                break;
            }
            parts.push(filename(&ancestor.name));
            parent = &ancestor.parent;
            depth += 1;
            if depth > tree.nodes.len() {
                return Err(Error::protocol("Folder parent walk contains a cycle"));
            }
        }
        parts.reverse();
        jobs.push(Job {
            node: node.clone(),
            relative: parts.iter().collect(),
        });
    }
    Ok(jobs)
}
