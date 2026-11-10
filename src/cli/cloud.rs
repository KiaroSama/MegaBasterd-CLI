use serde_json::json;

use super::{
    args::{AccountOptions, Trash},
    context::Context,
};
use crate::error::{Error, Result};
use crate::protocol::{
    links::{parse_link, require_link_key, resolve_offline},
    nodes::Node,
    shares::decode_import_listing,
};
use crate::terminal::{progress::format_bytes, prompts};

fn render(context: &Context, nodes: Vec<Node>, empty: &str) -> Result<()> {
    let rows = nodes
        .into_iter()
        .filter(|node| node.node_type < 2)
        .map(|node| {
            vec![
                if node.is_folder() {
                    "Folder".into()
                } else {
                    "File".into()
                },
                if node.name.is_empty() {
                    node.handle.clone()
                } else {
                    node.name
                },
                format_bytes(node.size),
                node.handle,
            ]
        })
        .collect::<Vec<_>>();
    if rows.is_empty() {
        context.output.message("INFO", empty)
    } else {
        context
            .output
            .table(&["Type", "Name", "Size", "Handle"], &rows)
    }
}

pub fn list(context: &mut Context, path: &str, all: bool, auth: &AccountOptions) -> Result<()> {
    let (mut cloud, _) = context.cloud(auth)?;
    let nodes = if all {
        cloud.tree()?.nodes.clone()
    } else {
        let node = cloud.find(path)?;
        if !node.is_folder() {
            vec![node]
        } else {
            cloud
                .tree()?
                .children(&node.handle)
                .into_iter()
                .cloned()
                .collect()
        }
    };
    let empty = if all {
        "Your MEGA account is empty.".to_owned()
    } else if path.is_empty() {
        "Your Cloud Drive is empty.".to_owned()
    } else {
        format!("Folder '{path}' is empty.")
    };
    render(context, nodes, &empty)
}

pub fn search(
    context: &mut Context,
    pattern: &str,
    regex: bool,
    auth: &AccountOptions,
) -> Result<()> {
    let (mut cloud, _) = context.cloud(auth)?;
    let nodes = cloud
        .tree()?
        .search(pattern, regex)?
        .into_iter()
        .cloned()
        .collect();
    render(context, nodes, &format!("Nothing matched '{pattern}'."))
}

pub fn trash(context: &mut Context, command: Trash) -> Result<()> {
    match command {
        Trash::List { auth } => {
            let (mut cloud, _) = context.cloud(&auth)?;
            let root = cloud.tree()?.root(4)?.handle.clone();
            let nodes = cloud.tree()?.children(&root).into_iter().cloned().collect();
            render(context, nodes, "The trash is empty.")
        }
        Trash::Empty { yes, auth } => {
            if !yes && !prompts::confirmed("Permanently delete every item in Trash?", false)? {
                return Ok(());
            }
            let (mut cloud, _) = context.cloud(&auth)?;
            cloud.empty_trash()?.require_complete("Trash cleanup")?;
            context.output.message("INFO", "Trash emptied.")
        }
    }
}

pub fn share(
    context: &mut Context,
    target: &str,
    password: Option<&str>,
    remove: bool,
    auth: &AccountOptions,
) -> Result<()> {
    let (mut cloud, _) = context.cloud(auth)?;
    if remove {
        cloud.unexport(target)?;
        context.output.message("INFO", "Public link removed.")
    } else {
        let link = cloud.export(target, password)?;
        context.output.public_link(&link)
    }
}

pub fn import(
    context: &mut Context,
    url: &str,
    target: Option<&str>,
    auth: &AccountOptions,
) -> Result<()> {
    let parsed = resolve_offline(&parse_link(url)?, None)?;
    if !parsed.is_folder() {
        return Err(Error::invalid("Only folder shares can be imported."));
    }
    let (mut cloud, _) = context.cloud(auth)?;
    let destination = match target {
        Some(target) => {
            let node = cloud.find(target)?;
            if !node.is_folder() {
                return Err(Error::invalid("Import target must be a folder"));
            }
            node.handle
        }
        None => cloud.root()?,
    };
    let key = require_link_key(&parsed)?;
    let listing = cloud.api.request(
        json!({"a":"f","c":1,"r":1,"ca":1}),
        &[("n", &parsed.public_id)],
    )?;
    let decoded = decode_import_listing(&listing, &key)?;
    for handle in decoded.skipped {
        context.output.message(
            "WARNING",
            &format!("Skipped shared node {handle}: its decryption key is unavailable."),
        )?;
    }
    let tree = decoded.tree;
    if let Some(handle) = parsed.subpath.as_deref() {
        if tree.node(handle).is_none() {
            return Err(Error::invalid("Subfolder not found in the public share"));
        }
    } else if tree.nodes.is_empty() {
        return context.output.message("INFO", "Imported 0 node(s).");
    }
    let root = match parsed.subpath.as_deref() {
        Some(handle) => handle.to_owned(),
        None => tree
            .nodes
            .iter()
            .find(|node| tree.node(&node.parent).is_none())
            .ok_or_else(|| Error::protocol("Public folder has no root"))?
            .handle
            .clone(),
    };
    let outcome = cloud.import_nodes(&tree, &root, &destination, &parsed.public_id)?;
    outcome.require_complete("Share import")?;
    context.event(
        "CLOUD",
        "Import completed",
        &json!({"nodes":outcome.completed.len()}),
    );
    context.output.message(
        "INFO",
        &format!("Imported {} node(s).", outcome.completed.len()),
    )
}
