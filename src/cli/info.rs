use serde_json::{Value, json};

use super::{args::Info, context::Context};
use crate::error::{Error, Result};
use crate::protocol::{
    api::{Api, field, string},
    link_services::{MegaCrypterResolution, Resolver},
    links::{self, LinkType, ParsedLink},
    metadata,
    nodes::Tree,
};
use crate::transfers::planner;

pub fn folder_document(link: &ParsedLink, tree: &Tree) -> Result<Value> {
    let selected = link
        .subpath
        .as_deref()
        .map(|handle| {
            tree.node(handle)
                .ok_or_else(|| Error::invalid("Selected shared node was not found"))
        })
        .transpose()?;
    if let Some(node) = selected.filter(|node| node.is_file()) {
        return Ok(json!({"type":"File (in folder share)","name":node.name,
            "folder_id":link.public_id,"file_handle":node.handle,"size":node.size}));
    }
    let nodes = match selected {
        Some(node) => tree.descendants(&node.handle)?,
        None => tree.nodes.iter().collect(),
    };
    let jobs = planner::plan(tree, link.subpath.as_deref())?;
    let mut total = 0u64;
    let files = jobs.into_iter().map(|job| {
        total = total.checked_add(job.node.size).ok_or_else(|| Error::protocol("Folder total size overflows"))?;
        Ok(json!({"path":job.relative.to_string_lossy().replace('\\',"/"),"size":job.node.size,"handle":job.node.handle}))
    }).collect::<Result<Vec<_>>>()?;
    let mut document = json!({"type":if selected.is_some() { "Folder (inside folder share)" } else { "Folder share" },
        "public_id":link.public_id,"node_count":nodes.len(),"file_count":files.len(),"total_size":total,"files":files});
    if let Some(node) = selected {
        document["subfolder_handle"] = json!(node.handle);
    }
    Ok(document)
}

pub fn inspect(api: &mut Api, link: &ParsedLink) -> Result<Value> {
    if link.kind == LinkType::File {
        let value = api.request(metadata::download_ticket(&link.public_id, false), &[])?;
        let size = field(&value, "s")?
            .as_u64()
            .ok_or_else(|| Error::protocol("File size is not an integer"))?;
        crate::crypto::chunks::chunk_count(size)?;
        let mut document = json!({"type":"File","public_id":link.public_id,"size":size});
        if link.key.is_some() {
            let raw = links::require_link_key(link)?;
            let key =
                crate::crypto::keys::unpack_file_key(&crate::crypto::wire::bytes_to_a32(&raw))?;
            let attrs = crate::crypto::wire::decrypt_attributes(
                &crate::crypto::wire::b64_url_decode(string(&value, "at")?)?,
                key.aes_key.as_slice(),
            )?;
            document["name"] = json!(string(&attrs, "n")?);
        }
        if let Some(attributes) = value.get("fa") {
            document["file_attributes"] = attributes.clone();
        }
        return Ok(document);
    }
    if matches!(
        link.kind,
        LinkType::Folder | LinkType::FolderInFolder | LinkType::FileInFolder
    ) {
        let (tree, _) = metadata::folder(api, link)?;
        return folder_document(link, &tree);
    }
    Err(Error::invalid(
        "Link has not been resolved to a public MEGA share",
    ))
}

pub fn dispatch(context: &mut Context, command: Info) -> Result<()> {
    let mut api = context.api(None)?;
    let parsed = links::resolve_offline(
        &links::parse_link(&command.url)?,
        command.password.as_deref(),
    )?;
    let document = if parsed.kind == LinkType::Megacrypter {
        let resolver = Resolver {
            transport: &api.transport,
            password: command.password.as_deref(),
            elc_user: command.elc_user.as_deref(),
            elc_api_key: command.elc_api_key.as_deref(),
            elc_accounts: &context.config.elc_accounts,
        };
        match resolver.megacrypter_source(&parsed)? {
            MegaCrypterResolution::Link(inline) => inspect(
                &mut api,
                &links::resolve_offline(&links::parse_link(&inline)?, command.password.as_deref())?,
            )?,
            MegaCrypterResolution::Metadata { info, .. } => {
                let info = *info;
                let mut document = json!({"type":"MegaCrypter file","file_key":if info.key.is_some() {"available"} else {"missing"}});
                if let Some(name) = info.name {
                    document["name"] = json!(name);
                }
                if let Some(size) = info.size {
                    document["size"] = json!(size);
                }
                if info.noexpire_token.is_some() {
                    document["no_expire_token"] = json!("available");
                }
                document
            }
        }
    } else if parsed.kind == LinkType::ElcContainer {
        let resolver = Resolver {
            transport: &api.transport,
            password: command.password.as_deref(),
            elc_user: command.elc_user.as_deref(),
            elc_api_key: command.elc_api_key.as_deref(),
            elc_accounts: &context.config.elc_accounts,
        };
        let expanded = resolver.resolve(&command.url)?;
        let items = expanded
            .iter()
            .map(|link| inspect(&mut api, link))
            .collect::<Result<Vec<_>>>()?;
        json!({"type":"container","links":items})
    } else {
        inspect(&mut api, &parsed)?
    };
    context.event(
        "LINK",
        "Public metadata inspected",
        &json!({"kind":document.get("type")}),
    );
    if command.json {
        return context.output.record(&document);
    }
    render(context, &document)
}

fn render(context: &Context, document: &Value) -> Result<()> {
    let mut rows = Vec::new();
    if let Some(object) = document.as_object() {
        for (key, value) in object {
            if key == "files" || key == "links" {
                continue;
            }
            rows.push(vec![
                key.clone(),
                match value {
                    Value::String(text) => text.clone(),
                    _ => value.to_string(),
                },
            ]);
        }
    }
    context.output.table(&["Field", "Value"], &rows)?;
    if let Some(files) = document.get("files").and_then(Value::as_array) {
        let rows = files
            .iter()
            .map(|file| {
                vec![
                    file.get("path")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_owned(),
                    file.get("size")
                        .and_then(Value::as_u64)
                        .map(crate::terminal::progress::format_bytes)
                        .unwrap_or_default(),
                    file.get("handle")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_owned(),
                ]
            })
            .collect::<Vec<_>>();
        context.output.table(&["Path", "Size", "Handle"], &rows)?;
    }
    if let Some(items) = document.get("links").and_then(Value::as_array) {
        for item in items {
            render(context, item)?;
        }
    }
    Ok(())
}
