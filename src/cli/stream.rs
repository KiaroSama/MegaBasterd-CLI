use super::{args::Stream, context::Context};
use crate::error::{Error, Result};
use crate::protocol::{
    link_services::{MegaCrypterResolution, Resolver},
    links::{self, LinkType},
    metadata,
};
use crate::services::streaming::{self, StreamServer};

pub fn dispatch(context: &mut Context, command: Stream) -> Result<()> {
    let mut api = context.api(command.proxy.as_deref())?;
    let parsed = links::resolve_offline(
        &links::parse_link(&command.url)?,
        command.password.as_deref(),
    )?;
    let expanded = if parsed.kind == LinkType::ElcContainer {
        let resolver = Resolver {
            transport: &api.transport,
            password: command.password.as_deref(),
            elc_user: command.elc_user.as_deref(),
            elc_api_key: command.elc_api_key.as_deref(),
            elc_accounts: &context.config.elc_accounts,
        };
        let links = resolver.resolve(&command.url)?;
        if links.len() != 1 {
            return Err(Error::invalid(
                "Stream requires exactly one file after container expansion",
            ));
        }
        links
            .into_iter()
            .next()
            .ok_or_else(|| Error::invalid("Container has no file"))?
    } else {
        parsed
    };
    let info = match expanded.kind {
        LinkType::File => metadata::file(&mut api, &expanded)?,
        LinkType::FileInFolder => {
            let (_, jobs) = metadata::folder(&mut api, &expanded)?;
            if jobs.len() != 1 {
                return Err(Error::invalid("Stream needs one file, not a folder"));
            }
            metadata::folder_file(&mut api, &expanded, &jobs[0])?
        }
        LinkType::Megacrypter => {
            let resolver = Resolver {
                transport: &api.transport,
                password: command.password.as_deref(),
                elc_user: None,
                elc_api_key: None,
                elc_accounts: &context.config.elc_accounts,
            };
            match resolver.megacrypter_source(&expanded)? {
                MegaCrypterResolution::Link(inline) => {
                    let link = links::resolve_offline(
                        &links::parse_link(&inline)?,
                        command.password.as_deref(),
                    )?;
                    metadata::file(&mut api, &link)?
                }
                MegaCrypterResolution::Metadata { info, download_url } => {
                    let url = match download_url {
                        Some(url) => url,
                        None => {
                            return Err(Error::protocol(
                                "MegaCrypter returned no usable download URL",
                            ));
                        }
                    };
                    metadata::FileInfo::megacrypter(expanded, *info, url)?
                }
            }
        }
        _ => {
            return Err(Error::invalid(
                "Stream source must resolve to one public file",
            ));
        }
    };
    let host = command
        .host
        .as_deref()
        .unwrap_or(&context.config.streaming_host);
    let mut token = command.token;
    if !streaming::loopback_host(host) && token.as_ref().is_none_or(|value| value.trim().is_empty())
    {
        token = Some(crate::storage::files::random_id()?);
        let path = context.paths.user.join("Data/stream-token.json");
        crate::storage::files::Store::new(&path)
            .lock()?
            .save(&serde_json::json!({"token":token}))?;
        context.output.message("INFO",&format!("Generated access token saved privately at {}. Use Authorization: Bearer <token>; no token was added to the URL or log.",path.display()))?;
    }
    let server = StreamServer::bind(
        host,
        command.port.unwrap_or(context.config.streaming_port),
        api,
        info,
        token,
        command.allow_query_token,
    )?;
    context.output.message(
        "INFO",
        &format!(
            "Stream running at {} (Ctrl+C to stop)",
            streaming::dialable(server.address()?)
        ),
    )?;
    context.event(
        "STREAM",
        "Local listener started",
        &serde_json::json!({"address":server.address()?.to_string()}),
    );
    server.serve(&context.control, |error| {
        if !matches!(error, Error::Canceled) {
            context.diagnostic(
                "ERROR",
                "STREAM",
                &format!("Peer request failed: {error}"),
                &serde_json::json!({}),
            );
        }
    })?;
    context.event("STREAM", "Local listener stopped", &serde_json::json!({}));
    Ok(())
}
