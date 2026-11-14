use std::collections::HashSet;
use std::io::Read;
use std::path::Path;
use std::time::Duration;

use reqwest::{Method, header::HeaderMap};
use url::Url;

use super::{args::Proxy, context::Context};
use crate::error::{Error, Result};
use crate::services::{connect, local_crypto::open_source};
use crate::storage::proxies::{ProxyStore, import_proxy, validate_proxy};
use crate::terminal::{prompts, redaction};

#[cfg(test)]
#[path = "proxy_response_tests.rs"]
mod response_tests;

fn config_urls(context: &Context) -> Vec<String> {
    context
        .config
        .smart_proxy_url
        .as_deref()
        .unwrap_or("")
        .split(|character: char| character.is_whitespace() || matches!(character, ',' | ';'))
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

fn read_list(path: &Path) -> Result<Vec<String>> {
    let (_directory, file) = open_source(path)?;
    let mut bytes = Vec::new();
    file.take(4 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 4 * 1024 * 1024 {
        return Err(Error::invalid("Proxy input exceeds 4 MiB"));
    }
    let text =
        std::str::from_utf8(&bytes).map_err(|_| Error::invalid("Proxy input is not UTF-8"))?;
    let urls: Vec<_> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(import_proxy)
        .collect::<Result<_>>()?;
    if urls.len() > 10_000 {
        return Err(Error::invalid("Proxy input exceeds 10000 entries"));
    }
    for url in &urls {
        validate_proxy(url)?;
    }
    Ok(urls)
}

pub fn dispatch(context: &mut Context, command: Proxy) -> Result<()> {
    context.require_config()?;
    let store = ProxyStore::new(context.paths.proxies());
    match command {
        Proxy::List {
            config_urls: _,
            no_config_urls,
        } => {
            let persisted = store.list()?;
            let mut urls = persisted.clone();
            if !no_config_urls {
                urls.extend(config_urls(context));
            }
            let mut seen = HashSet::new();
            urls.retain(|url| seen.insert(url.clone()));
            let rows = urls
                .iter()
                .map(|url| {
                    vec![
                        redaction::text(url),
                        "0".into(),
                        "0".into(),
                        "OK".into(),
                        if persisted.contains(url) {
                            "persisted"
                        } else {
                            "config"
                        }
                        .into(),
                    ]
                })
                .collect::<Vec<_>>();
            if rows.is_empty() {
                context.output.message("INFO", "Proxy pool is empty.")
            } else {
                context
                    .output
                    .table(&["URL", "Successes", "Failures", "Status", "Source"], &rows)
            }
        }
        Proxy::Add { urls } => {
            let count = urls.len();
            store.update(|saved| saved.extend(urls))?;
            context
                .output
                .message("SUCCESS", &format!("Added {count} proxy/proxies."))
        }
        Proxy::Remove { url } => {
            let mut removed = false;
            store.update(|saved| {
                let previous = saved.len();
                saved.retain(|value| value != &url);
                removed = saved.len() != previous;
            })?;
            context.output.message(
                "INFO",
                if removed {
                    "Proxy removed."
                } else {
                    "Proxy not found."
                },
            )
        }
        Proxy::Clear => {
            if !prompts::confirmed("Clear every saved proxy?", false)? {
                return Ok(());
            }
            store.update(Vec::clear)?;
            context.output.message("SUCCESS", "Proxy pool cleared.")
        }
        Proxy::Import { path } => {
            let urls = read_list(&path)?;
            let count = urls.len();
            store.update(|saved| saved.extend(urls))?;
            context
                .output
                .message("SUCCESS", &format!("Imported {count} proxy/proxies."))
        }
        Proxy::Fetch {
            protocol,
            source,
            limit,
            timeout,
        } => fetch(
            context,
            &store,
            &protocol,
            source.as_deref(),
            limit,
            timeout,
        ),
        Proxy::Test => {
            let mut urls = store.list()?;
            urls.extend(config_urls(context));
            let mut seen = HashSet::new();
            urls.retain(|url| seen.insert(url.clone()));
            if urls.len() > 10_000 {
                return Err(Error::invalid("Proxy pool exceeds 10,000 entries"));
            }
            super::proxy_probe::run(context, urls)
        }
        Proxy::Serve {
            port,
            password,
            any_port,
        } => {
            let password = zeroize::Zeroizing::new(password.or_else(|| context.config.connect_proxy_password.clone())
                .ok_or_else(|| Error::Auth("No proxy password set; use --password or config set connect_proxy_password".into()))?);
            let port = port.unwrap_or(context.config.connect_proxy_port);
            context.output.message(
                "INFO",
                &format!("MEGA CONNECT proxy starting at 127.0.0.1:{port}; Ctrl+C to stop."),
            )?;
            connect::serve(
                port,
                &password,
                any_port || context.config.connect_proxy_allow_any_port,
                &context.control,
                |error| {
                    context.event(
                        "PROXY",
                        "Local proxy request failed",
                        &serde_json::json!({"error":error.to_string()}),
                    )
                },
            )
        }
    }
}

fn read_fetch_response(
    response: &mut crate::protocol::http_response::HttpResponse,
) -> Result<(String, bool)> {
    const MAX_FETCH_BYTES: u64 = 4 * 1024 * 1024;

    let encoding = response
        .headers()
        .get(reqwest::header::CONTENT_ENCODING)
        .map(|value| value.to_str())
        .transpose()
        .map_err(|_| Error::protocol("Proxy source content encoding is invalid"))?
        .unwrap_or("")
        .to_ascii_lowercase();
    let reader: Box<dyn Read + '_> = match encoding.as_str() {
        "" | "identity" => Box::new(response),
        "gzip" => Box::new(flate2::read::GzDecoder::new(response)),
        _ => {
            return Err(Error::protocol(
                "Proxy source uses an unsupported content encoding",
            ));
        }
    };
    let mut bytes = Vec::new();
    reader.take(MAX_FETCH_BYTES).read_to_end(&mut bytes)?;
    let truncated = bytes.len() as u64 == MAX_FETCH_BYTES;
    if truncated {
        bytes.truncate(bytes.iter().rposition(|byte| *byte == b'\n').unwrap_or(0));
    }
    let text =
        String::from_utf8(bytes).map_err(|_| Error::protocol("Proxy source is not UTF-8"))?;
    Ok((text, truncated))
}

fn fetch(
    context: &mut Context,
    store: &ProxyStore,
    protocol: &str,
    source: Option<&str>,
    limit: u32,
    timeout: u64,
) -> Result<()> {
    let defaults = [
        format!(
            "https://api.proxyscrape.com/v2/?request=getproxies&protocol={protocol}&timeout=10000"
        ),
        format!("https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/{protocol}.txt"),
    ];
    let sources: Vec<_> = match source {
        Some(source) => vec![source.to_owned()],
        None => defaults.into(),
    };
    fetch_sources(context, store, protocol, &sources, limit, timeout)
}

pub(super) fn fetch_sources(
    context: &mut Context,
    store: &ProxyStore,
    protocol: &str,
    sources: &[String],
    limit: u32,
    timeout: u64,
) -> Result<()> {
    if limit == 0 || limit > 10_000 || timeout == 0 || timeout > 300 {
        return Err(Error::invalid(
            "Proxy fetch limit must be 1..10000 and timeout 1..300 seconds",
        ));
    }
    if !matches!(protocol, "http" | "socks4" | "socks5") {
        return Err(Error::invalid("Unsupported fetched proxy protocol"));
    }
    let api = context.api(None)?;
    let mut transport = api.transport.clone();
    transport.timeout = Duration::from_secs(timeout);
    let mut collected = Vec::new();
    for source in sources {
        context.control.checkpoint()?;
        let result = (|| {
            let url =
                Url::parse(source).map_err(|_| Error::invalid("Proxy list URL is invalid"))?;
            let mut reply = transport.send(Method::GET, url, HeaderMap::new(), None, false)?;
            if !reply.response.status().is_success() {
                return Err(Error::protocol(
                    "Proxy source returned unsuccessful HTTP status",
                ));
            }
            let (text, truncated) = read_fetch_response(&mut reply.response)?;
            context.control.checkpoint()?;
            if truncated {
                context
                    .output
                    .message("WARNING", "Proxy list truncated at 4194304 bytes.")?;
            }
            for line in text
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
            {
                if collected.len() >= limit as usize {
                    break;
                }
                let url = if line.contains("://") {
                    line.to_owned()
                } else {
                    format!("{protocol}://{line}")
                };
                if validate_proxy(&url).is_ok() && !collected.contains(&url) {
                    collected.push(url);
                }
            }
            reply.credit()?;
            Ok(())
        })();
        if let Err(error) = result {
            if context.control.is_canceled() || matches!(&error, Error::Canceled) {
                return Err(Error::Canceled);
            }
            let host = Url::parse(source)
                .ok()
                .and_then(|url| url.host_str().map(str::to_owned))
                .unwrap_or_else(|| "unknown host".into());
            let detail = match &error {
                Error::Protocol(message)
                    if message == "Proxy source returned unsuccessful HTTP status" =>
                {
                    "unsuccessful HTTP status"
                }
                _ => "check source availability, encoding and configured routing",
            };
            context.output.message(
                "WARNING",
                &format!("Proxy source {host} failed ({}): {detail}", error.code()),
            )?;
        }
        if collected.len() >= limit as usize {
            break;
        }
    }
    context.control.checkpoint()?;
    if collected.is_empty() {
        return Err(Error::protocol(
            "No proxies fetched; existing pool was preserved",
        ));
    }
    let count = collected.len();
    store.try_update(|saved| {
        context.control.checkpoint()?;
        saved.extend(collected);
        Ok(())
    })?;
    context.output.message(
        "SUCCESS",
        &format!("Fetched {count} {protocol} proxy/proxies."),
    )
}
