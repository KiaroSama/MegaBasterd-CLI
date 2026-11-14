use std::collections::{BTreeMap, VecDeque};

use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue};
use serde_json::{Value, json};
use url::Url;

use super::{
    api::string,
    containers::{self, MegaCrypterInfo},
    links::{self, LinkType, ParsedLink},
    transport::Transport,
};
use crate::error::{Error, Result};

#[cfg(test)]
#[path = "dlc_origin_tests.rs"]
mod dlc_origin_tests;
#[cfg(test)]
#[path = "link_service_peer_tests.rs"]
mod peer_tests;
#[cfg(test)]
#[path = "link_service_target_tests.rs"]
mod target_tests;

pub enum MegaCrypterResolution {
    Link(String),
    Metadata {
        info: Box<MegaCrypterInfo>,
        download_url: Option<String>,
    },
}

/// Online link operations require a caller-supplied transport and its routing policy.
/// Constructing a resolver cannot silently substitute a permissive direct route.
///
/// This function is type-checked but never called, so the example opens no sockets:
///
/// ```
/// use std::collections::BTreeMap;
/// use megabasterd_cli::{
///     error::Result,
///     protocol::{containers::MegaCrypterInfo, link_services::Resolver, links::ParsedLink,
///                transport::Transport},
/// };
///
/// fn online_operations(
///     transport: &Transport,
///     accounts: &BTreeMap<String, BTreeMap<String, String>>,
///     link: &ParsedLink,
///     info: &MegaCrypterInfo,
/// ) -> Result<()> {
///     let resolver = Resolver {
///         transport,
///         password: None,
///         elc_user: None,
///         elc_api_key: None,
///         elc_accounts: accounts,
///     };
///     resolver.elc(link)?;
///     resolver.dlc("container")?;
///     resolver.megacrypter_info(link)?;
///     resolver.megacrypter_download(link, info, None)?;
///     resolver.megacrypter_resolve(link)?;
///     Ok(())
/// }
/// ```
///
/// Omitting only the transport from the same construction must not compile:
///
/// ```compile_fail
/// use std::collections::BTreeMap;
/// use megabasterd_cli::{
///     error::Result,
///     protocol::{containers::MegaCrypterInfo, link_services::Resolver, links::ParsedLink,
///                transport::Transport},
/// };
///
/// fn online_operations(
///     transport: &Transport,
///     accounts: &BTreeMap<String, BTreeMap<String, String>>,
///     link: &ParsedLink,
///     info: &MegaCrypterInfo,
/// ) -> Result<()> {
///     let resolver = Resolver {
///         password: None,
///         elc_user: None,
///         elc_api_key: None,
///         elc_accounts: accounts,
///     };
///     resolver.elc(link)?;
///     resolver.dlc("container")?;
///     resolver.megacrypter_info(link)?;
///     resolver.megacrypter_download(link, info, None)?;
///     resolver.megacrypter_resolve(link)?;
///     Ok(())
/// }
/// ```
pub struct Resolver<'a> {
    pub transport: &'a Transport,
    pub password: Option<&'a str>,
    pub elc_user: Option<&'a str>,
    pub elc_api_key: Option<&'a str>,
    pub elc_accounts: &'a BTreeMap<String, BTreeMap<String, String>>,
}

pub(super) fn validate_dlc_endpoint(url: &Url) -> Result<()> {
    super::transport::safe_target(url)?;
    if !url.host_str().is_some_and(|host| {
        host.trim_end_matches('.')
            .eq_ignore_ascii_case("service.jdownloader.org")
    }) || url.port_or_known_default() != Some(443)
    {
        return Err(Error::invalid(
            "DLC request has an unapproved service endpoint",
        ));
    }
    Ok(())
}

fn mc_link(link: &ParsedLink) -> Result<String> {
    if link.kind != LinkType::Megacrypter {
        return Err(Error::invalid("Expected a MegaCrypter link"));
    }
    Ok(format!(
        "mc://{}/{}",
        link.crypter_server
            .as_deref()
            .ok_or_else(|| Error::invalid("MegaCrypter server is absent"))?,
        link.crypter_token
            .as_deref()
            .ok_or_else(|| Error::invalid("MegaCrypter token is absent"))?
    ))
}

pub fn megacrypter_download_request(
    link: &ParsedLink,
    noexpire: Option<&str>,
    sid: Option<&str>,
) -> Result<Value> {
    // Password-derived material stays local; this boundary accepts no decryption key.
    let mut request = json!({"m":"dl","link":mc_link(link)?});
    if let Some(noexpire) = noexpire.filter(|value| !value.is_empty()) {
        request["noexpire"] = json!(noexpire);
    }
    if let Some(sid) = sid.filter(|value| !value.is_empty()) {
        request["sid"] = json!(sid);
    }
    Ok(request)
}

enum ServiceResponse {
    Body(Value),
    Status(u16),
}

impl ServiceResponse {
    fn into_body(self) -> Result<Value> {
        match self {
            Self::Body(body) => Ok(body),
            Self::Status(_) => Err(Error::protocol(
                "Link service returned an unsuccessful HTTP status",
            )),
        }
    }
}

fn response_json(
    transport: &Transport,
    url: Url,
    body: Vec<u8>,
    content_type: &'static str,
) -> Result<ServiceResponse> {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    let mut reply = transport.post_link_service(url, headers, body, false)?;
    if !reply.response.status().is_success() {
        return Ok(ServiceResponse::Status(reply.response.status().as_u16()));
    }
    let bytes = reply.bytes(2_000_000)?;
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|_| Error::protocol("Link service returned invalid JSON"))?;
    if !value.is_object() {
        reply.malformed()?;
        return Err(Error::protocol("Link service response is not an object"));
    }
    reply.credit()?;
    Ok(ServiceResponse::Body(value))
}

impl Resolver<'_> {
    pub fn resolve(&self, input: &str) -> Result<Vec<ParsedLink>> {
        let mut pending = VecDeque::from([(input.to_owned(), 0usize)]);
        let mut result = Vec::new();
        while let Some((input, depth)) = pending.pop_front() {
            if depth >= 8 || result.len() + pending.len() > 200_000 {
                return Err(Error::invalid(
                    "Container nesting or link count exceeds its limit",
                ));
            }
            let parsed = links::resolve_offline(&links::parse_link(&input)?, self.password)?;
            let expanded = match parsed.kind {
                LinkType::ElcContainer => Some(self.elc(&parsed)?),
                LinkType::Megacrypter => Some(vec![self.megacrypter_resolve(&parsed)?]),
                _ => None,
            };
            if let Some(links) = expanded {
                pending.extend(links.into_iter().map(|link| (link, depth + 1)));
            } else {
                result.push(parsed);
            }
        }
        Ok(result)
    }

    pub fn elc(&self, link: &ParsedLink) -> Result<Vec<String>> {
        self.elc_with(link, |url, body, content_type| {
            response_json(self.transport, url, body, content_type)
        })
    }

    fn elc_with(
        &self,
        link: &ParsedLink,
        post: impl FnOnce(Url, Vec<u8>, &'static str) -> Result<ServiceResponse>,
    ) -> Result<Vec<String>> {
        let payload = containers::decode_elc_payload(link)?;
        let url = Url::parse(&payload.service_url)
            .map_err(|_| Error::invalid("ELC service URL is invalid"))?;
        super::transport::safe_target(&url)?;
        let host = url
            .host_str()
            .ok_or_else(|| Error::invalid("ELC service has no host"))?;
        let configured = self.elc_accounts.get(host);
        let user = self
            .elc_user
            .or_else(|| configured.and_then(|account| account.get("user").map(String::as_str)))
            .filter(|s| !s.is_empty())
            .ok_or_else(|| Error::Auth("ELC service requires its configured user".into()))?;
        let key = self
            .elc_api_key
            .or_else(|| {
                configured.and_then(|account| {
                    account
                        .get("api_key")
                        .or_else(|| account.get("apikey"))
                        .map(String::as_str)
                })
            })
            .filter(|s| !s.is_empty())
            .ok_or_else(|| Error::Auth("ELC service requires its configured API key".into()))?;
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("OPERATION_TYPE", "D")
            .append_pair("DATA", &payload.data_token)
            .append_pair("USER", user)
            .append_pair("APIKEY", key)
            .finish();
        let value =
            post(url, body.into_bytes(), "application/x-www-form-urlencoded")?.into_body()?;
        containers::decrypt_elc_links(&payload, string(&value, "d")?)
    }

    pub fn dlc(&self, input: &str) -> Result<Vec<String>> {
        self.dlc_with(input, None, |url, headers, body| {
            self.transport.post_link_service(url, headers, body, true)
        })
    }

    fn dlc_with(
        &self,
        input: &str,
        endpoint: Option<Url>,
        post: impl FnOnce(Url, HeaderMap, Vec<u8>) -> Result<super::transport::Reply>,
    ) -> Result<Vec<String>> {
        let url = match endpoint {
            Some(url) => url,
            None => Url::parse(containers::DLC_SERVICE_URL)
                .map_err(|_| Error::protocol("Built-in DLC service URL is invalid"))?,
        };
        validate_dlc_endpoint(&url)?;
        self.dlc_request_with(input, url, post)
    }

    #[cfg(test)]
    fn dlc_at(&self, input: &str, url: Url) -> Result<Vec<String>> {
        self.dlc_with(input, Some(url), |url, headers, body| {
            self.transport.post_link_service(url, headers, body, true)
        })
    }

    #[cfg(test)]
    fn dlc_request(&self, input: &str, url: Url) -> Result<Vec<String>> {
        self.dlc_request_with(input, url, |url, headers, body| {
            self.transport.post_link_service(url, headers, body, true)
        })
    }

    fn dlc_request_with(
        &self,
        input: &str,
        url: Url,
        post: impl FnOnce(Url, HeaderMap, Vec<u8>) -> Result<super::transport::Reply>,
    ) -> Result<Vec<String>> {
        let request = containers::parse_dlc_request(input)?;
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("destType", "jdtc6")
            .append_pair("b", "JD")
            .append_pair("srcType", "dlc")
            .append_pair("data", &request.id)
            .append_pair("v", containers::DLC_REV)
            .finish();
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        headers.insert("rev", HeaderValue::from_static(containers::DLC_REV));
        let mut reply = post(url, headers, body.into_bytes())?;
        if !reply.response.status().is_success() {
            return Err(Error::protocol(
                "DLC service returned an unsuccessful HTTP status",
            ));
        }
        let bytes = reply.bytes(2_000_000)?;
        let text =
            std::str::from_utf8(&bytes).map_err(|_| Error::protocol("DLC reply is not UTF-8"))?;
        reply.credit()?;
        containers::decrypt_dlc_response(&request, text)
    }

    pub fn megacrypter_post(&self, link: &ParsedLink, body: Value) -> Result<Value> {
        self.megacrypter_response(link, body)?.into_body()
    }

    fn megacrypter_response(&self, link: &ParsedLink, body: Value) -> Result<ServiceResponse> {
        let server = link
            .crypter_server
            .as_deref()
            .ok_or_else(|| Error::invalid("MegaCrypter link has no server"))?;
        let url = Url::parse(&format!("https://{server}/api"))
            .map_err(|_| Error::invalid("MegaCrypter server is invalid"))?;
        response_json(
            self.transport,
            url,
            serde_json::to_vec(&body)?,
            "application/json",
        )
    }

    pub fn megacrypter_resolve(&self, link: &ParsedLink) -> Result<String> {
        match self.megacrypter_source(link)? {
            MegaCrypterResolution::Link(url) => Ok(url),
            MegaCrypterResolution::Metadata { .. } => Err(Error::protocol(
                "MegaCrypter service did not expose an underlying MEGA link",
            )),
        }
    }

    pub fn megacrypter_source(&self, link: &ParsedLink) -> Result<MegaCrypterResolution> {
        let mut metadata: Option<MegaCrypterInfo> = None;
        for method in ["info", "openlink", "dl"] {
            let request = if method == "dl" {
                megacrypter_download_request(
                    link,
                    metadata
                        .as_ref()
                        .and_then(|info| info.noexpire_token.as_deref()),
                    None,
                )?
            } else {
                json!({"m":method,"link":mc_link(link)?})
            };
            // Policy, transport and cancellation failures are terminal, not another route to try.
            let response = self.megacrypter_response(link, request)?;
            if method == "openlink" && matches!(&response, ServiceResponse::Status(404 | 405 | 501))
            {
                continue;
            }
            let body = response.into_body()?;
            if containers::megacrypter_rejected(&body) {
                continue;
            }
            if let Some(url) = containers::inline_megacrypter_link(&body)
                .and_then(|url| links::normalize_link(&url).ok())
            {
                return Ok(MegaCrypterResolution::Link(url));
            }
            // A dl response's pass is a URL IV, not an info password descriptor.
            if method == "dl"
                && body.get("url").is_some()
                && !["file_id", "id", "file_key", "key"]
                    .iter()
                    .any(|field| body.get(*field).is_some())
            {
                if let Some(info) = metadata.take() {
                    let url = checked_megacrypter_download(&body, &info)?;
                    return Ok(MegaCrypterResolution::Metadata {
                        info: Box::new(info),
                        download_url: Some(url),
                    });
                }
                continue;
            }
            let info = containers::decrypt_megacrypter_info(&body, self.password)?;
            if let Some(url) = info.underlying_link() {
                return Ok(MegaCrypterResolution::Link(url));
            }
            if method == "info" {
                metadata = Some(info);
            }
        }
        metadata
            .map(|info| MegaCrypterResolution::Metadata {
                info: Box::new(info),
                download_url: None,
            })
            .ok_or_else(|| {
                Error::protocol("MegaCrypter service did not expose an underlying MEGA link")
            })
    }

    pub fn megacrypter_info(&self, link: &ParsedLink) -> Result<MegaCrypterInfo> {
        let body = self.megacrypter_post(link, json!({"m":"info","link":mc_link(link)?}))?;
        containers::decrypt_megacrypter_info(&body, self.password)
    }

    pub fn megacrypter_download(
        &self,
        link: &ParsedLink,
        info: &MegaCrypterInfo,
        sid: Option<&str>,
    ) -> Result<String> {
        let request = megacrypter_download_request(link, info.noexpire_token.as_deref(), sid)?;
        let body = self.megacrypter_post(link, request)?;
        checked_megacrypter_download(&body, info)
    }
}

fn checked_megacrypter_download(body: &Value, info: &MegaCrypterInfo) -> Result<String> {
    let url = containers::decrypt_megacrypter_download_url(body, info)?;
    let endpoint =
        Url::parse(&url).map_err(|_| Error::invalid("MegaCrypter download URL is invalid"))?;
    super::transport::safe_target(&endpoint)?;
    Ok(url)
}
