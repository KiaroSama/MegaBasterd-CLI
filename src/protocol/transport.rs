use std::io::Read;
use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::Client;
use reqwest::{
    Method,
    header::{ACCEPT_ENCODING, HeaderMap},
    redirect::Policy,
};
use url::{Host, Url};

use super::dns::{SafeResolver, is_public};
use super::http_response::HttpResponse;
use super::http_wait::interruptible;
use super::proxy_transport;
use crate::error::{Error, Result};
use crate::storage::proxies::{Routing, validate_proxy};
use crate::transfers::control::Control;

#[path = "transport_hops.rs"]
mod hops;

#[derive(Clone)]
pub struct Transport {
    pub routing: Routing,
    pub timeout: Duration,
    pub user_agent: String,
    control: Control,
    #[cfg(test)]
    test_peer: Option<std::net::SocketAddr>,
    #[cfg(test)]
    body_pending: Option<(String, std::sync::mpsc::SyncSender<()>)>,
}

pub struct Reply {
    pub response: HttpResponse,
    picked: Option<String>,
    routing: Routing,
}

pub(crate) struct AttemptFailure {
    pub error: Error,
    pub sent: bool,
}

impl AttemptFailure {
    fn before(error: Error) -> Self {
        Self { error, sent: false }
    }
    pub(crate) fn after(error: Error) -> Self {
        Self { error, sent: true }
    }
}

#[derive(Clone, Copy)]
enum Redirects {
    Reads { credentialed: bool },
    Service { same_origin: bool },
    None,
}

pub fn safe_target(url: &Url) -> Result<()> {
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        return Err(Error::invalid(
            "Remote endpoint must use HTTPS without embedded credentials",
        ));
    }
    match url.host() {
        Some(Host::Ipv4(ip)) if !is_public(ip.into()) => {
            Err(Error::invalid("Remote endpoint has a nonpublic address"))
        }
        Some(Host::Ipv6(ip)) if !is_public(ip.into()) => {
            Err(Error::invalid("Remote endpoint has a nonpublic address"))
        }
        Some(Host::Domain(host))
            if host.trim_end_matches('.').eq_ignore_ascii_case("localhost")
                || host.trim_end_matches('.').ends_with(".localhost") =>
        {
            Err(Error::invalid("Remote endpoint is local"))
        }
        None => Err(Error::invalid("Remote endpoint has no host")),
        _ => Ok(()),
    }
}

fn proxy_backend(url: &Url, proxy: Option<&str>) -> Result<bool> {
    let Some(proxy) = proxy else { return Ok(false) };
    let proxy = validate_proxy(proxy)?;
    if matches!(proxy.scheme(), "http" | "https" | "socks5h") {
        return Ok(true);
    }
    if matches!(url.host(), Some(Host::Domain(_))) && url.host() == proxy.host() {
        return Err(Error::protocol(
            "Service target cannot share the trusted local-DNS proxy hostname",
        ));
    }
    Ok(false)
}

fn redirect_target(
    url: &Url,
    initial: &Url,
    method: &Method,
    policy: Redirects,
    status: u16,
    location: Option<&str>,
    hop: usize,
) -> Result<Option<Url>> {
    if !matches!(status, 301 | 302 | 303 | 307 | 308) {
        return Ok(None);
    }
    let same_origin = match policy {
        Redirects::None => {
            return Err(Error::protocol(
                "State-changing HTTP redirect was refused; request was not replayed",
            ));
        }
        Redirects::Reads { credentialed } => {
            if method != Method::GET && method != Method::HEAD {
                return Err(Error::protocol(
                    "State-changing HTTP redirect was refused; request was not replayed",
                ));
            }
            credentialed
        }
        Redirects::Service { same_origin } => same_origin,
    };
    if hop == 5 {
        return Err(Error::protocol("Remote endpoint exceeded five redirects"));
    }
    let location = location
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| Error::protocol("Redirect has no valid Location"))?;
    let next = url
        .join(location.trim())
        .map_err(|_| Error::protocol("Redirect Location is invalid"))?;
    safe_target(&next)?;
    let equivalent_dlc = matches!(policy, Redirects::Service { same_origin: true })
        && super::link_services::validate_dlc_endpoint(initial).is_ok()
        && super::link_services::validate_dlc_endpoint(&next).is_ok();
    if same_origin && next.origin() != initial.origin() && !equivalent_dlc {
        return Err(Error::protocol(
            "Credentialed cross-origin redirect was refused",
        ));
    }
    Ok(Some(next))
}

impl Transport {
    pub fn new(
        routing: Routing,
        timeout: Duration,
        user_agent: String,
        control: Control,
    ) -> Result<Self> {
        if timeout.is_zero() {
            return Err(Error::invalid("HTTP timeout must be positive"));
        }
        Ok(Self {
            routing,
            timeout,
            user_agent,
            control,
            #[cfg(test)]
            test_peer: None,
            #[cfg(test)]
            body_pending: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn test_peer(address: std::net::SocketAddr, control: Control) -> Result<Self> {
        if !address.ip().is_loopback() || address.port() == 0 {
            return Err(Error::invalid(
                "Test peer must be a bound loopback listener",
            ));
        }
        let mut transport = Self::new(
            Routing {
                explicit: None,
                pool: None,
                force: false,
            },
            Duration::from_secs(5),
            "native-test".into(),
            control,
        )?;
        transport.test_peer = Some(address);
        Ok(transport)
    }

    #[cfg(test)]
    pub(crate) fn observe_body_pending(
        &mut self,
        path: &str,
        sender: std::sync::mpsc::SyncSender<()>,
    ) {
        assert!(
            self.test_peer.is_some() && path.starts_with('/'),
            "body observation requires an isolated peer and exact path"
        );
        self.body_pending = Some((path.to_owned(), sender));
    }

    #[cfg(test)]
    pub(crate) fn test_upload_url(&self, mut url: Url) -> Result<Url> {
        let Some(address) = self.test_peer else {
            return Ok(url);
        };
        // Called only after the real slot/state MEGA-host policy; no test exception enters a release.
        if url.host_str() != Some("upload.mega.nz")
            || url.port_or_known_default() != Some(443)
            || !url.path().starts_with("/native-peer-upload/")
        {
            return Err(Error::invalid(
                "Upload fixture escaped its selected peer slot",
            ));
        }
        safe_target(&url)?;
        url.set_host(Some("testserver.com"))
            .map_err(|_| Error::invalid("Upload fixture host is invalid"))?;
        url.set_port(Some(address.port()))
            .map_err(|_| Error::invalid("Upload fixture port is invalid"))?;
        Ok(url)
    }

    fn client(&self, proxy: Option<&str>) -> Result<Client> {
        #[cfg(test)]
        if let Some(address) = self.test_peer {
            if proxy.is_some() {
                return Err(Error::invalid("Test peer cannot use a configured proxy"));
            }
            return Ok(Client::builder()
                .no_proxy()
                .redirect(Policy::none())
                .retry(reqwest::retry::never())
                .timeout(self.timeout)
                .connect_timeout(self.timeout)
                .user_agent(&self.user_agent)
                .resolve("testserver.com", address)
                .tls_certs_only([reqwest::Certificate::from_der(include_bytes!(
                    "../../tests/fixtures/proxy_tls/root.der"
                ))?])
                .build()?);
        }
        let trusted_proxy_host = proxy
            .map(validate_proxy)
            .transpose()?
            .and_then(|url| url.host_str().map(str::to_owned));
        let mut builder = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .retry(reqwest::retry::never())
            .timeout(self.timeout)
            .connect_timeout(self.timeout.min(Duration::from_secs(20)))
            .user_agent(&self.user_agent)
            .dns_resolver(Arc::new(SafeResolver::new(
                self.timeout,
                trusted_proxy_host,
            )));
        if let Some(proxy) = proxy {
            builder = builder.proxy(
                reqwest::Proxy::all(proxy)
                    .map_err(|_| Error::invalid("Proxy URL is unsupported"))?,
            );
        }
        Ok(builder.build()?)
    }

    fn send_direct(
        &self,
        method: &Method,
        url: &Url,
        headers: &HeaderMap,
        body: Option<&[u8]>,
        proxy: Option<&str>,
    ) -> std::result::Result<HttpResponse, AttemptFailure> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| AttemptFailure::before(error.into()))?;
        let client = {
            let _entered = runtime.enter();
            self.client(proxy).map_err(AttemptFailure::before)?
        };
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .ok_or_else(|| AttemptFailure::before(Error::Timeout))?;
        let mut request = client
            .request(method.clone(), url.clone())
            .headers(headers.clone())
            .header(ACCEPT_ENCODING, "identity");
        if let Some(body) = body {
            request = request.body(body.to_vec());
        }
        let response = runtime.block_on(interruptible(
            async { request.send().await.map_err(Error::from) },
            deadline,
            &self.control,
        )).map_err(|error| {
            let sent = !matches!(&error, Error::Http(error) if error.is_builder() || error.is_connect());
            AttemptFailure { error, sent }
        })?;
        Ok(HttpResponse::reqwest(
            response,
            client,
            runtime,
            self.control.clone(),
            deadline,
            #[cfg(test)]
            self.body_pending
                .as_ref()
                .filter(|(path, _)| path == url.path())
                .map(|(_, sender)| sender.clone()),
        ))
    }

    /// One attempt only. API action classification owns retries, never this transport.
    pub fn send(
        &self,
        method: Method,
        url: Url,
        headers: HeaderMap,
        body: Option<Vec<u8>>,
        credentialed: bool,
    ) -> Result<Reply> {
        self.send_inner(
            method,
            url,
            headers,
            body,
            Redirects::Reads { credentialed },
        )
        .map_err(|failure| failure.error)
    }

    /// Link resolution retains POST/body through redirects like the source implementation.
    /// DLC pins the initial origin; arbitrary ELC/MegaCrypter origins never inherit MEGA trust.
    pub fn post_link_service(
        &self,
        url: Url,
        headers: HeaderMap,
        body: Vec<u8>,
        same_origin: bool,
    ) -> Result<Reply> {
        self.send_inner(
            Method::POST,
            url,
            headers,
            Some(body),
            Redirects::Service { same_origin },
        )
        .map_err(|failure| failure.error)
    }

    pub(crate) fn send_api(
        &self,
        url: Url,
        headers: HeaderMap,
        body: &[u8],
    ) -> std::result::Result<Reply, AttemptFailure> {
        self.send_inner(
            Method::POST,
            url,
            headers,
            Some(body.to_vec()),
            Redirects::None,
        )
    }

    fn send_inner(
        &self,
        method: Method,
        url: Url,
        headers: HeaderMap,
        body: Option<Vec<u8>>,
        policy: Redirects,
    ) -> std::result::Result<Reply, AttemptFailure> {
        self.send_hops(method, url, policy, |method, url, proxy, pinned| {
            if pinned {
                let proxy = proxy.ok_or_else(|| {
                    AttemptFailure::before(Error::protocol(
                        "Pinned routing requires a configured proxy",
                    ))
                })?;
                proxy_transport::send(
                    method,
                    url,
                    &headers,
                    body.as_deref(),
                    proxy,
                    self.timeout,
                    &self.user_agent,
                    &self.control,
                    #[cfg(test)]
                    self.test_peer,
                )
            } else {
                self.send_direct(method, url, &headers, body.as_deref(), proxy)
            }
        })
    }
}

struct BodyReadFailure<'a> {
    response: &'a mut HttpResponse,
    failed: &'a mut bool,
}

impl Read for BodyReadFailure<'_> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let result = self.response.read(output);
        if result
            .as_ref()
            .is_err_and(|error| error.kind() != std::io::ErrorKind::Interrupted)
        {
            *self.failed = true;
        }
        result
    }
}

impl Reply {
    #[cfg(test)]
    pub(super) fn test_response(response: HttpResponse) -> Self {
        Self {
            response,
            picked: None,
            routing: Routing {
                explicit: None,
                pool: None,
                force: false,
            },
        }
    }

    pub fn credit(&self) -> Result<()> {
        self.routing.report(self.picked.as_deref(), true)
    }
    pub fn malformed(&self) -> Result<()> {
        self.routing.report(self.picked.as_deref(), false)
    }

    pub fn bytes(&mut self, limit: u64) -> Result<Vec<u8>> {
        if self
            .response
            .content_length()
            .is_some_and(|length| length > limit)
        {
            return Err(Error::protocol("Remote response exceeds its size limit"));
        }
        let encoding = self
            .response
            .headers()
            .get(reqwest::header::CONTENT_ENCODING)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();
        let mut read_failed = false;
        let reader: Box<dyn Read + '_> = match encoding.as_str() {
            "" | "identity" => Box::new(&mut self.response),
            "gzip" => Box::new(flate2::read::GzDecoder::new(BodyReadFailure {
                response: &mut self.response,
                failed: &mut read_failed,
            })),
            _ => {
                return Err(Error::protocol(
                    "Remote response uses an unsupported content encoding",
                ));
            }
        };
        let mut output = Vec::new();
        let result = reader
            .take(
                limit
                    .checked_add(1)
                    .ok_or_else(|| Error::invalid("Response limit overflows"))?,
            )
            .read_to_end(&mut output);
        // A decoder's own EOF is malformed data, not an interrupted HTTP connection.
        if result.is_err() && encoding == "gzip" && !read_failed {
            return Err(Error::protocol(
                "Remote response contains invalid or truncated gzip data",
            ));
        }
        result?;
        if output.len() as u64 > limit {
            return Err(Error::protocol("Decoded response exceeds its size limit"));
        }
        Ok(output)
    }
}

#[cfg(test)]
#[path = "transport_dlc_tests.rs"]
mod dlc_tests;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn source_service_redirects_preserve_post_but_api_redirects_are_refused() {
        let initial = Url::parse("https://service.example/api").unwrap();
        for status in [301, 302, 303, 307, 308] {
            let next = redirect_target(
                &initial,
                &initial,
                &Method::POST,
                Redirects::Service { same_origin: false },
                status,
                Some("/v2/api"),
                0,
            )
            .unwrap();
            assert_eq!(next.unwrap().as_str(), "https://service.example/v2/api");
            assert!(
                redirect_target(
                    &initial,
                    &initial,
                    &Method::POST,
                    Redirects::None,
                    status,
                    Some("/v2/api"),
                    0
                )
                .is_err()
            );
        }
        for location in [
            "http://service.example/api",
            "https://127.0.0.1/api",
            "https://[2001:2::1]/api",
        ] {
            assert!(
                redirect_target(
                    &initial,
                    &initial,
                    &Method::POST,
                    Redirects::Service { same_origin: false },
                    307,
                    Some(location),
                    0
                )
                .is_err()
            );
        }
        assert!(
            redirect_target(
                &initial,
                &initial,
                &Method::POST,
                Redirects::Service { same_origin: true },
                307,
                Some("https://mirror.example/api"),
                0
            )
            .is_err()
        );
        assert!(
            redirect_target(
                &initial,
                &initial,
                &Method::POST,
                Redirects::Service { same_origin: false },
                307,
                Some("/api"),
                5
            )
            .is_err()
        );
        assert!(
            redirect_target(
                &initial,
                &initial,
                &Method::POST,
                Redirects::Service { same_origin: false },
                307,
                None,
                0
            )
            .is_err()
        );
    }

    #[test]
    fn every_remote_dns_proxy_uses_pinning_without_a_mega_hostname_exception() {
        for host in [
            "https://mega.nz/",
            "https://g.api.mega.co.nz/cs",
            "https://service.example/api",
            "https://evilmega.nz/api",
            "https://mega.nz.evil.invalid/api",
            "https://mega.nz:8443/api",
            "https://1.1.1.1/api",
        ] {
            for proxy in [
                "http://127.0.0.1:9",
                "https://127.0.0.1:9",
                "socks5h://127.0.0.1:9",
            ] {
                assert!(proxy_backend(&Url::parse(host).unwrap(), Some(proxy)).unwrap());
            }
        }
        let target = Url::parse("https://service.example/api").unwrap();
        assert!(!proxy_backend(&target, None).unwrap());
        assert!(!proxy_backend(&target, Some("socks5://127.0.0.1:9")).unwrap());
        assert!(proxy_backend(&target, Some("socks5://service.example:1080")).is_err());
    }
}
