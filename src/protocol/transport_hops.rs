//! Shared redirect lifecycle; only the external per-hop exchange varies in tests.

use super::*;

#[cfg(test)]
#[path = "transport_hop_tests.rs"]
mod tests;

impl Transport {
    pub(super) fn send_hops(
        &self,
        method: Method,
        url: Url,
        policy: Redirects,
        mut send: impl FnMut(
            &Method,
            &Url,
            Option<&str>,
            bool,
        ) -> std::result::Result<HttpResponse, AttemptFailure>,
    ) -> std::result::Result<Reply, AttemptFailure> {
        safe_target(&url).map_err(AttemptFailure::before)?;
        let initial = url.clone();
        let mut url = url;
        let mut sent = false;
        for hop in 0..=5 {
            let failure = |error| AttemptFailure { error, sent };
            self.control.checkpoint().map_err(failure)?;
            safe_target(&url).map_err(failure)?;
            #[cfg(test)]
            if let Some(address) = self.test_peer
                && (url.host_str() != Some("testserver.com") || url.port() != Some(address.port()))
            {
                return Err(failure(Error::invalid("Test peer destination changed")));
            }
            let (proxy, picked) = self.routing.select().map_err(failure)?;
            let pinned = proxy_backend(&url, proxy.as_deref()).map_err(failure)?;
            let response = match send(&method, &url, proxy.as_deref(), pinned) {
                Ok(response) => response,
                Err(mut error) => {
                    error.sent |= sent;
                    // Bookkeeping cannot turn an in-flight request into a pre-send failure.
                    let _ = self.routing.report(picked.as_deref(), false);
                    return Err(error);
                }
            };
            sent = true;
            let next = redirect_target(
                &url,
                &initial,
                &method,
                policy,
                response.status().as_u16(),
                response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|value| value.to_str().ok()),
                hop,
            )
            .map_err(AttemptFailure::after)?;
            if let Some(next) = next {
                drop(response);
                url = next;
                continue;
            }
            if response.status().as_u16() == 407 {
                self.routing
                    .report(picked.as_deref(), false)
                    .map_err(AttemptFailure::after)?;
            }
            return Ok(Reply {
                response,
                picked,
                routing: self.routing.clone(),
            });
        }
        Err(AttemptFailure::after(Error::protocol(
            "Redirect limit exceeded",
        )))
    }
}
