//! Deliver one encrypted upload chunk; file/state ownership stays with the upload orchestrator.
use std::time::Duration;

use reqwest::{Method, header::HeaderMap};
use url::Url;

use super::control::{Control, RateLimiter};
use crate::{
    error::{Error, Result},
    protocol::{transport::Transport, uploads::completion_token},
};

#[cfg(test)]
#[path = "upload_chunk_health_tests.rs"]
mod health_tests;
#[cfg(test)]
#[path = "upload_chunk_tests.rs"]
mod tests;

pub(super) enum Delivery {
    Accepted(Option<String>),
    Expired,
}

pub(super) struct ChunkRequest<'a> {
    pub transport: &'a Transport,
    pub endpoint: &'a str,
    pub offset: u64,
    pub final_chunk: bool,
    pub ciphertext: &'a [u8],
    pub limiter: &'a RateLimiter,
    pub control: &'a Control,
}

impl ChunkRequest<'_> {
    pub(super) fn send(self) -> Result<Delivery> {
        self.with_wait(|duration| self.control.wait(duration))
    }

    fn with_wait(&self, wait: impl FnMut(Duration) -> Result<()>) -> Result<Delivery> {
        self.with_send(wait, |url| {
            self.transport.send(
                Method::POST,
                url,
                HeaderMap::new(),
                Some(self.ciphertext.to_vec()),
                false,
            )
        })
    }

    fn with_send(
        &self,
        mut wait: impl FnMut(Duration) -> Result<()>,
        mut send: impl FnMut(Url) -> Result<crate::protocol::transport::Reply>,
    ) -> Result<Delivery> {
        let url = Url::parse(&format!(
            "{}/{}",
            self.endpoint.trim_end_matches('/'),
            self.offset
        ))
        .map_err(|_| Error::protocol("Upload chunk URL is invalid"))?;
        #[cfg(test)]
        let url = self.transport.test_upload_url(url)?;
        for attempt in 0..5u32 {
            self.limiter.acquire(self.ciphertext.len(), self.control)?;
            let mut reply = match send(url.clone()) {
                Ok(reply) => reply,
                Err(_) if self.control.is_canceled() => return Err(Error::Canceled),
                Err(error) if attempt < 4 && error.retryable_network() => {
                    wait(Duration::from_secs((2u64 << attempt).min(30)))?;
                    continue;
                }
                Err(error) => return Err(error),
            };
            let status = reply.response.status().as_u16();
            if matches!(status, 403 | 404 | 410 | 509) {
                return Ok(Delivery::Expired);
            }
            if status >= 500 && attempt < 4 {
                let _ = reply.malformed();
                drop(reply);
                wait(Duration::from_secs((2u64 << attempt).min(30)))?;
                continue;
            }
            if status != 200 {
                let _ = reply.malformed();
                return Err(Error::protocol(format!(
                    "Upload chunk returned HTTP {status}"
                )));
            }
            let token = match reply
                .bytes(4096)
                .and_then(|body| completion_token(&body, self.final_chunk))
            {
                Ok(token) => token,
                Err(error) => {
                    self.control.checkpoint()?;
                    let _ = reply.malformed();
                    if attempt < 4 && error.retryable_network() {
                        drop(reply);
                        wait(Duration::from_secs((2u64 << attempt).min(30)))?;
                        continue;
                    }
                    return Err(error);
                }
            };
            reply.credit()?;
            return Ok(Delivery::Accepted(token));
        }
        Err(Error::Timeout)
    }
}
