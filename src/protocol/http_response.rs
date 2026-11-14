use std::{
    io::{self, Cursor, Read},
    time::Instant,
};

use reqwest::header::HeaderMap;

use super::http_wait::interruptible;
use crate::{error::Error, transfers::control::Control};

pub struct HttpResponse {
    status: reqwest::StatusCode,
    headers: HeaderMap,
    body: Box<dyn Read + Send>,
}

impl HttpResponse {
    pub(super) fn reqwest(
        response: reqwest::Response,
        client: reqwest::Client,
        runtime: tokio::runtime::Runtime,
        control: Control,
        deadline: Instant,
        #[cfg(test)] body_pending: Option<std::sync::mpsc::SyncSender<()>>,
    ) -> Self {
        Self {
            status: response.status(),
            headers: response.headers().clone(),
            body: Box::new(DirectBody {
                response,
                _client: client,
                pending: Box::new(io::empty()),
                runtime,
                control,
                deadline,
                #[cfg(test)]
                body_pending,
                #[cfg(test)]
                body_started: false,
            }),
        }
    }
    pub fn streamed(
        status: reqwest::StatusCode,
        headers: HeaderMap,
        body: impl Read + Send + 'static,
    ) -> Self {
        Self {
            status,
            headers,
            body: Box::new(body),
        }
    }
    pub fn status(&self) -> reqwest::StatusCode {
        self.status
    }
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }
    pub fn content_length(&self) -> Option<u64> {
        self.headers
            .get(reqwest::header::CONTENT_LENGTH)?
            .to_str()
            .ok()?
            .parse()
            .ok()
    }
}

impl Read for HttpResponse {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.body.read(output)
    }
}

// Field order drops network state before its owning runtime, including on early cancellation.
struct DirectBody {
    response: reqwest::Response,
    _client: reqwest::Client,
    pending: Box<dyn Read + Send>,
    runtime: tokio::runtime::Runtime,
    control: Control,
    deadline: Instant,
    #[cfg(test)]
    body_pending: Option<std::sync::mpsc::SyncSender<()>>,
    #[cfg(test)]
    body_started: bool,
}

impl Read for DirectBody {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        loop {
            if self.control.is_canceled() {
                return Err(network_io(Error::Canceled));
            }
            let count = self.pending.read(output)?;
            if count != 0 {
                #[cfg(test)]
                {
                    self.body_started = true;
                }
                return Ok(count);
            }
            #[cfg(test)]
            let observer = self
                .body_pending
                .as_ref()
                .filter(|_| self.body_started)
                .map(|sender| super::http_wait::observe_pending(sender.clone()));
            let chunk = self.runtime.block_on(interruptible(
                async { self.response.chunk().await.map_err(Error::from) },
                self.deadline,
                &self.control,
            ));
            #[cfg(test)]
            {
                if observer
                    .as_ref()
                    .is_some_and(|observer| observer.notified())
                {
                    self.body_pending = None;
                }
                drop(observer);
            }
            match chunk.map_err(network_io)? {
                Some(bytes) => self.pending = Box::new(Cursor::new(bytes)),
                None => return Ok(0),
            }
        }
    }
}

fn network_io(error: Error) -> io::Error {
    match error {
        Error::Http(error) => {
            let kind = if error.is_timeout() {
                io::ErrorKind::TimedOut
            } else if error.is_body() || error.is_decode() {
                io::ErrorKind::UnexpectedEof
            } else {
                io::ErrorKind::Other
            };
            io::Error::new(kind, error)
        }
        Error::Canceled => io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "HTTP operation was canceled",
        ),
        Error::Timeout => io::Error::new(
            io::ErrorKind::TimedOut,
            "HTTP operation exceeded its deadline",
        ),
        error => io::Error::other(error),
    }
}

#[cfg(test)]
#[path = "http_response_peer_tests.rs"]
mod peer_tests;
