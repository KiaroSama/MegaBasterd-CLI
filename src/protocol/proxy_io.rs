use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ureq::unversioned::transport::{Buffers, LazyBuffers, NextTimeout, Transport};

use crate::transfers::control::Control;

pub(super) struct Socket {
    stream: TcpStream,
    buffers: LazyBuffers,
    control: Control,
    deadline: Instant,
    connect_deadline: Instant,
    connected: Arc<AtomicBool>,
}

impl Socket {
    pub(super) fn new(
        stream: TcpStream,
        control: Control,
        deadline: Instant,
        connect_deadline: Instant,
        connected: Arc<AtomicBool>,
    ) -> io::Result<Self> {
        stream.set_nodelay(true)?;
        Ok(Self {
            stream,
            buffers: LazyBuffers::new(64 * 1024, 64 * 1024),
            control,
            deadline,
            connect_deadline,
            connected,
        })
    }

    fn operation_deadline(&self, timeout: NextTimeout) -> Instant {
        let absolute = if self.connected.load(Ordering::Acquire) {
            self.deadline
        } else {
            self.deadline.min(self.connect_deadline)
        };
        match timeout.after {
            ureq::unversioned::transport::time::Duration::Exact(duration) => Instant::now()
                .checked_add(duration)
                .map_or(absolute, |limit| absolute.min(limit)),
            ureq::unversioned::transport::time::Duration::NotHappening => absolute,
        }
    }
}

fn remaining(control: &Control, deadline: Instant) -> io::Result<Duration> {
    if control.is_canceled() {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "HTTP operation was canceled",
        ));
    }
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "HTTP operation exceeded its deadline",
        ));
    }
    Ok(remaining.min(Duration::from_millis(250)))
}

fn poll_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

impl Transport for Socket {
    fn buffers(&mut self) -> &mut dyn Buffers {
        &mut self.buffers
    }

    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), ureq::Error> {
        let deadline = self.operation_deadline(timeout);
        let output = &self.buffers.output()[..amount];
        let mut sent = 0;
        while sent < output.len() {
            self.stream
                .set_write_timeout(Some(remaining(&self.control, deadline)?))?;
            match self.stream.write(&output[sent..]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "HTTP peer refused remaining bytes",
                    )
                    .into());
                }
                Ok(count) => sent += count,
                Err(error) if poll_error(&error) => (),
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
        let deadline = self.operation_deadline(timeout);
        loop {
            self.stream
                .set_read_timeout(Some(remaining(&self.control, deadline)?))?;
            match self.stream.read(self.buffers.input_append_buf()) {
                Ok(count) => {
                    self.buffers.input_appended(count);
                    return Ok(count > 0);
                }
                Err(error) if poll_error(&error) => (),
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn is_open(&mut self) -> bool {
        // Each agent serves one request; a socket must never enter a reusable pool.
        false
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}

impl fmt::Debug for Socket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundedProxySocket").finish_non_exhaustive()
    }
}

pub(super) struct Tunnel(pub Box<dyn Transport>);

impl Transport for Tunnel {
    fn buffers(&mut self) -> &mut dyn Buffers {
        self.0.buffers()
    }
    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), ureq::Error> {
        self.0.transmit_output(amount, timeout)
    }
    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
        self.0.await_input(timeout)
    }
    fn is_open(&mut self) -> bool {
        false
    }
    // The outer HTTPS proxy is not the destination TLS endpoint.
    fn is_tls(&self) -> bool {
        false
    }
}

impl fmt::Debug for Tunnel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyTunnel").finish_non_exhaustive()
    }
}

pub(super) struct Target {
    pub inner: Box<dyn Transport>,
    pub sent: Arc<AtomicBool>,
    pub control: Control,
}

impl Transport for Target {
    fn buffers(&mut self) -> &mut dyn Buffers {
        self.inner.buffers()
    }
    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), ureq::Error> {
        if self.control.is_canceled() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "HTTP operation was canceled",
            )
            .into());
        }
        if amount > 0 {
            self.sent.store(true, Ordering::Release);
        }
        self.inner.transmit_output(amount, timeout)
    }
    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
        if self.control.is_canceled() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "HTTP operation was canceled",
            )
            .into());
        }
        self.inner.await_input(timeout)
    }
    fn is_open(&mut self) -> bool {
        false
    }
    fn is_tls(&self) -> bool {
        self.inner.is_tls()
    }
}

impl fmt::Debug for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinnedTlsTarget").finish_non_exhaustive()
    }
}
