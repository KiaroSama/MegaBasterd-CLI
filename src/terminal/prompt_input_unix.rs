use std::{
    ffi::{CStr, OsStr},
    fs::{File, OpenOptions},
    io::{self, Read},
    os::{
        fd::{AsFd, AsRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
        },
    },
};

use crate::{
    error::{Error, Result},
    transfers::control::Control,
};

#[cfg(test)]
#[path = "prompt_input_unix_tests.rs"]
mod tests;

pub(super) struct Reader<'a> {
    file: File,
    control: &'a Control,
    original_mode: libc::termios,
    secret: bool,
    visible_limit: Option<usize>,
    received: usize,
    restored: bool,
}

impl<'a> Reader<'a> {
    pub(super) fn new(input: &impl AsFd, secret: bool, control: &'a Control) -> Result<Self> {
        let mut name = [0u8; 4096];
        // SAFETY: input keeps its descriptor alive; name is writable for the stated length.
        let status = unsafe {
            libc::ttyname_r(
                input.as_fd().as_raw_fd(),
                name.as_mut_ptr().cast(),
                name.len(),
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status).into());
        }
        let name = CStr::from_bytes_until_nul(&name)
            .map_err(|_| Error::protocol("Terminal device name is not terminated"))?;
        // A new file description avoids changing O_NONBLOCK on inherited stdin or its duplicates.
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOCTTY)
            .open(OsStr::from_bytes(name.to_bytes()))?;
        let source = File::from(input.as_fd().try_clone_to_owned()?).metadata()?;
        let opened = file.metadata()?;
        if !opened.file_type().is_char_device()
            || (source.dev(), source.ino(), source.rdev())
                != (opened.dev(), opened.ino(), opened.rdev())
        {
            return Err(Error::protocol("Interactive terminal identity changed"));
        }
        let mut mode = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: the successful call initializes mode; file remains open and is a tty.
        if unsafe { libc::tcgetattr(file.as_raw_fd(), mode.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: tcgetattr returned success immediately above.
        let original_mode = unsafe { mode.assume_init() };
        let visible_limit = if secret {
            None
        } else {
            // SAFETY: the validated terminal descriptor remains live for this read-only query.
            let capacity = unsafe { libc::fpathconf(file.as_raw_fd(), libc::_PC_MAX_CANON) };
            let capacity = usize::try_from(capacity)
                .ok()
                .filter(|&value| value > 1)
                .ok_or_else(|| {
                    Error::protocol("Terminal canonical input capacity is unavailable")
                })?;
            // Reserve the delimiter byte; a saturated canonical line may already have lost input.
            Some((capacity - 1).min(super::MAX_PROMPT_BYTES))
        };
        let mut mode = original_mode;
        mode.c_lflag |= libc::ISIG;
        // Keep CR distinct from LF across hidden/cooked transitions and optional CRLF tails.
        mode.c_iflag &= !(libc::ICRNL | libc::INLCR | libc::IGNCR);
        if secret {
            // Canonical queues silently discard long secrets before the application can bound them.
            mode.c_lflag &= !(libc::ICANON | libc::ECHO | libc::ECHONL);
            mode.c_cc[libc::VMIN] = 1;
            mode.c_cc[libc::VTIME] = 0;
        } else {
            mode.c_lflag |= libc::ICANON | libc::ECHO;
            mode.c_lflag &= !libc::ECHOCTL;
            mode.c_cc[libc::VEOL] = b'\r';
        }
        let reader = Self {
            file,
            control,
            original_mode,
            secret,
            visible_limit,
            received: 0,
            restored: mode.c_lflag == original_mode.c_lflag
                && mode.c_iflag == original_mode.c_iflag
                && mode.c_cc == original_mode.c_cc,
        };
        if !reader.restored {
            // SAFETY: same validated tty and initialized termios; retain visible kernel editing.
            if unsafe { libc::tcsetattr(reader.file.as_raw_fd(), libc::TCSANOW, &mode) } != 0 {
                return Err(io::Error::last_os_error().into());
            }
        }
        control.checkpoint()?;
        Ok(reader)
    }

    pub(super) fn next(&mut self) -> Result<Option<u8>> {
        loop {
            self.control.checkpoint()?;
            let mut descriptor = libc::pollfd {
                fd: self.file.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: descriptor is one valid pollfd; the borrowed file remains open throughout poll.
            let status = unsafe { libc::poll(&mut descriptor, 1, 100) };
            let error = (status < 0).then(io::Error::last_os_error);
            self.control.checkpoint()?;
            if let Some(error) = error {
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error.into());
            }
            if status == 0 {
                continue;
            }
            if descriptor.revents & libc::POLLNVAL != 0 {
                return Err(Error::protocol("Interactive terminal handle is invalid"));
            }
            let mut byte = [0];
            match self.file.read(&mut byte) {
                Ok(0)
                    if self.secret && descriptor.revents & (libc::POLLERR | libc::POLLHUP) == 0 =>
                {
                    continue;
                }
                Ok(0) => return Ok(None),
                Ok(_) => {
                    if let Some(limit) = self.visible_limit {
                        if matches!(byte[0], b'\r' | b'\n') {
                            self.received = 0;
                        } else {
                            self.received = self.received.saturating_add(1);
                            if self.received >= limit {
                                return Err(Error::invalid(
                                    "Prompt input reaches the terminal's safe line limit; use CLI arguments for long values",
                                ));
                            }
                        }
                    }
                    return Ok(Some(byte[0]));
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if descriptor.revents & (libc::POLLERR | libc::POLLHUP) != 0 {
                        return Err(Error::protocol("Interactive terminal disconnected"));
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    pub(super) fn finish(&mut self) -> Result<()> {
        if !self.restored {
            // SAFETY: this owned descriptor still refers to the validated terminal.
            if unsafe { libc::tcsetattr(self.file.as_raw_fd(), libc::TCSANOW, &self.original_mode) }
                != 0
            {
                return Err(Error::protocol("Terminal mode restoration failed"));
            }
            self.restored = true;
        }
        Ok(())
    }
}

impl Drop for Reader<'_> {
    fn drop(&mut self) {
        if self.finish().is_err() {
            eprintln!("[ERROR] Terminal mode restoration failed.");
        }
    }
}
