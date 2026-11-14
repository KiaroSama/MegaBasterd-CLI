use std::{
    io::{self, StdinLock},
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    sync::{Arc, Mutex, mpsc},
    thread::JoinHandle,
    time::Duration,
};

use windows_sys::Win32::{
    Foundation::{DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE},
    System::{
        Console::{
            CONSOLE_READCONSOLE_CONTROL, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT,
            ENABLE_PROCESSED_INPUT, GetConsoleMode, ReadConsoleW, SetConsoleMode,
        },
        IO::CancelSynchronousIo,
        Threading::{GetCurrentProcess, GetCurrentThread},
    },
};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    error::{Error, Result},
    transfers::control::Control,
};

#[cfg(test)]
#[path = "prompt_input_windows_tests.rs"]
mod tests;

struct Cancellation {
    active: Arc<Mutex<bool>>,
    stop: mpsc::SyncSender<()>,
    worker: Option<JoinHandle<()>>,
}

impl Cancellation {
    fn new(control: &Control) -> Result<Self> {
        let mut handle = std::ptr::null_mut();
        // SAFETY: both pseudo-handles are valid here; DuplicateHandle transfers one real handle.
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                GetCurrentThread(),
                GetCurrentProcess(),
                &mut handle,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: this is the successful unique duplicate, never the pseudo-handle itself.
        let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
        let active = Arc::new(Mutex::new(false));
        let reading = active.clone();
        let control = control.clone();
        let (stop, stopped) = mpsc::sync_channel(1);
        let worker = std::thread::Builder::new()
            .name("prompt-cancel".into())
            .spawn(move || {
                while let Err(mpsc::RecvTimeoutError::Timeout) =
                    stopped.recv_timeout(Duration::from_millis(50))
                {
                    let active = reading.lock().unwrap_or_else(|error| error.into_inner());
                    if *active && control.is_canceled() {
                        // SAFETY: the owned duplicate identifies only this prompt's calling thread.
                        // Repeat until the read returns: cancellation can race just before ReadConsoleW.
                        unsafe {
                            CancelSynchronousIo(handle.as_raw_handle());
                        }
                    }
                }
            })?;
        Ok(Self {
            active,
            stop,
            worker: Some(worker),
        })
    }

    fn close(&mut self) -> Result<()> {
        if let Some(worker) = self.worker.take() {
            let _ = self.stop.try_send(());
            worker
                .join()
                .map_err(|_| Error::protocol("Prompt cancellation worker failed"))?;
        }
        Ok(())
    }
}

impl Drop for Cancellation {
    fn drop(&mut self) {
        if self.close().is_err() {
            eprintln!("[ERROR] Prompt cancellation worker failed.");
        }
    }
}

pub(super) struct Reader<'a, 'input> {
    handle: HANDLE,
    _input: &'a StdinLock<'input>,
    original_mode: u32,
    secret: bool,
    restored: bool,
    control: &'a Control,
    cancellation: Cancellation,
    bytes: Zeroizing<Vec<u8>>,
    position: usize,
    surrogate: Option<u16>,
    eof: bool,
}

impl<'a, 'input> Reader<'a, 'input> {
    pub(super) fn new(
        input: &'a StdinLock<'input>,
        secret: bool,
        control: &'a Control,
    ) -> Result<Self> {
        let handle = input.as_raw_handle();
        let mut mode = 0;
        // SAFETY: input's lock outlives Reader; no ownership of the standard handle is taken.
        if unsafe { GetConsoleMode(handle, &mut mode) } == 0 {
            return Err(io::Error::last_os_error().into());
        }
        let cancellation = Cancellation::new(control)?;
        let mut reader = Self {
            handle,
            _input: input,
            original_mode: mode,
            secret,
            restored: false,
            control,
            cancellation,
            bytes: Zeroizing::new(Vec::with_capacity(4)),
            position: 0,
            surrogate: None,
            eof: false,
        };
        let desired = mode | ENABLE_PROCESSED_INPUT;
        let desired = if secret {
            desired & !(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT)
        } else {
            desired | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT
        };
        // SAFETY: same live console handle; keep signals and visible cooked editing.
        if unsafe { SetConsoleMode(handle, desired) } == 0 {
            return Err(io::Error::last_os_error().into());
        }
        reader.restored = desired == mode;
        control.checkpoint()?;
        Ok(reader)
    }

    pub(super) fn next(&mut self) -> Result<Option<u8>> {
        loop {
            self.control.checkpoint()?;
            if let Some(byte) = self.bytes.get(self.position).copied() {
                self.position += 1;
                return Ok(Some(byte));
            }
            if self.eof {
                return Ok(None);
            }
            self.bytes.zeroize();
            self.position = 0;
            // Leave subsequent pasted lines in the console, not a soon-to-be-dropped local buffer.
            let mut units = Zeroizing::new([0u16; 1]);
            let mut count = 0;
            let input = CONSOLE_READCONSOLE_CONTROL {
                nLength: std::mem::size_of::<CONSOLE_READCONSOLE_CONTROL>() as u32,
                nInitialChars: 0,
                dwCtrlWakeupMask: 1 << 0x1a,
                dwControlKeyState: 0,
            };
            {
                let mut active = self
                    .cancellation
                    .active
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                self.control.checkpoint()?;
                *active = true;
            }
            // SAFETY: buffers/control have their declared sizes and the standard handle is borrowed.
            let (success, error) = unsafe {
                windows_sys::Win32::Foundation::SetLastError(0);
                let success = ReadConsoleW(
                    self.handle,
                    units.as_mut_ptr().cast(),
                    units.len() as u32,
                    &mut count,
                    if self.secret {
                        std::ptr::null()
                    } else {
                        &input
                    },
                );
                (success != 0, windows_sys::Win32::Foundation::GetLastError())
            };
            // Serializing disarm with CancelSynchronousIo prevents canceling later unrelated I/O.
            *self
                .cancellation
                .active
                .lock()
                .unwrap_or_else(|error| error.into_inner()) = false;
            read_result(success, count, error, self.control)?;
            if count as usize > units.len() {
                return Err(Error::protocol("Invalid console read length"));
            }
            let mut units = &units[..count as usize];
            self.eof = (!self.secret && units.last() == Some(&0x1a)) || units.is_empty();
            if !self.secret && units.last() == Some(&0x1a) {
                units = &units[..units.len() - 1];
            }
            decode(units, &mut self.surrogate, &mut self.bytes)?;
            if self.eof && self.surrogate.is_some() {
                return Err(Error::invalid("Prompt input is not valid Unicode"));
            }
        }
    }

    pub(super) fn finish(&mut self) -> Result<()> {
        self.surrogate.zeroize();
        self.bytes.zeroize();
        let stopped = self.cancellation.close();
        if !self.restored {
            // SAFETY: Reader cannot outlive its caller's standard-input lock.
            if unsafe { SetConsoleMode(self.handle, self.original_mode) } == 0 {
                return Err(Error::protocol("Terminal mode restoration failed"));
            }
            self.restored = true;
        }
        stopped
    }
}

impl Drop for Reader<'_, '_> {
    fn drop(&mut self) {
        if self.finish().is_err() {
            eprintln!("[ERROR] Terminal mode restoration failed.");
        }
    }
}

fn read_result(success: bool, count: u32, error: u32, control: &Control) -> Result<()> {
    if (!success || count == 0) && error == 995 {
        control.cancel();
        return Err(Error::Canceled);
    }
    control.checkpoint()?;
    if !success {
        return Err(io::Error::from_raw_os_error(error as i32).into());
    }
    Ok(())
}

fn decode(units: &[u16], pending: &mut Option<u16>, bytes: &mut Vec<u8>) -> Result<()> {
    for &unit in units {
        let scalar = if let Some(high) = pending.take() {
            if !(0xdc00..=0xdfff).contains(&unit) {
                return Err(Error::invalid("Prompt input is not valid Unicode"));
            }
            0x10000 + ((u32::from(high) - 0xd800) << 10) + u32::from(unit) - 0xdc00
        } else if (0xd800..=0xdbff).contains(&unit) {
            *pending = Some(unit);
            continue;
        } else {
            u32::from(unit)
        };
        let character = char::from_u32(scalar)
            .ok_or_else(|| Error::invalid("Prompt input is not valid Unicode"))?;
        let mut encoded = Zeroizing::new([0; 4]);
        bytes.extend_from_slice(character.encode_utf8(&mut *encoded).as_bytes());
    }
    Ok(())
}
