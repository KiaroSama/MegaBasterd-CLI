//! Native Windows Unicode clipboard access, without a script host.
use crate::error::{Error, Result};

const MAX_UNITS: usize = 512 * 1024;

fn decode(units: &[u16]) -> Result<String> {
    if units.len() > MAX_UNITS {
        return Err(Error::protocol("Clipboard text exceeds its size limit"));
    }
    let end = units
        .iter()
        .position(|unit| *unit == 0)
        .ok_or_else(|| Error::protocol("Clipboard text is not terminated"))?;
    let text = String::from_utf16(&units[..end])
        .map_err(|_| Error::protocol("Clipboard text is not valid Unicode"))?;
    if text.len() > 1024 * 1024 {
        return Err(Error::protocol("Clipboard text exceeds its size limit"));
    }
    Ok(text)
}

#[cfg(windows)]
pub(crate) fn read(control: &crate::transfers::control::Control) -> Result<String> {
    use windows_sys::Win32::{
        Foundation::HGLOBAL,
        System::{
            DataExchange::{
                CloseClipboard, GetClipboardData, IsClipboardFormatAvailable, OpenClipboard,
            },
            Memory::{GlobalLock, GlobalSize, GlobalUnlock},
        },
    };
    const CF_UNICODETEXT: u32 = 13;
    control.checkpoint()?;
    // SAFETY: OpenClipboard accepts a null owner for read-only access.
    if unsafe { OpenClipboard(std::ptr::null_mut()) } == 0 {
        return Err(Error::Busy("Clipboard".into()));
    }
    struct Clipboard;
    impl Drop for Clipboard {
        fn drop(&mut self) {
            // SAFETY: this guard owns the successful OpenClipboard call on this thread.
            unsafe {
                CloseClipboard();
            }
        }
    }
    let _clipboard = Clipboard;
    // SAFETY: the current thread holds the clipboard open for these queries.
    if unsafe { IsClipboardFormatAvailable(CF_UNICODETEXT) } == 0 {
        return Ok(String::new());
    }
    // SAFETY: the current thread owns clipboard access; the returned handle stays system-owned.
    let data = unsafe { GetClipboardData(CF_UNICODETEXT) };
    if data.is_null() {
        return Err(Error::protocol("Clipboard text is unavailable"));
    }
    // SAFETY: CF_UNICODETEXT is a global allocation whose size is queried before dereferencing.
    let size = unsafe { GlobalSize(data) };
    if size < 2 || !size.is_multiple_of(2) || size / 2 > MAX_UNITS {
        return Err(Error::protocol(
            "Clipboard text allocation is invalid or oversized",
        ));
    }
    // SAFETY: GlobalLock locks the system-owned allocation while the clipboard remains open.
    let pointer = unsafe { GlobalLock(data) };
    if pointer.is_null() {
        return Err(Error::protocol("Clipboard text could not be locked"));
    }
    struct Locked(HGLOBAL);
    impl Drop for Locked {
        fn drop(&mut self) {
            // SAFETY: this guard balances exactly one successful GlobalLock.
            unsafe {
                GlobalUnlock(self.0);
            }
        }
    }
    let _locked = Locked(data);
    // SAFETY: the retained allocation contains size bytes and is aligned for UTF-16 data.
    let units = unsafe { std::slice::from_raw_parts(pointer.cast::<u16>(), size / 2) };
    let text = decode(units)?;
    control.checkpoint()?;
    Ok(text)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn native_unicode_clipboard_preserves_empty_multiline_and_non_ascii_text() {
        for text in ["", "first\nsecond\n", "متن 🦀"] {
            let mut units: Vec<_> = text.encode_utf16().collect();
            units.extend([0, 65, 66]);
            assert_eq!(decode(&units).unwrap(), text);
        }
    }
    #[test]
    fn malformed_unterminated_or_oversized_native_clipboards_are_refused() {
        assert!(decode(&[65]).is_err());
        assert!(decode(&[0xd800, 0]).is_err());
        assert!(decode(&vec![0; MAX_UNITS + 1]).is_err());
    }
}
