//! Caller-available filesystem space; a preflight observation, never a reservation.

use crate::error::{Error, Result};

#[cfg(unix)]
pub(super) fn available(file: &std::fs::File) -> Result<u64> {
    use std::os::fd::AsRawFd;

    let mut status = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: the borrowed file descriptor remains live and the output has its native layout.
    if unsafe { libc::fstatvfs(file.as_raw_fd(), status.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: successful fstatvfs initialized the output structure.
    let status = unsafe { status.assume_init() };
    let bytes = u128::from(status.f_bavail)
        .checked_mul(u128::from(status.f_frsize))
        .filter(|_| status.f_frsize != 0)
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or_else(|| Error::protocol("Filesystem available-space count is invalid"))?;
    Ok(bytes)
}

#[cfg(windows)]
pub(super) fn available(path: &std::path::Path) -> Result<u64> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

    let mut path: Vec<u16> = path.as_os_str().encode_wide().collect();
    if path.contains(&0) || path.len() > 32_766 {
        return Err(Error::invalid("Filesystem query path is invalid"));
    }
    path.push(0);
    let mut available = 0;
    // SAFETY: terminated path and valid output; caller retains the pinned directory chain.
    if unsafe {
        GetDiskFreeSpaceExW(
            path.as_ptr(),
            &mut available,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(available)
}
