// SPDX-License-Identifier: GPL-3.0-or-later
//! Native Windows private creation/verification. No shell ACL repair or insecure reopen.
use super::secure_files::{DirectorySync, LeafPolicy, validate_name};
use crate::error::{Error, Result};
use std::{
    ffi::{OsStr, c_void},
    fs::File,
    io,
    mem::{offset_of, size_of},
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::{Component, Path, PathBuf},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{
        ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_NO_TOKEN, ERROR_PATH_NOT_FOUND,
        GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
    },
    Security::{
        self, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            GetSecurityInfo, SE_FILE_OBJECT,
        },
        DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, SE_DACL_PROTECTED,
        SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
    },
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateDirectoryW, CreateFileW, DELETE,
        FILE_ALL_ACCESS, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_DISPOSITION_INFO,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH,
        FILE_ID_INFO, FILE_RENAME_INFO, FILE_RENAME_INFO_0, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FILE_TYPE_DISK, FileAttributeTagInfo, FileDispositionInfo, FileIdInfo,
        FileRenameInfo, GetFileInformationByHandle, GetFileInformationByHandleEx, GetFileType,
        OPEN_EXISTING, READ_CONTROL, SetFileInformationByHandle,
    },
    System::{
        SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE},
        Threading::{GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken},
    },
};

#[cfg(test)]
#[path = "windows_creation_tests.rs"]
mod creation_tests;

struct LocalAllocation(*mut c_void);
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: pointer came from a Win32 LocalAlloc-owned SID/SD conversion.
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

fn owned(handle: HANDLE) -> Result<OwnedHandle> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: successful native call transferred this unique handle; OwnedHandle closes it once.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}
fn wide(path: &OsStr) -> Result<Vec<u16>> {
    let mut text: Vec<u16> = path.encode_wide().collect();
    if text.contains(&0) || text.len() > 32_766 {
        return Err(Error::invalid(
            "Windows path contains NUL or exceeds the native length limit",
        ));
    }
    text.push(0);
    Ok(text)
}
fn token_user() -> Result<Vec<usize>> {
    let mut raw = ptr::null_mut();
    // SAFETY: pseudo thread handle valid; output HANDLE address valid, non-inheritable token.
    let thread_open = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut raw) };
    if thread_open == 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_NO_TOKEN as i32) {
            return Err(error.into());
        }
        // SAFETY: valid pseudo-process and output token pointer, same checked access.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
            return Err(io::Error::last_os_error().into());
        }
    }
    let token = owned(raw)?;
    let mut size = 0;
    // SAFETY: null sizing query; token is retained throughout both calls.
    unsafe {
        Security::GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            ptr::null_mut(),
            0,
            &mut size,
        );
    }
    if size < size_of::<TOKEN_USER>() as u32 || size > 4096 {
        return Err(Error::protocol("Invalid token identity buffer size"));
    }
    let mut buffer = vec![0usize; (size as usize).div_ceil(size_of::<usize>())];
    // SAFETY: usize vector has pointer alignment and sufficient initialized writable bytes.
    if unsafe {
        Security::GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            buffer.as_mut_ptr().cast(),
            size,
            &mut size,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().into());
    }
    Ok(buffer)
}
fn sid_from_token(token: &[usize]) -> Result<*mut c_void> {
    // SAFETY: token_user returned aligned TOKEN_USER storage kept alive by the caller.
    let user = unsafe { &*token.as_ptr().cast::<TOKEN_USER>() };
    let start = token.as_ptr() as usize;
    let end = start + std::mem::size_of_val(token);
    let sid_start = user.User.Sid as usize;
    if sid_start < start || sid_start.checked_add(8).is_none_or(|n| n > end) {
        return Err(Error::protocol(
            "Current token SID is outside its identity buffer",
        ));
    }
    // SAFETY: checked SID fixed header lies within retained token storage.
    let count = unsafe { *user.User.Sid.cast::<u8>().add(1) } as usize;
    if sid_start + 8 + count * 4 > end || unsafe { Security::IsValidSid(user.User.Sid) } == 0 {
        return Err(Error::protocol("Current token has no valid user SID"));
    }
    Ok(user.User.Sid)
}
fn descriptor(sid: *mut c_void) -> Result<LocalAllocation> {
    let mut text = ptr::null_mut();
    // SAFETY: checked SID; conversion allocates terminated UTF16 string with LocalAlloc.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(io::Error::last_os_error().into());
    }
    let string_allocation = LocalAllocation(text.cast());
    let mut length = 0;
    // SID strings have a documented bounded shape; reject a missing terminator safely.
    while length < 256 {
        // SAFETY: ConvertSidToStringSidW returned a terminated SID string; maximum SID is below256chars.
        if unsafe { *text.add(length) } == 0 {
            break;
        }
        length += 1;
    }
    if length == 256 {
        return Err(Error::protocol("Current SID string is too long"));
    }
    // SAFETY: the terminated converted SID string covers these length UTF16 units.
    let sid_text = String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) })
        .map_err(|_| Error::protocol("Current SID is not valid UTF16"))?;
    let sddl = wide(OsStr::new(&format!(
        "O:{sid_text}G:{sid_text}D:P(A;;FA;;;{sid_text})"
    )))?;
    let result = descriptor_from_sddl(&sddl);
    drop(string_allocation);
    result
}
fn descriptor_from_sddl(sddl: &[u16]) -> Result<LocalAllocation> {
    let mut sd = ptr::null_mut();
    // SAFETY: callers supply terminated SDDL; returned memory is managed by LocalAllocation.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut sd,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error().into());
    }
    Ok(LocalAllocation(sd))
}
fn attributes(sd: &LocalAllocation) -> SECURITY_ATTRIBUTES {
    SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    }
}
fn open_path(
    path: &Path,
    directory: bool,
    access: u32,
    share: u32,
    disposition: u32,
    attrs: Option<&SECURITY_ATTRIBUTES>,
) -> Result<OwnedHandle> {
    let path = wide(path.as_os_str())?;
    let flags = FILE_FLAG_OPEN_REPARSE_POINT
        | if directory {
            FILE_FLAG_BACKUP_SEMANTICS
        } else {
            // Win32 documents write-through flushing NTFS metadata from writes/renames.
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH
        };
    // SAFETY: path/optional attributes live through call; no inheritance, no truncate dispositions.
    owned(unsafe {
        CreateFileW(
            path.as_ptr(),
            access,
            share,
            attrs.map_or(ptr::null(), |a| a),
            disposition,
            flags,
            ptr::null_mut(),
        )
    })
}
pub(crate) fn file_identity(file: &File) -> Result<String> {
    verify_kind(file.as_raw_handle(), false)?;
    identity_query(file.as_raw_handle())
}
fn identity_query(handle: HANDLE) -> Result<String> {
    // SAFETY: zeroed scalar output layout; exact live handle and typed-size output buffer.
    let mut identity: FILE_ID_INFO = unsafe { std::mem::zeroed() };
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            (&mut identity as *mut FILE_ID_INFO).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().into());
    }
    Ok(format!(
        "windows:{:016x}:{}",
        identity.VolumeSerialNumber,
        hex::encode(identity.FileId.Identifier)
    ))
}

fn verify_kind(handle: HANDLE, directory: bool) -> Result<()> {
    // SAFETY: retained disk handle, correctly sized typed output.
    let mut tags: FILE_ATTRIBUTE_TAG_INFO = unsafe { std::mem::zeroed() };
    if unsafe { GetFileType(handle) } != FILE_TYPE_DISK
        || unsafe {
            GetFileInformationByHandleEx(
                handle,
                FileAttributeTagInfo,
                (&mut tags as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
                size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
            )
        } == 0
    {
        return Err(Error::protocol("Cannot verify native disk object kind"));
    }
    if tags.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (tags.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
    {
        return Err(Error::protocol(
            "Native path is a reparse point or the wrong object kind",
        ));
    }
    if !directory {
        // SAFETY: zero initialization is valid for scalar output structure; call initializes it.
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 || info.nNumberOfLinks != 1
        {
            return Err(Error::protocol("Private file has an unsafe link count"));
        }
    }
    Ok(())
}
fn verify_security(handle: HANDLE, sid: *mut c_void) -> Result<()> {
    let mut owner = ptr::null_mut();
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut sd = ptr::null_mut();
    // SAFETY: retained handle, valid output pointers; all borrowed pointers live within returned SD.
    let rc = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut sd,
        )
    };
    if rc != 0 || sd.is_null() {
        return Err(Error::protocol("Cannot read native owner or ACL"));
    }
    let sd = LocalAllocation(sd);
    let mut control = 0;
    let mut revision = 0;
    // SAFETY: SID and returned descriptor/ACL pointers live; API validates structures before use.
    if owner.is_null()
        || dacl.is_null()
        || unsafe { Security::IsValidSid(owner) } == 0
        || unsafe { Security::EqualSid(owner, sid) } == 0
        || unsafe { Security::GetSecurityDescriptorControl(sd.0, &mut control, &mut revision) } == 0
        || control & SE_DACL_PROTECTED == 0
        || unsafe { Security::IsValidAcl(dacl) } == 0
    {
        return Err(Error::protocol(
            "Native object lacks current-user protected ownership",
        ));
    }
    // SAFETY: IsValidAcl checked header and ACE boundaries.
    let count = unsafe { (*dacl).AceCount };
    let mut granted = 0;
    for index in 0..u32::from(count) {
        let mut raw = ptr::null_mut();
        // SAFETY: checked ACL and bounded ACE index; API supplies pointer into retained SD.
        if unsafe { Security::GetAce(dacl, index, &mut raw) } == 0 || raw.is_null() {
            return Err(Error::protocol("Cannot inspect native access rule"));
        }
        // SAFETY: ACL validator and GetAce ensured ACE header is readable.
        let header = unsafe { &*raw.cast::<ACE_HEADER>() };
        if !matches!(
            u32::from(header.AceType),
            ACCESS_ALLOWED_ACE_TYPE | ACCESS_DENIED_ACE_TYPE
        ) || usize::from(header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>()
        {
            return Err(Error::protocol("Unsupported native access rule"));
        }
        // SAFETY: common ACE shape and minimum size checked; SID starts within returned ACE.
        let ace = unsafe { &*raw.cast::<ACCESS_ALLOWED_ACE>() };
        let ace_sid = ptr::addr_of!(ace.SidStart).cast_mut().cast::<c_void>();
        // The variable SID tail must fit inside this ACE before SID APIs inspect it.
        let sid_bytes = usize::from(header.AceSize) - offset_of!(ACCESS_ALLOWED_ACE, SidStart);
        if sid_bytes < 8 {
            return Err(Error::protocol("Native rule SID is truncated"));
        }
        // SAFETY: ACE bounds above include SID's fixed eight-byte header.
        let sub_authorities = unsafe { *ace_sid.cast::<u8>().add(1) } as usize;
        if 8 + 4 * sub_authorities > sid_bytes || unsafe { Security::IsValidSid(ace_sid) } == 0 {
            return Err(Error::protocol("Invalid native rule SID"));
        }
        // SAFETY: both SIDs validated and alive.
        let is_self = unsafe { Security::EqualSid(ace_sid, sid) } != 0;
        if u32::from(header.AceType) == ACCESS_ALLOWED_ACE_TYPE {
            if !is_self {
                return Err(Error::protocol(
                    "Private native object grants another principal access",
                ));
            }
            granted |= ace.Mask;
        } else if is_self {
            return Err(Error::protocol(
                "Private native object denies its owner access",
            ));
        }
    }
    if granted & FILE_ALL_ACCESS != FILE_ALL_ACCESS {
        return Err(Error::protocol(
            "Private native object lacks full owner access",
        ));
    }
    Ok(())
}

pub struct Directory {
    chain: Vec<OwnedHandle>,
    path: PathBuf,
    policy: LeafPolicy,
}
impl Directory {
    pub fn resolve(path: &Path, create: bool, policy: LeafPolicy) -> Result<Self> {
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()?.join(path)
        };
        let mut parts = absolute.components();
        let Some(Component::Prefix(prefix)) = parts.next() else {
            return Err(Error::invalid(
                "Windows private directory needs an absolute drive path",
            ));
        };
        if !matches!(
            prefix.kind(),
            std::path::Prefix::Disk(_) | std::path::Prefix::VerbatimDisk(_)
        ) {
            return Err(Error::invalid(
                "Only local Windows drive paths are supported for private storage",
            ));
        }
        if !matches!(parts.next(), Some(Component::RootDir)) {
            return Err(Error::invalid(
                "Windows private path must have a drive root",
            ));
        }
        let token = token_user()?;
        let sid = sid_from_token(&token)?;
        let sd = descriptor(sid)?;
        let mut current = PathBuf::from(prefix.as_os_str());
        current.push("\\");
        let mut chain = vec![open_path(
            &current,
            true,
            READ_CONTROL,
            FILE_SHARE_READ,
            OPEN_EXISTING,
            None,
        )?];
        verify_kind(chain[0].as_raw_handle(), true)?;
        for part in parts {
            let Component::Normal(name) = part else {
                return Err(Error::invalid(
                    "Private directory path cannot contain parent traversal",
                ));
            };
            validate_name(name)?;
            current.push(name);
            let opened = open_path(
                &current,
                true,
                READ_CONTROL,
                FILE_SHARE_READ,
                OPEN_EXISTING,
                None,
            );
            let handle = match opened {
                Ok(handle) => handle,
                Err(Error::Io(error))
                    if create
                        && matches!(error.raw_os_error(), Some(code) if code == ERROR_FILE_NOT_FOUND as i32 || code == ERROR_PATH_NOT_FOUND as i32) =>
                {
                    let wide_path = wide(current.as_os_str())?;
                    let attrs = attributes(&sd);
                    // SAFETY: pinned parent chain, terminated path, private descriptor before exposure.
                    if unsafe { CreateDirectoryW(wide_path.as_ptr(), &attrs) } == 0
                        && io::Error::last_os_error().raw_os_error()
                            != Some(ERROR_ALREADY_EXISTS as i32)
                    {
                        return Err(io::Error::last_os_error().into());
                    }
                    let handle = open_path(
                        &current,
                        true,
                        READ_CONTROL,
                        FILE_SHARE_READ,
                        OPEN_EXISTING,
                        None,
                    )?;
                    verify_security(handle.as_raw_handle(), sid)?;
                    handle
                }
                Err(error) => return Err(error),
            };
            verify_kind(handle.as_raw_handle(), true)?;
            chain.push(handle);
        }
        let directory = Self {
            chain,
            path: current,
            policy,
        };
        if policy == LeafPolicy::Private {
            verify_security(directory.leaf()?, sid)?;
        }
        Ok(directory)
    }
    fn leaf(&self) -> Result<HANDLE> {
        self.chain
            .last()
            .map(|h| h.as_raw_handle())
            .ok_or_else(|| Error::protocol("Missing native directory anchor"))
    }
    fn check(&self, sid: *mut c_void) -> Result<()> {
        verify_kind(self.leaf()?, true)?;
        if self.policy == LeafPolicy::Private {
            verify_security(self.leaf()?, sid)?;
        }
        Ok(())
    }
    fn file(
        &self,
        name: &OsStr,
        create_new: bool,
        mutation: bool,
        share_delete: bool,
        read_only: bool,
    ) -> Result<OwnedHandle> {
        let token = token_user()?;
        let sid = sid_from_token(&token)?;
        self.check(sid)?;
        let sd = descriptor(sid)?;
        #[cfg(test)]
        let sd = creation_tests::descriptor_for_creation(&self.path, create_new, sd)?;
        let attrs = attributes(&sd);
        let handle = open_path(
            &self.path.join(name),
            false,
            GENERIC_READ
                | if read_only { 0 } else { GENERIC_WRITE }
                | if self.policy == LeafPolicy::Private || create_new {
                    READ_CONTROL
                } else {
                    0
                }
                | if mutation { DELETE } else { 0 },
            FILE_SHARE_READ | FILE_SHARE_WRITE | if share_delete { FILE_SHARE_DELETE } else { 0 },
            if create_new {
                CREATE_NEW
            } else {
                OPEN_EXISTING
            },
            if create_new { Some(&attrs) } else { None },
        )?;
        verify_kind(handle.as_raw_handle(), false)?;
        if self.policy == LeafPolicy::Private || create_new {
            verify_security(handle.as_raw_handle(), sid)?;
        }
        Ok(handle)
    }
    pub fn verify_private(&self, file: &File) -> Result<()> {
        let token = token_user()?;
        let sid = sid_from_token(&token)?;
        verify_kind(self.leaf()?, true)?;
        verify_security(self.leaf()?, sid)?;
        verify_kind(file.as_raw_handle(), false)?;
        verify_security(file.as_raw_handle(), sid)
    }
    pub fn open_file(&self, name: &OsStr, create_new: bool, read_only: bool) -> Result<File> {
        Ok(File::from(
            self.file(name, create_new, false, false, read_only)?,
        ))
    }
    pub fn child(&self, name: &OsStr) -> Result<Self> {
        Self::resolve(&self.path.join(name), false, self.policy)
    }
    pub fn entries(&self, maximum: usize) -> Result<Vec<super::secure_files::DirectoryEntry>> {
        use super::secure_files::{DirectoryEntry, EntryKind};
        use std::os::windows::fs::MetadataExt;
        let token = token_user()?;
        self.check(sid_from_token(&token)?)?;
        // Retained prefix handles deny delete/write sharing, so this path cannot be redirected.
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(&self.path)? {
            let entry = entry?;
            if entries.len() >= maximum {
                return Err(Error::invalid("Directory manifest exceeds its entry limit"));
            }
            let metadata = std::fs::symlink_metadata(entry.path())?;
            let kind = if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                EntryKind::Other
            } else if metadata.is_dir() {
                EntryKind::Directory
            } else if metadata.is_file() {
                EntryKind::File
            } else {
                EntryKind::Other
            };
            entries.push(DirectoryEntry {
                name: entry.file_name(),
                kind,
                size: metadata.len(),
            });
        }
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(entries)
    }
    pub fn replace(&self, from: &OsStr, to: &OsStr) -> Result<()> {
        self.publish(from, to, true)
    }
    pub fn publish(&self, from: &OsStr, to: &OsStr, overwrite: bool) -> Result<()> {
        let source = self.file(from, false, true, false, false)?;
        let destination = match self.file(to, false, false, true, true) {
            Ok(file) => Some(file),
            Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        if let Some(file) = &destination {
            if identity_query(source.as_raw_handle())? == identity_query(file.as_raw_handle())? {
                return Err(Error::invalid(
                    "Publication source and destination name the same file",
                ));
            }
        }
        let cloned = source.try_clone()?;
        File::from(cloned).sync_all()?;
        // Use Win32's absolute destination form with a NULL root. The retained
        // ancestor handles deny write/delete sharing, so this path cannot be
        // renamed or redirected while the exact source handle is published.
        // Include a terminator in the buffer, but not in FileNameLength.
        let name = wide(self.path.join(to).as_os_str())?;
        let bytes = offset_of!(FILE_RENAME_INFO, FileName) + name.len() * 2;
        let mut buffer = vec![
            0usize;
            bytes
                .max(size_of::<FILE_RENAME_INFO>())
                .div_ceil(size_of::<usize>())
        ];
        let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
        // SAFETY: aligned allocation includes full header+UTF16 tail, root/source retained through call.
        unsafe {
            (*info).Anonymous = FILE_RENAME_INFO_0 {
                ReplaceIfExists: overwrite,
            };
            (*info).RootDirectory = ptr::null_mut();
            (*info).FileNameLength = u32::try_from((name.len() - 1) * 2)
                .map_err(|_| Error::invalid("Replacement name is too long"))?;
            ptr::copy_nonoverlapping(
                name.as_ptr(),
                ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
                name.len(),
            );
            if SetFileInformationByHandle(
                source.as_raw_handle(),
                FileRenameInfo,
                info.cast(),
                u32::try_from(bytes)
                    .map_err(|_| Error::invalid("Replacement buffer is too large"))?,
            ) == 0
            {
                return Err(io::Error::last_os_error().into());
            }
        }
        drop(destination);
        Ok(())
    }
    pub fn remove(&self, name: &OsStr) -> Result<()> {
        self.remove_checked(name, None)
    }
    pub fn remove_owned(&self, name: &OsStr, expected_identity: &str) -> Result<()> {
        self.remove_checked(name, Some(expected_identity))
    }
    fn remove_checked(&self, name: &OsStr, expected_identity: Option<&str>) -> Result<()> {
        let file = self.file(name, false, true, false, true)?;
        if let Some(expected) = expected_identity {
            if identity_query(file.as_raw_handle())? != expected {
                return Err(Error::protocol(
                    "Cleanup refused because the file identity changed",
                ));
            }
        }
        let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
        // SAFETY: exact verified DELETE handle, typed disposition live through synchronous call.
        if unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle(),
                FileDispositionInfo,
                (&disposition as *const FILE_DISPOSITION_INFO).cast(),
                size_of::<FILE_DISPOSITION_INFO>() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        Ok(())
    }
    pub fn available_space(&self) -> Result<u64> {
        super::disk_space::available(&self.path)
    }
    pub fn sync(&self) -> Result<DirectorySync> {
        let token = token_user()?;
        self.check(sid_from_token(&token)?)?;
        // Windows does not document ordinary directory FlushFileBuffers durability.
        // File data is sync_all/FlushFileBuffers before atomic handle-rooted rename.
        Ok(DirectorySync::Unsupported)
    }
}
