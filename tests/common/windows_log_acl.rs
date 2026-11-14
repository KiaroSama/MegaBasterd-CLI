use std::{
    ffi::c_void,
    fs::OpenOptions,
    mem::{offset_of, size_of},
    os::windows::{
        ffi::OsStrExt,
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::Path,
    ptr,
};
use windows_sys::Win32::{
    Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_NO_TOKEN, LocalFree},
    Security::{
        self, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            GetSecurityInfo, SE_FILE_OBJECT,
        },
        CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, OBJECT_INHERIT_ACE,
        OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, SE_DACL_PROTECTED,
        SetFileSecurityW, TOKEN_QUERY, TOKEN_USER, TokenUser,
    },
    Storage::FileSystem::{FILE_ALL_ACCESS, FILE_FLAG_BACKUP_SEMANTICS, FILE_GENERIC_READ},
    System::{
        SystemServices::ACCESS_ALLOWED_ACE_TYPE,
        Threading::{GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken},
    },
};

const LOCAL_SERVICE: &str = "S-1-5-19";

struct Allocation(*mut c_void);
impl Drop for Allocation {
    fn drop(&mut self) {
        // SAFETY: this fixture owns only buffers returned by LocalAlloc-based security APIs.
        unsafe { LocalFree(self.0) };
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Snapshot {
    owner: String,
    protected: bool,
    grants: Vec<(String, u32, u8)>,
}

fn sid_text(sid: *mut c_void) -> String {
    let mut text = ptr::null_mut();
    // SAFETY: caller supplies a validated SID inside its retained descriptor/ACE.
    assert_ne!(unsafe { ConvertSidToStringSidW(sid, &mut text) }, 0);
    let _allocation = Allocation(text.cast());
    assert!(!text.is_null());
    let length = (0..256)
        // SAFETY: conversion returns a terminated SID string, bounded below 256 code units.
        .find(|&index| unsafe { *text.add(index) } == 0)
        .unwrap();
    // SAFETY: the terminated allocation covers the inspected prefix.
    String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) }).unwrap()
}

pub fn snapshot(path: &Path) -> Snapshot {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .unwrap();
    let mut owner = ptr::null_mut();
    let mut acl: *mut ACL = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    // SAFETY: retained fixture file and valid outputs; owner/ACL borrow the returned descriptor.
    assert_eq!(
        unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                &mut acl,
                ptr::null_mut(),
                &mut descriptor,
            )
        },
        0
    );
    let _allocation = Allocation(descriptor);
    assert!(!descriptor.is_null() && !owner.is_null() && !acl.is_null());
    // SAFETY: pointers borrow the successful native security query's live descriptor.
    assert_ne!(unsafe { Security::IsValidSid(owner) }, 0);
    assert_ne!(unsafe { Security::IsValidAcl(acl) }, 0);
    let mut control = 0;
    let mut revision = 0;
    // SAFETY: retained valid descriptor and typed outputs.
    assert_ne!(
        unsafe { Security::GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) },
        0
    );
    // SAFETY: IsValidAcl validated the ACL header and contained ACE boundaries.
    let count = unsafe { (*acl).AceCount };
    assert!(count <= 4, "unexpected fixture ACL size");
    let mut grants = Vec::new();
    for index in 0..u32::from(count) {
        let mut raw = ptr::null_mut();
        // SAFETY: valid ACL, bounded ACE index, output pointer into retained descriptor.
        assert_ne!(unsafe { Security::GetAce(acl, index, &mut raw) }, 0);
        assert!(!raw.is_null());
        // SAFETY: validated ACL and GetAce provide a readable ACE header.
        let header = unsafe { &*raw.cast::<ACE_HEADER>() };
        assert_eq!(u32::from(header.AceType), ACCESS_ALLOWED_ACE_TYPE);
        assert!(usize::from(header.AceSize) >= size_of::<ACCESS_ALLOWED_ACE>());
        // SAFETY: checked allow-ACE type and size; variable SID tail remains inside this ACE.
        let ace = unsafe { &*raw.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = ptr::addr_of!(ace.SidStart).cast_mut().cast::<c_void>();
        let bytes = usize::from(header.AceSize) - offset_of!(ACCESS_ALLOWED_ACE, SidStart);
        assert!(bytes >= 8);
        // SAFETY: fixed SID header lies within the checked ACE boundary.
        let sub_authorities = unsafe { *sid.cast::<u8>().add(1) } as usize;
        assert!(8 + 4 * sub_authorities <= bytes);
        assert_ne!(unsafe { Security::IsValidSid(sid) }, 0);
        grants.push((sid_text(sid), ace.Mask, header.AceFlags));
    }
    Snapshot {
        owner: sid_text(owner),
        protected: control & SE_DACL_PROTECTED != 0,
        grants,
    }
}

fn current_token_user() -> String {
    let mut raw = ptr::null_mut();
    // SAFETY: valid pseudo-thread and output pointer; token is not inherited.
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut raw) } == 0 {
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(ERROR_NO_TOKEN as i32)
        );
        // SAFETY: valid pseudo-process and output pointer with query-only access.
        assert_ne!(
            unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) },
            0
        );
    }
    assert!(!raw.is_null());
    // SAFETY: successful token open transfers this unique handle to the fixture.
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut needed = 0;
    // SAFETY: documented sizing query; token remains live for the following read.
    assert_eq!(
        unsafe {
            Security::GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                ptr::null_mut(),
                0,
                &mut needed,
            )
        },
        0
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(ERROR_INSUFFICIENT_BUFFER as i32)
    );
    assert!((size_of::<TOKEN_USER>() as u32..=4096).contains(&needed));
    let mut buffer = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
    // SAFETY: aligned initialized storage covers needed bytes and outlives every SID read.
    assert_ne!(
        unsafe {
            Security::GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                buffer.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        },
        0
    );
    assert!(needed as usize >= size_of::<TOKEN_USER>());
    assert!(needed as usize <= std::mem::size_of_val(buffer.as_slice()));
    // SAFETY: successful TokenUser query initialized the checked aligned structure.
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let start = buffer.as_ptr() as usize;
    let end = start + needed as usize;
    let sid = user.User.Sid as usize;
    assert!(sid >= start && sid.checked_add(8).is_some_and(|value| value <= end));
    // SAFETY: the fixed SID header was checked inside the retained token buffer.
    let count = usize::from(unsafe { *user.User.Sid.cast::<u8>().add(1) });
    assert!(sid + 8 + count * 4 <= end);
    assert_ne!(unsafe { Security::IsValidSid(user.User.Sid) }, 0);
    sid_text(user.User.Sid)
}

impl Snapshot {
    pub fn grants_local_service_read(&self) -> bool {
        self.grants.iter().any(|(sid, mask, _)| {
            sid == LOCAL_SERVICE && mask & FILE_GENERIC_READ == FILE_GENERIC_READ
        })
    }

    pub fn assert_owner_only(&self) {
        assert!(!self.grants_local_service_read());
        let current = current_token_user();
        assert_eq!(self.owner, current);
        assert!(self.protected);
        assert_eq!(self.grants, [(current, FILE_ALL_ACCESS, 0)]);
    }
}

pub fn grant_local_service_read(path: &Path, inheritable: bool) -> Snapshot {
    if inheritable {
        assert!(path.is_dir());
    }
    let before = snapshot(path);
    assert_ne!(before.owner, LOCAL_SERVICE);
    assert!(before.protected);
    assert_eq!(before.grants, [(before.owner.clone(), FILE_ALL_ACCESS, 0)]);
    let inheritance = if inheritable { "OICI" } else { "" };
    let flags = if inheritable {
        u8::try_from(OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE).unwrap()
    } else {
        0
    };
    let sddl: Vec<u16> = format!(
        "D:P(A;{inheritance};FA;;;{})(A;{inheritance};FR;;;{LOCAL_SERVICE})",
        before.owner
    )
    .encode_utf16()
    .chain(Some(0))
    .collect();
    let path_wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut descriptor = ptr::null_mut();
    // SAFETY: terminated SDDL and valid output allocation, retained through the setter.
    assert_ne!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                ptr::null_mut(),
            )
        },
        0
    );
    let _allocation = Allocation(descriptor);
    // SAFETY: this changes only the owned fixture's DACL, never its owner or another path.
    assert_ne!(
        unsafe {
            SetFileSecurityW(
                path_wide.as_ptr(),
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                descriptor,
            )
        },
        0
    );
    let after = snapshot(path);
    assert_eq!(after.owner, before.owner);
    assert!(after.protected);
    assert_eq!(
        after.grants,
        [
            (before.owner, FILE_ALL_ACCESS, flags),
            (LOCAL_SERVICE.to_owned(), FILE_GENERIC_READ, flags),
        ]
    );
    after
}
