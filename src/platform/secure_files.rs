// SPDX-License-Identifier: GPL-3.0-or-later
//! Handle-anchored owner-private storage. Retain the directory across a transaction.
use crate::error::{Error, Result};
use std::{
    ffi::OsStr,
    fs::File,
    path::{Component, Path},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectorySync {
    Synced,
    Unsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Directory,
    Other,
}

pub struct DirectoryEntry {
    pub name: std::ffi::OsString,
    pub kind: EntryKind,
    pub size: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum LeafPolicy {
    Private,
    Output,
}

#[cfg(unix)]
type NativeDirectory = unix::Directory;
#[cfg(windows)]
type NativeDirectory = super::windows_files::Directory;

pub struct PrivateDirectory {
    inner: NativeDirectory,
}

/// Ordinary output/source files retain native permissions, never secret-store floors.
pub struct OutputDirectory {
    inner: NativeDirectory,
}

impl PrivateDirectory {
    pub fn open(path: &Path) -> Result<Self> {
        Self::resolve(path, false)
    }
    pub fn ensure(path: &Path) -> Result<Self> {
        Self::resolve(path, true)
    }
    fn resolve(path: &Path, create: bool) -> Result<Self> {
        #[cfg(unix)]
        {
            Ok(Self {
                inner: unix::Directory::resolve(path, create, LeafPolicy::Private)?,
            })
        }
        #[cfg(windows)]
        {
            Ok(Self {
                inner: super::windows_files::Directory::resolve(path, create, LeafPolicy::Private)?,
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (path, create);
            Err(Error::protocol(
                "Private native files are unsupported on this platform",
            ))
        }
    }
    pub fn open_private(&self, name: &OsStr, create_new: bool) -> Result<File> {
        validate_name(name)?;
        self.inner.open_file(name, create_new, false)
    }
    /// Revalidate a retained private file without reopening or changing its permissions.
    pub fn verify_private(&self, file: &File) -> Result<()> {
        self.inner.verify_private(file)
    }
    /// Caller holds its persistent sidecar lock across staging and replacement.
    pub fn replace(&self, from: &OsStr, to: &OsStr) -> Result<()> {
        validate_name(from)?;
        validate_name(to)?;
        if from == to {
            return Err(Error::invalid("Replacement names must be different"));
        }
        self.inner.replace(from, to)
    }
    /// Remove only a verified owner-private regular file under this anchor.
    pub fn remove(&self, name: &OsStr) -> Result<()> {
        validate_name(name)?;
        self.inner.remove(name)
    }
    pub fn sync(&self) -> Result<DirectorySync> {
        self.inner.sync()
    }
}

impl OutputDirectory {
    pub fn open(path: &Path) -> Result<Self> {
        Ok(Self {
            inner: NativeDirectory::resolve(path, false, LeafPolicy::Output)?,
        })
    }
    pub fn ensure(path: &Path) -> Result<Self> {
        Ok(Self {
            inner: NativeDirectory::resolve(path, true, LeafPolicy::Output)?,
        })
    }
    pub fn open_file(&self, name: &OsStr, create_new: bool) -> Result<File> {
        validate_name(name)?;
        self.inner.open_file(name, create_new, false)
    }
    pub fn open_read(&self, name: &OsStr) -> Result<File> {
        validate_name(name)?;
        self.inner.open_file(name, false, true)
    }
    pub fn entries(&self, maximum: usize) -> Result<Vec<DirectoryEntry>> {
        self.inner.entries(maximum)
    }
    pub fn available_space(&self) -> Result<u64> {
        self.inner.available_space()
    }
    pub fn child(&self, name: &OsStr) -> Result<Self> {
        validate_name(name)?;
        Ok(Self {
            inner: self.inner.child(name)?,
        })
    }
    /// Caller owns the destination claim and explicit overwrite decision.
    pub fn replace(&self, from: &OsStr, to: &OsStr) -> Result<()> {
        self.publish(from, to, true)
    }
    /// Refuses even a newly appeared destination atomically when overwrite is false.
    pub fn publish(&self, from: &OsStr, to: &OsStr, overwrite: bool) -> Result<()> {
        validate_name(from)?;
        validate_name(to)?;
        if from == to {
            return Err(Error::invalid("Publication names must be different"));
        }
        self.inner.publish(from, to, overwrite)
    }
    pub fn remove(&self, name: &OsStr) -> Result<()> {
        validate_name(name)?;
        self.inner.remove(name)
    }
    /// Refuse cleanup if the basename now identifies a different object.
    /// Unix callers retain their claim lock; the OS has no inode-CAS unlink operation.
    pub fn remove_owned(&self, name: &OsStr, expected_identity: &str) -> Result<()> {
        validate_name(name)?;
        if expected_identity.is_empty() {
            return Err(Error::invalid(
                "Owned cleanup requires an expected file identity",
            ));
        }
        self.inner.remove_owned(name, expected_identity)
    }
    pub fn sync(&self) -> Result<DirectorySync> {
        self.inner.sync()
    }
}

/// Compare identities only while both file handles remain live; IDs can be reused after close.
pub fn file_identity(file: &File) -> Result<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = file.metadata()?;
        if !meta.is_file() {
            return Err(Error::invalid("File identity requires a regular file"));
        }
        Ok(format!("unix:{:016x}:{:016x}", meta.dev(), meta.ino()))
    }
    #[cfg(windows)]
    {
        super::windows_files::file_identity(file)
    }
}

pub fn ensure_private_dir(path: &Path) -> Result<PrivateDirectory> {
    PrivateDirectory::ensure(path)
}

pub(crate) fn validate_name(name: &OsStr) -> Result<()> {
    let path = Path::new(name);
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err(Error::invalid(
            "Private file name must be one normal path component",
        ));
    }
    if name
        .to_string_lossy()
        .chars()
        .any(|c| matches!(c, '\0' | ':' | '\\' | '/'))
    {
        return Err(Error::invalid(
            "Private file name contains a reserved separator",
        ));
    }
    Ok(())
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::{
        ffi::CString,
        io,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{ffi::OsStrExt, fs::MetadataExt},
        },
        path::PathBuf,
    };

    pub struct Directory {
        chain: Vec<File>,
        policy: LeafPolicy,
    }

    fn component(name: &OsStr) -> Result<CString> {
        CString::new(name.as_bytes()).map_err(|_| Error::invalid("Native path contains a NUL byte"))
    }
    fn fd_file(fd: libc::c_int) -> Result<File> {
        if fd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: successful open/openat returned a fresh owned descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    fn open_at(
        parent: &File,
        name: &CString,
        flags: libc::c_int,
        mode: libc::mode_t,
    ) -> Result<File> {
        // SAFETY: parent is live; name is a terminated component; mode supplied for create.
        fd_file(unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                mode,
            )
        })
    }
    fn verify(file: &File, directory: bool, policy: LeafPolicy) -> Result<()> {
        let meta = file.metadata()?;
        // SAFETY: geteuid has no pointer arguments or mutable state.
        let owner = unsafe { libc::geteuid() };
        let wanted = if directory { 0o700 } else { 0o600 };
        if (policy == LeafPolicy::Private
            && (meta.uid() != owner || meta.mode() & 0o7777 != wanted))
            || if directory {
                !meta.is_dir()
            } else {
                !meta.is_file() || meta.nlink() != 1
            }
        {
            return Err(Error::protocol(
                "Native object is not an owner-private regular file or directory",
            ));
        }
        Ok(())
    }

    impl Directory {
        pub fn resolve(path: &Path, create: bool, policy: LeafPolicy) -> Result<Self> {
            let absolute: PathBuf = if path.is_absolute() {
                path.to_path_buf()
            } else {
                std::env::current_dir()?.join(path)
            };
            let names: Vec<_> = absolute
                .components()
                .filter_map(|c| match c {
                    Component::RootDir | Component::CurDir => None,
                    _ => Some(c),
                })
                .collect();
            if (names.is_empty() && policy == LeafPolicy::Private)
                || names.iter().any(|c| !matches!(c, Component::Normal(_)))
            {
                return Err(Error::invalid(
                    "Private directory path cannot contain parent traversal",
                ));
            }
            let root =
                CString::new("/").map_err(|_| Error::protocol("Cannot encode native root"))?;
            // SAFETY: root string is terminated; read-only directory flags and mode are valid.
            let root = fd_file(unsafe {
                libc::open(
                    root.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            })?;
            let mut chain = vec![root];
            for part in names {
                let Component::Normal(name) = part else {
                    return Err(Error::invalid("Invalid directory component"));
                };
                let name = component(name)?;
                let parent = chain
                    .last()
                    .ok_or_else(|| Error::protocol("Missing native directory anchor"))?;
                let opened = open_at(parent, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0);
                let file = match opened {
                    Ok(file) => file,
                    Err(Error::Io(error)) if create && error.kind() == io::ErrorKind::NotFound => {
                        // SAFETY: parent is retained; one terminated component; mode private at creation.
                        let result =
                            unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
                        if result != 0
                            && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists
                        {
                            return Err(io::Error::last_os_error().into());
                        }
                        let file = open_at(parent, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
                        verify(&file, true, LeafPolicy::Private)?;
                        file
                    }
                    Err(error) => return Err(error),
                };
                chain.push(file);
            }
            let directory = Self { chain, policy };
            verify(directory.leaf()?, true, policy)?;
            Ok(directory)
        }
        fn leaf(&self) -> Result<&File> {
            self.chain
                .last()
                .ok_or_else(|| Error::protocol("Missing native directory anchor"))
        }
        pub fn verify_private(&self, file: &File) -> Result<()> {
            verify(self.leaf()?, true, LeafPolicy::Private)?;
            verify(file, false, LeafPolicy::Private)
        }
        pub fn open_file(&self, name: &OsStr, create_new: bool, read_only: bool) -> Result<File> {
            verify(self.leaf()?, true, self.policy)?;
            let flags = (if read_only {
                libc::O_RDONLY
            } else {
                libc::O_RDWR
            }) | libc::O_NONBLOCK
                | if create_new {
                    libc::O_CREAT | libc::O_EXCL
                } else {
                    0
                };
            let file = open_at(self.leaf()?, &component(name)?, flags, 0o600)?;
            verify(
                &file,
                false,
                if create_new {
                    LeafPolicy::Private
                } else {
                    self.policy
                },
            )?;
            Ok(file)
        }
        pub fn child(&self, name: &OsStr) -> Result<Self> {
            let file = open_at(
                self.leaf()?,
                &component(name)?,
                libc::O_RDONLY | libc::O_DIRECTORY,
                0,
            )?;
            verify(&file, true, self.policy)?;
            Ok(Self {
                chain: vec![file],
                policy: self.policy,
            })
        }
        pub fn available_space(&self) -> Result<u64> {
            super::super::disk_space::available(self.leaf()?)
        }
        pub fn entries(&self, maximum: usize) -> Result<Vec<DirectoryEntry>> {
            use std::os::fd::IntoRawFd;
            use std::os::unix::ffi::OsStringExt;
            let dot = component(OsStr::new("."))?;
            let file = open_at(self.leaf()?, &dot, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
            let descriptor = file.into_raw_fd();
            // SAFETY: fdopendir takes the fresh owned descriptor only on successful return.
            let pointer = unsafe { libc::fdopendir(descriptor) };
            if pointer.is_null() {
                let error = io::Error::last_os_error();
                // SAFETY: failed fdopendir left this unique descriptor owned by us.
                unsafe {
                    libc::close(descriptor);
                }
                return Err(error.into());
            }
            struct Stream(*mut libc::DIR);
            impl Drop for Stream {
                fn drop(&mut self) {
                    // SAFETY: successful fdopendir returned this uniquely owned stream.
                    unsafe {
                        libc::closedir(self.0);
                    }
                }
            }
            let stream = Stream(pointer);
            let mut entries = Vec::new();
            loop {
                #[cfg(target_os = "linux")]
                // SAFETY: libc exposes the current thread's errno cell.
                let errno = unsafe { libc::__errno_location() };
                #[cfg(target_os = "macos")]
                // SAFETY: libc exposes the current thread's errno cell.
                let errno = unsafe { libc::__error() };
                // SAFETY: retained stream, no concurrent consumer; errno is thread-local.
                let entry = unsafe {
                    *errno = 0;
                    libc::readdir(stream.0)
                };
                if entry.is_null() {
                    // SAFETY: this thread's errno remains valid through synchronous inspection.
                    if unsafe { *errno } != 0 {
                        return Err(io::Error::last_os_error().into());
                    }
                    break;
                }
                // SAFETY: readdir returned a terminated d_name, copied before the next read.
                let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
                if matches!(name.to_bytes(), b"." | b"..") {
                    continue;
                }
                if entries.len() >= maximum {
                    return Err(Error::invalid("Directory manifest exceeds its entry limit"));
                }
                let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
                // SAFETY: retained parent, terminated basename, valid stat output and nofollow flag.
                if unsafe {
                    libc::fstatat(
                        self.leaf()?.as_raw_fd(),
                        name.as_ptr(),
                        stat.as_mut_ptr(),
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                } != 0
                {
                    return Err(io::Error::last_os_error().into());
                }
                // SAFETY: successful fstatat initialized the stat output.
                let stat = unsafe { stat.assume_init() };
                let kind = match stat.st_mode & libc::S_IFMT {
                    libc::S_IFREG => EntryKind::File,
                    libc::S_IFDIR => EntryKind::Directory,
                    _ => EntryKind::Other,
                };
                entries.push(DirectoryEntry {
                    name: std::ffi::OsString::from_vec(name.to_bytes().to_vec()),
                    kind,
                    size: u64::try_from(stat.st_size)
                        .map_err(|_| Error::invalid("Directory entry has negative size"))?,
                });
            }
            entries.sort_by(|left, right| left.name.cmp(&right.name));
            Ok(entries)
        }
        fn check_identity(&self, name: &CString, file: &File) -> Result<()> {
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: output is correctly sized, descriptor/name live; nofollow final component.
            if unsafe {
                libc::fstatat(
                    self.leaf()?.as_raw_fd(),
                    name.as_ptr(),
                    stat.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            {
                return Err(io::Error::last_os_error().into());
            }
            // SAFETY: successful fstatat initialized all stat fields.
            let stat = unsafe { stat.assume_init() };
            let metadata = file.metadata()?;
            if stat.st_dev as u64 != metadata.dev() || stat.st_ino as u64 != metadata.ino() {
                return Err(Error::protocol(
                    "Private file identity changed before mutation",
                ));
            }
            Ok(())
        }
        pub fn replace(&self, from: &OsStr, to: &OsStr) -> Result<()> {
            self.publish(from, to, true)
        }
        pub fn publish(&self, from: &OsStr, to: &OsStr, overwrite: bool) -> Result<()> {
            let source = self.open_file(from, false, false)?;
            let destination = match self.open_file(to, false, true) {
                Ok(file) => Some(file),
                Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound => None,
                Err(error) => return Err(error),
            };
            let old = component(from)?;
            let new = component(to)?;
            self.check_identity(&old, &source)?;
            if let Some(file) = &destination {
                self.check_identity(&new, file)?;
                if file_identity(&source)? == file_identity(file)? {
                    return Err(Error::invalid(
                        "Publication source and destination name the same file",
                    ));
                }
            }
            source.sync_all()?;
            if !overwrite {
                // SAFETY: same held parent and normal names; flags0 never follows a source symlink.
                // linkat atomically refuses any destination that appeared after the caller's claim.
                if unsafe {
                    libc::linkat(
                        self.leaf()?.as_raw_fd(),
                        old.as_ptr(),
                        self.leaf()?.as_raw_fd(),
                        new.as_ptr(),
                        0,
                    )
                } != 0
                {
                    return Err(io::Error::last_os_error().into());
                }
                // Recheck the staging identity after the temporary two-link publication window.
                // ponytail: pathname cleanup needs caller claim lock; same-UID hostile mutation is not CAS.
                self.check_identity(&old, &source).and_then(|()| self.check_identity(&new, &source))
                    .map_err(|_| Error::protocol("Output was published but its identity changed; preserve both names and reconcile"))?;
                // SAFETY: verified staging name under retained parent; never roll back the published name.
                if unsafe { libc::unlinkat(self.leaf()?.as_raw_fd(), old.as_ptr(), 0) } != 0 {
                    return Err(Error::protocol(
                        "Output was published but staging cleanup failed; preserve both names and reconcile",
                    ));
                }
                return Ok(());
            }
            // SAFETY: both names are leaf components relative to the same retained private dir.
            if unsafe {
                libc::renameat(
                    self.leaf()?.as_raw_fd(),
                    old.as_ptr(),
                    self.leaf()?.as_raw_fd(),
                    new.as_ptr(),
                )
            } != 0
            {
                return Err(io::Error::last_os_error().into());
            }
            Ok(())
        }
        pub fn remove(&self, name: &OsStr) -> Result<()> {
            self.remove_checked(name, None)
        }
        pub fn remove_owned(&self, name: &OsStr, expected_identity: &str) -> Result<()> {
            self.remove_checked(name, Some(expected_identity))
        }
        fn remove_checked(&self, name: &OsStr, expected_identity: Option<&str>) -> Result<()> {
            let file = self.open_file(name, false, true)?;
            if let Some(expected) = expected_identity {
                if file_identity(&file)? != expected {
                    return Err(Error::protocol(
                        "Cleanup refused because the file identity changed",
                    ));
                }
            }
            let name = component(name)?;
            self.check_identity(&name, &file)?;
            // SAFETY: retained private dir, normal basename, file checked under caller lock.
            if unsafe { libc::unlinkat(self.leaf()?.as_raw_fd(), name.as_ptr(), 0) } != 0 {
                return Err(io::Error::last_os_error().into());
            }
            Ok(())
        }
        pub fn sync(&self) -> Result<DirectorySync> {
            verify(self.leaf()?, true, self.policy)?;
            match self.leaf()?.sync_all() {
                Ok(()) => Ok(DirectorySync::Synced),
                Err(error)
                    if matches!(error.raw_os_error(), Some(libc::EINVAL | libc::ENOTSUP)) =>
                {
                    Ok(DirectorySync::Unsupported)
                }
                Err(error) => Err(error.into()),
            }
        }
    }
}
