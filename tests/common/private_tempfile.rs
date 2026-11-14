//! Private fixture roots on Windows; Unix tempfile already creates mode 0700 roots.
#![allow(dead_code)]
pub use ::tempfile::TempDir;
use std::{ffi::OsStr, io, path::Path};

fn private(directory: TempDir) -> io::Result<TempDir> {
    #[cfg(windows)]
    {
        // Recreate only the newly owned, empty fixture directory through the native
        // creator so tests never depend on the runner's inherited/default DACL.
        std::fs::remove_dir(directory.path())?;
        drop(
            ::megabasterd_cli::platform::secure_files::PrivateDirectory::ensure(directory.path())
                .map_err(|error| io::Error::other(error.to_string()))?,
        );
    }
    Ok(directory)
}

pub fn tempdir() -> io::Result<TempDir> {
    #[cfg(target_os = "macos")]
    // Darwin's default /var/... temporary root aliases /private/var. Create
    // owned fixtures beneath its canonical path, leaving nofollow policy intact.
    {
        private(::tempfile::tempdir_in(std::fs::canonicalize(
            std::env::temp_dir(),
        )?)?)
    }
    #[cfg(not(target_os = "macos"))]
    {
        private(::tempfile::tempdir()?)
    }
}
pub fn tempdir_in(path: impl AsRef<Path>) -> io::Result<TempDir> {
    private(::tempfile::tempdir_in(path)?)
}

pub struct Builder<'a, 'b>(::tempfile::Builder<'a, 'b>);
impl Default for Builder<'_, '_> {
    fn default() -> Self {
        Self::new()
    }
}
impl<'a, 'b> Builder<'a, 'b> {
    pub fn new() -> Self {
        Self(::tempfile::Builder::new())
    }
    pub fn prefix<S: AsRef<OsStr> + ?Sized>(&mut self, prefix: &'a S) -> &mut Self {
        self.0.prefix(prefix);
        self
    }
    pub fn suffix<S: AsRef<OsStr> + ?Sized>(&mut self, suffix: &'b S) -> &mut Self {
        self.0.suffix(suffix);
        self
    }
    pub fn tempdir(&self) -> io::Result<TempDir> {
        #[cfg(target_os = "macos")]
        {
            private(
                self.0
                    .tempdir_in(std::fs::canonicalize(std::env::temp_dir())?)?,
            )
        }
        #[cfg(not(target_os = "macos"))]
        {
            private(self.0.tempdir()?)
        }
    }
    pub fn tempdir_in(&self, path: impl AsRef<Path>) -> io::Result<TempDir> {
        private(self.0.tempdir_in(path)?)
    }
}
