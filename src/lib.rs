pub mod cli;
pub mod crypto;
pub mod error;
pub mod platform;
pub mod protocol;
pub mod services;
pub mod storage;
pub mod terminal;
pub mod transfers;
#[cfg(test)]
extern crate self as megabasterd_cli;
#[cfg(test)]
#[path = "../tests/common/private_tempfile.rs"]
pub(crate) mod test_support;
// Loaded once here: per-module #[path] includes compile it twice (clippy::duplicate_mod).
#[cfg(all(test, windows))]
#[allow(dead_code, clippy::unwrap_used)] // Test-only fixture; library tests use part of it.
#[path = "../tests/common/windows_log_acl.rs"]
pub(crate) mod windows_log_acl;
