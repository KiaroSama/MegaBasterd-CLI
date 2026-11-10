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
