//! Compatibility checksums. MD5 is for identifying existing files, never authentication.
use crate::{error::Result, services::local_crypto::open_source};
use md5::{Digest, Md5};
use std::{io::Read, path::Path};

pub fn file_md5(path: &Path) -> Result<String> {
    let (_directory, mut file) = open_source(path)?;
    let mut digest = Md5::new();
    let mut block = [0u8; 64 * 1024];
    loop {
        let count = file.read(&mut block)?;
        if count == 0 {
            break;
        }
        digest.update(&block[..count]);
    }
    Ok(hex::encode(digest.finalize()))
}
