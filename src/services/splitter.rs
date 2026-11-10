// SPDX-License-Identifier: GPL-3.0-or-later
//! Source-compatible split naming and verified, alias-safe merge publication.
use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use sha1::{Digest, Sha1};

use super::local_crypto::{
    Progress, StagedOutput, open_source, progress, reject_aliases, require_unchanged,
};
use crate::{
    error::{Error, Result},
    platform::secure_files::{OutputDirectory, file_identity},
};

const BUFFER: usize = 1024 * 1024;
const MAX_PARTS: u64 = 10_000;

#[cfg(unix)]
fn prepare_merge_capacity(count: u64, parent: &Path, target: &Path) -> Result<()> {
    use std::sync::Mutex;

    static LIMIT_CHANGE: Mutex<()> = Mutex::new(());
    let _change = LIMIT_CHANGE.lock().map_err(crate::error::poisoned)?;
    let source_depth = std::path::absolute(parent)?.components().count() as u64;
    let target_depth = std::path::absolute(target)?.components().count() as u64;
    // Keep originals pinned; allow both anchored path chains and transient file handles.
    let needed = count
        .checked_add(source_depth)
        .and_then(|value| value.checked_add(target_depth))
        .and_then(|value| value.checked_add(64))
        .ok_or_else(|| Error::invalid("Merge descriptor budget overflows"))?;
    let refusal = || {
        Error::protocol(
            "Merge needs a higher open-file limit to keep inputs safe; use larger parts or raise the process limit before starting",
        )
    };
    let mut limits = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: the native output is exclusively borrowed and live during each syscall.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limits) } != 0 {
        return Err(refusal());
    }
    if limits.rlim_max < count {
        return Err(refusal());
    }
    // Headroom is an estimate, not a reason to reject a merge that fits the actual hard limit.
    let requested = needed.min(limits.rlim_max);
    if limits.rlim_cur >= requested {
        return Ok(());
    }
    limits.rlim_cur = requested;
    // SAFETY: only this process's soft limit changes; the hard limit is preserved.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limits) } != 0
        || unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limits) } != 0
        || limits.rlim_cur < requested
    {
        return Err(refusal());
    }
    Ok(())
}

#[derive(Debug)]
pub struct SplitResult {
    pub parts: Vec<PathBuf>,
    pub sha1: String,
    pub total_bytes: u64,
}

fn append(base: &OsStr, suffix: impl AsRef<OsStr>) -> OsString {
    let mut name = base.to_owned();
    name.push(suffix);
    name
}

fn ensure_available(
    directory: &OutputDirectory,
    name: &OsStr,
    inputs: &[&File],
    overwrite: bool,
) -> Result<()> {
    reject_aliases(directory, name, inputs)?;
    if !overwrite {
        match directory.open_read(name) {
            Ok(_) => {
                return Err(Error::invalid(
                    "Split output already exists; explicit overwrite permission is required",
                ));
            }
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

pub(crate) struct SplitLayout {
    pub parts: Vec<PathBuf>,
    pub checksum: PathBuf,
    parent: PathBuf,
    part_size: u64,
}

pub(crate) fn split_layout(
    source: &Path,
    total: u64,
    part_size_mb: u64,
    output_dir: Option<&Path>,
) -> Result<SplitLayout> {
    let part_size = part_size_mb
        .checked_mul(1024 * 1024)
        .filter(|size| *size > 0)
        .ok_or_else(|| Error::invalid("Part size must be positive and fit in u64 bytes"))?;
    if total == 0 {
        return Err(Error::invalid("Cannot split an empty file"));
    }
    let count = total.div_ceil(part_size);
    if count > MAX_PARTS {
        return Err(Error::invalid(
            "Split exceeds the 10000-part resource limit; use larger parts",
        ));
    }
    let base = source
        .file_name()
        .ok_or_else(|| Error::invalid("Source needs a filename"))?;
    let parent = output_dir
        .unwrap_or_else(|| {
            source
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."))
        })
        .to_owned();
    Ok(SplitLayout {
        parts: (1..=count)
            .map(|index| parent.join(append(base, format!(".part{index}-{count}"))))
            .collect(),
        checksum: parent.join(append(base, ".sha1")),
        parent,
        part_size,
    })
}

/// Parts are individually atomic, as in the source: a later failure preserves earlier complete parts.
pub fn split_file(
    source: &Path,
    part_size_mb: u64,
    output_dir: Option<&Path>,
    overwrite: bool,
    mut on_progress: Progress<'_>,
) -> Result<SplitResult> {
    let (_source_directory, mut input) = open_source(source)?;
    let metadata = input.metadata()?;
    let total = metadata.len();
    let SplitLayout {
        parts,
        checksum,
        parent,
        part_size,
    } = split_layout(source, total, part_size_mb, output_dir)?;
    let directory = OutputDirectory::ensure(&parent)?;
    // Preflight every output, not just the first part, before publishing anything.
    for path in &parts {
        ensure_available(
            &directory,
            path.file_name()
                .ok_or_else(|| Error::invalid("Part needs a filename"))?,
            &[&input],
            overwrite,
        )?;
    }
    ensure_available(
        &directory,
        checksum
            .file_name()
            .ok_or_else(|| Error::invalid("Checksum needs a filename"))?,
        &[&input],
        overwrite,
    )?;
    let mut hash = Sha1::new();
    let mut done = 0u64;
    let mut buffer = vec![0; BUFFER];
    for path in &parts {
        let mut output = StagedOutput::new(path, overwrite, &[&input])?;
        let mut remaining = part_size.min(total - done);
        while remaining != 0 {
            let length = remaining.min(BUFFER as u64) as usize;
            input.read_exact(&mut buffer[..length]).map_err(|error| {
                if error.kind() == std::io::ErrorKind::UnexpectedEof {
                    Error::integrity("Source changed while splitting")
                } else {
                    error.into()
                }
            })?;
            output.writer()?.write_all(&buffer[..length])?;
            hash.update(&buffer[..length]);
            remaining -= length as u64;
            done += length as u64;
            progress(&mut on_progress, done, total)?;
        }
        require_unchanged(&input, &metadata)?;
        output.commit(&[&input])?;
    }
    if input.read(&mut [0])? != 0 {
        return Err(Error::integrity("Source grew while splitting"));
    }
    require_unchanged(&input, &metadata)?;
    let digest = hex::encode(hash.finalize());
    let mut output = StagedOutput::new(&checksum, overwrite, &[&input])?;
    writeln!(output.writer()?, "{digest}")?;
    output.commit(&[&input])?;
    Ok(SplitResult {
        parts,
        sha1: digest,
        total_bytes: total,
    })
}

fn parse_part(path: &Path) -> Result<(&str, u64)> {
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| Error::invalid("Part filename is not valid UTF-8"))?;
    let (base, tail) = name
        .rsplit_once(".part")
        .ok_or_else(|| Error::invalid("Filename must match *.partN-total"))?;
    let (index, count) = tail
        .split_once('-')
        .ok_or_else(|| Error::invalid("Filename must match *.partN-total"))?;
    let parse = |value: &str| -> Result<u64> {
        if value.is_empty() {
            return Err(Error::invalid("Part counts must be decimal integers"));
        }
        value.chars().try_fold(0u64, |number, character| {
            let digit = crate::transfers::selection::decimal(character)
                .ok_or_else(|| Error::invalid("Part counts must be decimal integers"))?;
            number
                .checked_mul(10)
                .and_then(|n| n.checked_add(u64::from(digit)))
                .ok_or_else(|| Error::invalid("Part count exceeds its resource limit"))
        })
    };
    let (index, count) = (parse(index)?, parse(count)?);
    if base.is_empty() || count == 0 || count > MAX_PARTS || index == 0 || index > count {
        return Err(Error::invalid(
            "Part index/total is invalid or exceeds 10000 parts",
        ));
    }
    Ok((base, count))
}

pub(crate) fn merge_destination(any_part: &Path, output: Option<&Path>) -> Result<PathBuf> {
    let (base, _) = parse_part(any_part)?;
    Ok(output.map(Path::to_owned).unwrap_or_else(|| {
        any_part
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .join(base)
    }))
}

fn expected_sha1(file: &mut File) -> Result<String> {
    if file.metadata()?.len() > 4096 {
        return Err(Error::invalid("SHA-1 sidecar exceeds its size limit"));
    }
    let mut bytes = Vec::new();
    file.take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 || !bytes.is_ascii() {
        return Err(Error::invalid("Invalid ASCII SHA-1 sidecar"));
    }
    let text =
        std::str::from_utf8(&bytes).map_err(|_| Error::invalid("Invalid ASCII SHA-1 sidecar"))?;
    let first = text
        .split_whitespace()
        .next()
        .ok_or_else(|| Error::invalid("Empty SHA-1 sidecar"))?;
    if first.len() != 40 || !first.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::invalid("Invalid SHA-1 checksum"));
    }
    Ok(first.to_ascii_lowercase())
}

fn reread_hash(file: &mut File, total: u64) -> Result<String> {
    file.flush()?;
    file.seek(SeekFrom::Start(0))?;
    let mut hash = Sha1::new();
    let mut buffer = vec![0; BUFFER];
    let mut remaining = total;
    while remaining != 0 {
        let length = remaining.min(BUFFER as u64) as usize;
        file.read_exact(&mut buffer[..length])?;
        hash.update(&buffer[..length]);
        remaining -= length as u64;
    }
    if file.read(&mut [0])? != 0 {
        return Err(Error::integrity(
            "Merged staging output has unexpected trailing bytes",
        ));
    }
    Ok(hex::encode(hash.finalize()))
}

/// `delete_parts` is explicit caller authorization. No source is removed on a failed merge.
pub fn merge_parts(
    any_part: &Path,
    output: Option<&Path>,
    verify_sha1: bool,
    delete_parts: bool,
    overwrite: bool,
    mut on_progress: Progress<'_>,
) -> Result<PathBuf> {
    let (base, count) = parse_part(any_part)?;
    let parent = any_part
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let target = merge_destination(any_part, output)?;
    #[cfg(unix)]
    prepare_merge_capacity(count, parent, &target)?;
    let directory = OutputDirectory::open(parent)?;
    let names: Vec<OsString> = (1..=count)
        .map(|index| OsString::from(format!("{base}.part{index}-{count}")))
        .collect();
    let mut parts = Vec::with_capacity(names.len());
    let mut snapshots = Vec::with_capacity(names.len());
    let mut total = 0u64;
    for name in &names {
        let file = directory.open_read(name)?;
        let metadata = file.metadata()?;
        total = total
            .checked_add(metadata.len())
            .ok_or_else(|| Error::invalid("Merged length exceeds u64"))?;
        snapshots.push((file_identity(&file)?, metadata));
        parts.push(file);
    }
    let checksum_name = OsString::from(format!("{base}.sha1"));
    let mut checksum = match directory.open_read(&checksum_name) {
        Ok(file) => Some(file),
        Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    let checksum_identity = checksum.as_ref().map(file_identity).transpose()?;
    let checksum_metadata = checksum.as_ref().map(File::metadata).transpose()?;
    let expected = if verify_sha1 {
        checksum.as_mut().map(expected_sha1).transpose()?
    } else {
        None
    };
    let refs: Vec<&File> = parts.iter().chain(checksum.iter()).collect();
    let mut stage = StagedOutput::new(&target, overwrite, &refs)?;
    let mut hash = Sha1::new();
    let mut done = 0u64;
    let mut buffer = vec![0; BUFFER];
    for (mut part, (_, metadata)) in parts.iter().zip(&snapshots) {
        let mut remaining = metadata.len();
        while remaining != 0 {
            let length = remaining.min(BUFFER as u64) as usize;
            part.read_exact(&mut buffer[..length]).map_err(|error| {
                if error.kind() == std::io::ErrorKind::UnexpectedEof {
                    Error::integrity("Input part changed while merging")
                } else {
                    error.into()
                }
            })?;
            stage.writer()?.write_all(&buffer[..length])?;
            hash.update(&buffer[..length]);
            remaining -= length as u64;
            done += length as u64;
            progress(&mut on_progress, done, total)?;
        }
        if part.read(&mut [0])? != 0 {
            return Err(Error::integrity("Input part grew while merging"));
        }
    }
    let written_hash = hex::encode(hash.finalize());
    // Pass2 proves the output bytes on disk, not just the buffers we asked the OS to write.
    let disk_hash = reread_hash(stage.writer()?, total)?;
    if disk_hash != written_hash
        || expected
            .as_ref()
            .is_some_and(|expected| *expected != disk_hash)
    {
        return Err(Error::integrity(
            "SHA-1 mismatch; original destination and parts were preserved",
        ));
    }
    for (file, (identity, metadata)) in parts.iter().zip(&snapshots) {
        require_unchanged(file, metadata)?;
        if file_identity(file)? != *identity {
            return Err(Error::integrity(
                "Input part changed during merge verification",
            ));
        }
    }
    if let (Some(file), Some(metadata)) = (&checksum, &checksum_metadata) {
        require_unchanged(file, metadata)?;
    }
    let target = stage.commit(&refs)?;
    if delete_parts {
        // Do not erase inputs changed after verification, even if they still have the
        // same file ID. Keep all originals pinned until the last pre-delete check.
        for (file, (_, metadata)) in parts.iter().zip(&snapshots) {
            require_unchanged(file, metadata)?;
        }
        if let (Some(file), Some(metadata)) = (&checksum, &checksum_metadata) {
            require_unchanged(file, metadata)?;
        }
        drop(refs);
        for ((name, file), (identity, _)) in names.iter().zip(parts.into_iter()).zip(snapshots) {
            drop(file);
            remove_original(&directory, name, &identity)?;
        }
        drop(checksum);
        if let Some(identity) = checksum_identity {
            remove_original(&directory, &checksum_name, &identity)?;
        }
        directory.sync()?;
    }
    Ok(target)
}

fn remove_original(directory: &OutputDirectory, name: &OsStr, identity: &str) -> Result<()> {
    let file = directory.open_read(name)?;
    if file_identity(&file)? != identity {
        return Err(Error::integrity(
            "Merged output is safe, but a part was replaced; refusing deletion",
        ));
    }
    drop(file);
    directory.remove_owned(name, identity).map_err(|_| {
        Error::protocol("Merged output is safe, but an authorized part deletion failed")
    })
}
