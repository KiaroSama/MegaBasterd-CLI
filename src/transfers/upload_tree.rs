use std::path::{Path, PathBuf};

use super::control::Control;
use crate::error::{Error, Result};
use crate::platform::secure_files::{EntryKind, OutputDirectory};

const MAX_ENTRIES: usize = 200_000;
const MAX_DEPTH: usize = 256;

#[derive(Clone)]
pub struct Entry {
    pub relative: PathBuf,
    pub directory: bool,
    pub size: u64,
}

pub struct Manifest {
    pub entries: Vec<Entry>,
    pub bytes: u64,
    pub skipped: usize,
    _root: OutputDirectory,
}

pub fn walk(root: &Path, control: &Control) -> Result<Manifest> {
    let anchor = OutputDirectory::open(root)?;
    let mut result = Manifest {
        entries: Vec::new(),
        bytes: 0,
        skipped: 0,
        _root: anchor,
    };
    collect(
        &result._root,
        Path::new(""),
        0,
        control,
        &mut result.entries,
        &mut result.bytes,
        &mut result.skipped,
    )?;
    Ok(result)
}

fn collect(
    directory: &OutputDirectory,
    relative: &Path,
    depth: usize,
    control: &Control,
    entries: &mut Vec<Entry>,
    bytes: &mut u64,
    skipped: &mut usize,
) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(Error::invalid("Upload directory exceeds 256 levels"));
    }
    control.checkpoint()?;
    for entry in directory.entries(MAX_ENTRIES.saturating_sub(entries.len()))? {
        control.checkpoint()?;
        if entries
            .len()
            .checked_add(*skipped)
            .is_none_or(|count| count >= MAX_ENTRIES)
        {
            return Err(Error::invalid("Upload tree exceeds 200000 entries"));
        }
        let path = relative.join(&entry.name);
        match entry.kind {
            EntryKind::Other => {
                *skipped += 1;
            }
            EntryKind::File => {
                // The real source handle still has to pass native nofollow/hardlink checks at transfer time.
                let file = directory.open_read(&entry.name)?;
                let size = file.metadata()?.len();
                *bytes = bytes
                    .checked_add(size)
                    .ok_or_else(|| Error::invalid("Upload tree size overflows"))?;
                entries.push(Entry {
                    relative: path,
                    directory: false,
                    size,
                });
            }
            EntryKind::Directory => {
                let child = directory.child(&entry.name)?;
                entries.push(Entry {
                    relative: path.clone(),
                    directory: true,
                    size: 0,
                });
                collect(&child, &path, depth + 1, control, entries, bytes, skipped)?;
            }
        }
    }
    Ok(())
}
