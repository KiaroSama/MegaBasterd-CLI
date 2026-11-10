//! Durable folder receipts and pre-send intents for an interrupted structured upload.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path, PathBuf},
    time::Duration,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{upload_operation, upload_tree::Manifest};
use crate::{
    error::{Error, Result},
    storage::files::{LockedStore, Store, random_id},
};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    binding: String,
    manifest: String,
    operation: String,
    folders: BTreeMap<PathBuf, String>,
    pending: Option<PathBuf>,
    finalized_files: BTreeMap<PathBuf, String>,
    completed: bool,
}

impl Saved {
    fn validate(&self) -> Result<()> {
        if !digest(&self.binding)
            || !digest(&self.manifest)
            || self.operation.len() != 32
            || !self.operation.bytes().all(|b| b.is_ascii_hexdigit())
            || self.folders.len() > 200_001
            || self.finalized_files.len() > 200_000
            || self.folders.iter().any(|(path, handle)| {
                !normal_relative(path)
                    || !valid_handle(handle)
                    || parent(path).is_some_and(|parent| !self.folders.contains_key(parent))
            })
            || self.folders.values().collect::<BTreeSet<_>>().len() != self.folders.len()
            || self.pending.as_ref().is_some_and(|path| {
                !normal_relative(path)
                    || self.folders.contains_key(path)
                    || parent(path).is_some_and(|parent| !self.folders.contains_key(parent))
            })
            || self.finalized_files.iter().any(|(path, handle)| {
                path.as_os_str().is_empty()
                    || !normal_relative(path)
                    || !valid_handle(handle)
                    || parent(path).is_none_or(|parent| !self.folders.contains_key(parent))
            })
            || (self.completed
                && (self.pending.is_some() || !self.folders.contains_key(Path::new(""))))
        {
            return Err(Error::Corrupt(
                "Upload tree journal has invalid receipt or completion data".into(),
            ));
        }
        Ok(())
    }
}

pub struct Journal {
    store: LockedStore,
    saved: Saved,
    directories: BTreeSet<PathBuf>,
    files: BTreeSet<PathBuf>,
    _operation: Option<LockedStore>,
}

impl Journal {
    pub fn open(
        directory: &Path,
        source: &Path,
        binding: &str,
        operation: Option<&str>,
        manifest: &Manifest,
    ) -> Result<Self> {
        if manifest.entries.len() > 200_000 {
            return Err(Error::invalid("Upload tree exceeds 200000 entries"));
        }
        let source = std::fs::canonicalize(source)?;
        let identity = serde_json::to_vec(&(&source, operation))?;
        let name = hex::encode(Sha256::digest(&identity));
        let fence = upload_operation::bind(directory, operation, &source, binding)?;
        let store = Store::new(directory.join(format!("tree-{name}.json")))
            .with_timeout(Duration::ZERO)
            .lock()?;
        let mut entries: Vec<_> = manifest
            .entries
            .iter()
            .map(|entry| (&entry.relative, entry.directory, entry.size))
            .collect();
        entries.sort();
        let fingerprint = hex::encode(Sha256::digest(serde_json::to_vec(&(
            manifest.bytes,
            manifest.skipped,
            entries,
        ))?));
        let mut directories = BTreeSet::from([PathBuf::new()]);
        let mut files = BTreeSet::new();
        let mut paths = BTreeSet::new();
        for entry in &manifest.entries {
            if !normal_relative(&entry.relative)
                || entry.relative.as_os_str().is_empty()
                || !paths.insert(entry.relative.clone())
            {
                return Err(Error::invalid(
                    "Upload manifest has a noncanonical or repeated relative path",
                ));
            }
            if entry.directory {
                directories.insert(entry.relative.clone());
            } else {
                files.insert(entry.relative.clone());
            }
        }
        if paths
            .iter()
            .any(|path| parent(path).is_none_or(|p| !directories.contains(p)))
        {
            return Err(Error::invalid(
                "Upload manifest is missing a parent directory",
            ));
        }
        let expected = hex::encode(Sha256::digest(binding.as_bytes()));
        let previous: Option<Saved> = store.load()?;
        if let Some(previous) = &previous {
            previous.validate()?;
        }
        // A durable completed tombstone permits a deliberate new unqueued invocation, without
        // unlinking recovery state and then mistaking a failed directory sync for transfer failure.
        let saved = match previous {
            Some(saved) if !saved.completed || operation.is_some() => saved,
            _ => Saved {
                binding: expected.clone(),
                manifest: fingerprint.clone(),
                operation: random_id()?,
                folders: BTreeMap::new(),
                pending: None,
                finalized_files: BTreeMap::new(),
                completed: false,
            },
        };
        if saved.binding != expected
            || saved.manifest != fingerprint
            || saved.folders.keys().any(|path| !directories.contains(path))
            || saved
                .pending
                .as_ref()
                .is_some_and(|path| !directories.contains(path))
            || saved
                .finalized_files
                .keys()
                .any(|path| !files.contains(path))
            || (saved.completed
                && (saved.folders.len() != directories.len()
                    || saved.finalized_files.len() != files.len()))
        {
            return Err(Error::Corrupt(
                "Upload tree account, target, manifest or saved folder receipt changed; original outcomes were preserved".into(),
            ));
        }
        if saved.pending.is_some() {
            return Err(Error::AmbiguousMutation("upload tree"));
        }
        store.save(&saved)?;
        Ok(Self {
            store,
            saved,
            directories,
            files,
            _operation: fence,
        })
    }

    pub fn operation(&self) -> &str {
        &self.saved.operation
    }

    pub fn folder_handle(&self, path: &Path) -> Result<Option<&str>> {
        if self.saved.pending.is_some() {
            return Err(Error::AmbiguousMutation("upload tree"));
        }
        if !self.directories.contains(path)
            || parent(path).is_some_and(|parent| !self.saved.folders.contains_key(parent))
        {
            return Err(Error::invalid(
                "Upload folder is absent from its manifest or has no confirmed parent",
            ));
        }
        Ok(self.saved.folders.get(path).map(String::as_str))
    }

    /// Adapter performs only a prepared mutation, never parent lookup or key generation.
    pub fn folder(
        &mut self,
        path: &Path,
        create: impl FnOnce() -> Result<String>,
    ) -> Result<String> {
        if let Some(handle) = self.folder_handle(path)? {
            return Ok(handle.to_owned());
        }
        self.saved.pending = Some(path.to_owned());
        self.store.save(&self.saved)?;
        let handle = match create() {
            Ok(handle)
                if valid_handle(&handle)
                    && !self.saved.folders.values().any(|old| old == &handle) =>
            {
                handle
            }
            Err(error @ Error::Mega { .. }) => {
                self.saved.pending = None;
                if self.store.save(&self.saved).is_err() {
                    self.saved.pending = Some(path.to_owned());
                    return Err(Error::AmbiguousMutation("upload tree"));
                }
                return Err(error);
            }
            Err(Error::Canceled) => return Err(Error::Canceled),
            Ok(_) | Err(_) => return Err(Error::AmbiguousMutation("upload tree")),
        };
        self.saved.folders.insert(path.to_owned(), handle.clone());
        self.saved.pending = None;
        if self.store.save(&self.saved).is_err() {
            self.saved.pending = Some(path.to_owned());
            return Err(Error::AmbiguousMutation("upload tree"));
        }
        Ok(handle)
    }

    /// Called only after Uploaded::finalize durably fenced the actual per-file side effects.
    pub fn file_finished(&mut self, path: &Path, handle: &str) -> Result<()> {
        if !self.files.contains(path)
            || !valid_handle(handle)
            || parent(path).is_none_or(|parent| !self.saved.folders.contains_key(parent))
        {
            return Err(Error::invalid(
                "Finalized upload has no matching file or confirmed parent",
            ));
        }
        if let Some(previous) = self.saved.finalized_files.get(path) {
            return if previous == handle {
                Ok(())
            } else {
                Err(Error::Corrupt(
                    "Finalized upload receipt handle changed".into(),
                ))
            };
        }
        self.saved
            .finalized_files
            .insert(path.to_owned(), handle.to_owned());
        if self.store.save(&self.saved).is_err() {
            self.saved.finalized_files.remove(path);
            return Err(Error::AmbiguousMutation("upload tree"));
        }
        Ok(())
    }

    /// A persistence error retains file/folder receipts; caller reports it as a nonfatal warning.
    pub fn acknowledge(mut self) -> Result<()> {
        if self.saved.pending.is_some() {
            return Err(Error::AmbiguousMutation("upload tree"));
        }
        if self.saved.folders.len() != self.directories.len()
            || self.saved.finalized_files.len() != self.files.len()
        {
            return Err(Error::invalid(
                "Upload tree has unfinished entries; journal was preserved",
            ));
        }
        self.saved.completed = true;
        self.store.save(&self.saved)
    }
}

fn normal_relative(path: &Path) -> bool {
    path.components()
        .all(|part| matches!(part, Component::Normal(_)))
}

fn parent(path: &Path) -> Option<&Path> {
    if path.as_os_str().is_empty() {
        None
    } else {
        path.parent()
    }
}

fn valid_handle(handle: &str) -> bool {
    handle.len() == 8
        && handle
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

fn digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}
