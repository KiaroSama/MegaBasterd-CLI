use std::path::{Path, PathBuf};

use super::{
    control::Control,
    download::DownloadOptions,
    planner::{Filter, Job},
    quota,
};
use crate::error::{Error, Result};
use crate::protocol::{
    api::Api,
    links::ParsedLink,
    metadata::{self, FileInfo},
};

pub fn select_jobs(
    jobs: Vec<Job>,
    include: &[String],
    exclude: &[String],
    selected: Option<&[usize]>,
) -> Result<Vec<Job>> {
    let filtering = include.iter().chain(exclude).any(|value| !value.is_empty());
    let filter = Filter::new(include, exclude)?;
    let jobs: Vec<_> = jobs.into_iter().filter(|job| filter.accepts(job)).collect();
    if filtering && jobs.is_empty() {
        return Err(Error::transfer(Error::protocol(
            "File selection matched no files in the folder share",
        )));
    }
    match selected {
        None => Ok(jobs),
        Some(indices) => {
            if indices
                .iter()
                .any(|index| *index == 0 || *index > jobs.len())
            {
                return Err(Error::invalid(
                    "Selected file index is outside the filtered manifest",
                ));
            }
            Ok(jobs
                .into_iter()
                .enumerate()
                .filter(|(index, _)| indices.contains(&(index + 1)))
                .map(|(_, job)| job)
                .collect())
        }
    }
}

pub enum Source {
    File(FileInfo),
    FolderFile { link: ParsedLink, job: Job },
}

pub struct TransferJob {
    pub source: Source,
    pub destination: PathBuf,
    pub item: usize,
}

impl TransferJob {
    pub fn size(&self) -> u64 {
        match &self.source {
            Source::File(info) => info.size,
            Source::FolderFile { job, .. } => job.node.size,
        }
    }
    pub fn name(&self) -> &str {
        match &self.source {
            Source::File(info) => &info.name,
            Source::FolderFile { job, .. } => &job.node.name,
        }
    }
    pub fn resolve(
        &self,
        api: &mut Api,
        options: &DownloadOptions,
        control: &Control,
    ) -> Result<FileInfo> {
        match &self.source {
            Source::File(info) => Ok(info.clone()),
            Source::FolderFile { link, job } => {
                let routing = api.transport.routing.clone();
                quota::retry(options, &routing, control, || {
                    metadata::folder_file(api, link, job)
                })
            }
        }
    }
}

pub fn file_destination(root: &Path, info: &FileInfo, rename: Option<&str>) -> PathBuf {
    root.join(super::planner::filename(rename.unwrap_or(&info.name)))
}
