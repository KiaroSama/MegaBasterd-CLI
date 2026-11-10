use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::{
    api::{Api, field, string},
    links::{LinkType, ParsedLink, require_link_key},
    nodes::Tree,
};
use crate::crypto::wire;
use crate::error::{Error, Result};
use crate::transfers::planner::{Job, plan};

#[derive(Clone)]
#[allow(
    clippy::large_enum_variant,
    reason = "One metadata value per transfer; keep owned secret-bearing state together."
)]
pub enum DownloadSource {
    Public,
    Folder,
    Megacrypter {
        link: ParsedLink,
        info: super::containers::MegaCrypterInfo,
    },
}

#[derive(Clone)]
pub struct FileInfo {
    pub name: String,
    pub size: u64,
    pub raw_key: Zeroizing<Vec<u8>>,
    pub url: String,
    pub handle: String,
    pub public_id: String,
    pub source: DownloadSource,
}

impl FileInfo {
    pub fn source_identity(&self) -> Result<String> {
        Ok(match &self.source {
            DownloadSource::Public => serde_json::to_string(&("public", &self.public_id))?,
            DownloadSource::Folder => {
                serde_json::to_string(&("folder", &self.public_id, &self.handle))?
            }
            DownloadSource::Megacrypter { link, .. } => {
                serde_json::to_string(&("megacrypter", &link.crypter_server, &link.crypter_token))?
            }
        })
    }

    pub fn megacrypter(
        link: ParsedLink,
        info: super::containers::MegaCrypterInfo,
        url: String,
    ) -> Result<Self> {
        if link.kind != LinkType::Megacrypter {
            return Err(Error::invalid("Expected a MegaCrypter download source"));
        }
        let size = info
            .size
            .ok_or_else(|| Error::protocol("MegaCrypter metadata has no file size"))?;
        crate::crypto::chunks::chunk_count(size)?;
        let mut key_link = ParsedLink::new(LinkType::File);
        key_link.key = info.key.clone();
        let raw_key = require_link_key(&key_link)?;
        let endpoint =
            url::Url::parse(&url).map_err(|_| Error::protocol("MegaCrypter CDN URL is invalid"))?;
        super::transport::safe_target(&endpoint)?;
        let handle = link
            .crypter_token
            .clone()
            .ok_or_else(|| Error::invalid("MegaCrypter token is absent"))?;
        let name = info.name.clone().unwrap_or_else(|| handle.clone());
        Ok(Self {
            name,
            size,
            raw_key,
            url,
            handle,
            public_id: String::new(),
            source: DownloadSource::Megacrypter { link, info },
        })
    }
}

pub fn download_ticket(handle: &str, private: bool) -> Value {
    let mut ticket = json!({"a":"g", "g":1, "ssl":2});
    ticket[if private { "n" } else { "p" }] = json!(handle);
    ticket
}

pub fn refresh(api: &mut Api, info: &FileInfo) -> Result<String> {
    let result = match &info.source {
        DownloadSource::Public => api.request(download_ticket(&info.public_id, false), &[])?,
        DownloadSource::Folder => api.request(
            download_ticket(&info.handle, true),
            &[("n", &info.public_id)],
        )?,
        DownloadSource::Megacrypter { link, info } => {
            let accounts = Default::default();
            let resolver = super::link_services::Resolver {
                transport: &api.transport,
                password: None,
                elc_user: None,
                elc_api_key: None,
                elc_accounts: &accounts,
            };
            return resolver.megacrypter_download(link, info, None);
        }
    };
    let size = field(&result, "s")?
        .as_u64()
        .ok_or_else(|| Error::protocol("Download size is not an integer"))?;
    if size != info.size {
        return Err(Error::integrity(
            "Refreshed CDN metadata changed the file size",
        ));
    }
    Ok(string(&result, "g")?.to_owned())
}

pub fn file(api: &mut Api, link: &ParsedLink) -> Result<FileInfo> {
    if link.kind != LinkType::File {
        return Err(Error::invalid("Expected a public file link"));
    }
    let raw_key = require_link_key(link)?;
    let key = crate::crypto::keys::unpack_file_key(&wire::bytes_to_a32(&raw_key))?;
    let result = api.request(download_ticket(&link.public_id, false), &[])?;
    let size = field(&result, "s")?
        .as_u64()
        .ok_or_else(|| Error::protocol("Download size is not an integer"))?;
    crate::crypto::chunks::chunk_count(size)?;
    let fallback = || {
        link.subpath
            .as_deref()
            .unwrap_or(&link.public_id)
            .to_owned()
    };
    let name = match result.get("at") {
        None | Some(Value::Null) => fallback(),
        Some(Value::String(attributes)) if attributes.is_empty() => fallback(),
        Some(Value::String(attributes)) => {
            let attrs = wire::decrypt_attributes(
                &wire::b64_url_decode(attributes)?,
                key.aes_key.as_slice(),
            )?;
            match attrs.get("n") {
                None | Some(Value::Null) => fallback(),
                Some(Value::String(name)) if name.is_empty() => fallback(),
                Some(Value::String(name)) => name.clone(),
                _ => return Err(Error::protocol("File attribute name is not a string")),
            }
        }
        _ => return Err(Error::protocol("File attributes are not a string")),
    };
    Ok(FileInfo {
        name,
        size,
        raw_key,
        url: string(&result, "g")?.to_owned(),
        handle: link.public_id.clone(),
        public_id: link.public_id.clone(),
        source: DownloadSource::Public,
    })
}

pub fn folder(api: &mut Api, link: &ParsedLink) -> Result<(Tree, Vec<Job>)> {
    if !matches!(
        link.kind,
        LinkType::Folder | LinkType::FolderInFolder | LinkType::FileInFolder
    ) {
        return Err(Error::invalid("Expected a public folder share"));
    }
    let key = require_link_key(link)?;
    let listing = api.request(
        json!({"a":"f","c":1,"r":1,"ca":1}),
        &[("n", &link.public_id)],
    )?;
    let tree = Tree::decode(&listing, &key)?;
    let jobs = plan(&tree, link.subpath.as_deref())?;
    Ok((tree, jobs))
}

pub fn folder_file(api: &mut Api, link: &ParsedLink, job: &Job) -> Result<FileInfo> {
    let key = Zeroizing::new(job.node.key()?.to_vec());
    let mut info = FileInfo {
        name: job.node.name.clone(),
        size: job.node.size,
        raw_key: key,
        url: String::new(),
        handle: job.node.handle.clone(),
        public_id: link.public_id.clone(),
        source: DownloadSource::Folder,
    };
    info.url = refresh(api, &info)?;
    Ok(info)
}

#[cfg(test)]
#[path = "metadata_peer_tests.rs"]
mod peer_tests;
