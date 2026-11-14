use std::env;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

#[derive(Clone)]
pub struct Paths {
    pub root: PathBuf,
    pub user: PathBuf,
    pub logs: PathBuf,
    pub output: PathBuf,
}

fn absolute(value: PathBuf) -> Result<PathBuf> {
    if value.is_absolute() {
        Ok(value)
    } else {
        Ok(env::current_dir()?.join(value))
    }
}

impl Paths {
    pub fn discover() -> Result<Self> {
        let root = match env::var_os("MEGABASTERD_PROJECT_ROOT") {
            Some(path) if !path.is_empty() => absolute(PathBuf::from(path))?,
            _ => env::current_exe()?
                .parent()
                .ok_or_else(|| Error::invalid("Binary has no parent directory"))?
                .to_owned(),
        };
        // A versioned child prevents the fresh Rust format from touching Python-era stores.
        let user = match env::var_os("MEGABASTERD_USER_DIR") {
            Some(path) if !path.is_empty() => absolute(PathBuf::from(path))?.join("native-v2"),
            _ => root.join("User/native-v2"),
        };
        let logs = match env::var_os("MEGABASTERD_LOG_DIR") {
            Some(path) if !path.is_empty() => absolute(PathBuf::from(path))?,
            _ => user.join("Logs"),
        };
        Ok(Self {
            output: root.join("Output"),
            root,
            user,
            logs,
        })
    }

    pub fn config(&self) -> PathBuf {
        self.user.join("Config/config.json")
    }
    pub fn accounts(&self) -> PathBuf {
        self.user.join("Data/accounts.json")
    }
    pub fn queue(&self) -> PathBuf {
        self.user.join("Data/queue.json")
    }
    pub fn proxies(&self) -> PathBuf {
        self.user.join("Data/proxies.json")
    }
    pub fn sessions(&self) -> PathBuf {
        self.user.join("Data/sessions")
    }

    pub fn session(&self, account: &str) -> PathBuf {
        use sha2::{Digest, Sha256};
        self.sessions().join(format!(
            "{}.json",
            hex::encode(Sha256::digest(account.to_lowercase().as_bytes()))
        ))
    }

    pub fn download<'a>(&'a self, configured: &'a str) -> &'a Path {
        if configured.is_empty() {
            &self.output
        } else {
            Path::new(configured)
        }
    }
}
