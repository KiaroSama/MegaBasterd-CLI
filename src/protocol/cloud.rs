use rand::{TryRng, rngs::SysRng};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::{
    api::{Api, string},
    auth::Session,
    nodes::{Node, Tree},
};
use crate::crypto::{keys, wire};
use crate::error::{Error, Result};

#[derive(Debug, Default)]
pub struct BatchOutcome {
    pub completed: Vec<String>,
    pub rejections: Vec<Error>,
}

impl BatchOutcome {
    pub fn require_complete(&self, operation: &str) -> Result<()> {
        if let Some(first) = self.rejections.first() {
            return Err(Error::protocol(format!(
                "{operation} incomplete: completed={} failed={}; successful changes were preserved. First rejection: {first}",
                self.completed.len(),
                self.rejections.len()
            )));
        }
        Ok(())
    }
}

pub(crate) struct FolderCreation(Value);

pub struct Cloud {
    pub api: Api,
    pub session: Session,
    cached: Option<Tree>,
}

pub fn first_handle(value: &Value) -> Result<String> {
    let node = value
        .get("f")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .ok_or_else(|| Error::protocol("MEGA mutation returned no registered node"))?;
    let handle = string(node, "h")?;
    if handle.is_empty() {
        return Err(Error::protocol("MEGA registered node has no handle"));
    }
    Ok(handle.to_owned())
}

impl Cloud {
    pub fn new(mut api: Api, session: Session) -> Self {
        api.set_session(&session.sid);
        Self {
            api,
            session,
            cached: None,
        }
    }

    pub fn tree(&mut self) -> Result<&Tree> {
        if self.cached.is_none() {
            let listing = self.api.request(json!({"a": "f", "c": 1}), &[])?;
            self.cached = Some(Tree::decode_account(&listing, &self.session.master_key)?);
        }
        self.cached
            .as_ref()
            .ok_or_else(|| Error::protocol("Cloud tree initialization failed"))
    }

    pub fn find(&mut self, target: &str) -> Result<Node> {
        Ok(self.tree()?.find(target)?.clone())
    }
    pub fn root(&mut self) -> Result<String> {
        Ok(self.tree()?.root(2)?.handle.clone())
    }
    pub fn invalidate(&mut self) {
        self.cached = None;
    }

    pub fn mkdir(&mut self, name: &str, parent: Option<&str>) -> Result<String> {
        let prepared = self.prepare_mkdir(name, parent)?;
        self.create_folder(prepared)
    }

    pub(crate) fn prepare_mkdir(
        &mut self,
        name: &str,
        parent: Option<&str>,
    ) -> Result<FolderCreation> {
        if name.is_empty() || name.chars().any(char::is_control) {
            return Err(Error::invalid(
                "Folder name is empty or contains control characters",
            ));
        }
        let parent = match parent {
            Some(target) => {
                let node = self.find(target)?;
                if !node.is_folder() {
                    return Err(Error::invalid("Folder parent must be a cloud folder"));
                }
                node.handle
            }
            None => self.root()?,
        };
        let mut key = Zeroizing::new([0u8; 16]);
        SysRng
            .try_fill_bytes(&mut *key)
            .map_err(|_| Error::protocol("Operating-system randomness is unavailable"))?;
        let attrs = wire::encrypt_attributes(&json!({"n": name}), &*key)?;
        let wrapped = wire::aes_key_wrap_encrypt(&*key, &self.session.master_key)?;
        Ok(FolderCreation(
            json!({"a": "p", "t": parent, "n": [{"h": "xxxxxxxx", "t": 1,
            "a": wire::b64_url_encode(&attrs), "k": wire::b64_url_encode(&wrapped)}]}),
        ))
    }

    pub(crate) fn create_folder(&mut self, prepared: FolderCreation) -> Result<String> {
        let result = self.api.request(prepared.0, &[]);
        self.invalidate();
        first_handle(&result?)
    }

    pub fn delete(&mut self, target: &str) -> Result<()> {
        let node = self.find(target)?;
        if node.node_type >= 2 {
            return Err(Error::invalid("A cloud system root cannot be deleted"));
        }
        self.api.request(json!({"a": "d", "n": node.handle}), &[])?;
        self.invalidate();
        Ok(())
    }

    pub fn move_node(&mut self, source: &str, target: &str) -> Result<()> {
        let source = self.find(source)?;
        let target = self.find(target)?;
        if !target.is_folder() || source.node_type >= 2 {
            return Err(Error::invalid(
                "Move needs a user node and a destination folder",
            ));
        }
        if self
            .tree()?
            .descendants(&source.handle)?
            .iter()
            .any(|n| n.handle == target.handle)
        {
            return Err(Error::invalid(
                "Cannot move a folder into its own descendants",
            ));
        }
        self.api.request(
            json!({"a": "m", "n": source.handle, "t": target.handle}),
            &[],
        )?;
        self.invalidate();
        Ok(())
    }

    pub fn rename(&mut self, target: &str, name: &str) -> Result<()> {
        if name.is_empty() || name.chars().any(char::is_control) {
            return Err(Error::invalid(
                "Node name is empty or contains control characters",
            ));
        }
        let node = self.find(target)?;
        let mut attrs = node.attrs.clone();
        attrs
            .as_object_mut()
            .ok_or_else(|| Error::protocol("Node attributes are invalid"))?
            .insert("n".into(), json!(name));
        let encrypted = wire::encrypt_attributes(&attrs, &node.attribute_key()?)?;
        let wrapped = wire::aes_key_wrap_encrypt(node.key()?, &self.session.master_key)?;
        self.api.request(
            json!({"a": "a", "n": node.handle, "attr": wire::b64_url_encode(&encrypted),
            "key": wire::b64_url_encode(&wrapped)}),
            &[],
        )?;
        self.invalidate();
        Ok(())
    }

    pub fn export(&mut self, target: &str, password: Option<&str>) -> Result<String> {
        let node = self.find(target)?;
        if node.node_type > 1 {
            return Err(Error::invalid("Only files and folders can be shared"));
        }
        node.key()?;
        let handle = self.api.request(json!({"a": "l", "n": node.handle}), &[])?;
        let handle = handle
            .as_str()
            .filter(|h| !h.is_empty())
            .ok_or_else(|| Error::protocol("Export returned no public handle"))?;
        match password {
            Some(password) => {
                let blob = keys::encrypt_password_link(
                    node.node_type,
                    &wire::b64_url_decode(handle)?,
                    node.key()?,
                    password,
                    2,
                )?;
                Ok(format!("https://mega.nz/#P!{blob}"))
            }
            None => Ok(format!(
                "https://mega.nz/{}/{handle}#{}",
                if node.is_file() { "file" } else { "folder" },
                wire::b64_url_encode(node.key()?)
            )),
        }
    }

    pub fn unexport(&mut self, target: &str) -> Result<()> {
        let node = self.find(target)?;
        self.api
            .request(json!({"a": "l", "n": node.handle, "d": 1}), &[])?;
        Ok(())
    }

    pub fn empty_trash(&mut self) -> Result<BatchOutcome> {
        self.api.control.checkpoint()?;
        let trash = self.tree()?.root(4)?.handle.clone();
        let handles: Vec<_> = self
            .tree()?
            .children(&trash)
            .iter()
            .map(|node| node.handle.clone())
            .collect();
        let result = (|| {
            let mut outcome = BatchOutcome::default();
            for handle in handles {
                self.api.control.checkpoint()?;
                match self.api.request(json!({"a": "d", "n": handle}), &[]) {
                    Ok(_) => outcome.completed.push(handle),
                    Err(error @ Error::Mega { .. }) => outcome.rejections.push(error),
                    Err(error) => return Err(error),
                }
            }
            self.api.control.checkpoint()?;
            Ok(outcome)
        })();
        self.invalidate();
        result
    }
}

#[cfg(test)]
#[path = "cloud_operation_tests.rs"]
mod operation_tests;
