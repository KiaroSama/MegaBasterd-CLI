use std::path::PathBuf;

use super::{
    args::{self, AccountOptions},
    context::Context,
};
use crate::error::{Error, Result};
use crate::storage::queue::{JobType, QueueItem, QueuePayload};

pub fn execute(
    context: &mut Context,
    item: &QueueItem,
    payload: &QueuePayload,
    auth: &args::VaultOptions,
) -> Result<()> {
    if item.kind == JobType::Upload {
        match std::fs::symlink_metadata(&payload.source) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Queued upload source is missing",
                )
                .into());
            }
            Err(error) => return Err(error.into()),
            Ok(metadata) if !metadata.is_file() || metadata.file_type().is_symlink() => {
                return Err(Error::invalid(
                    "Queued upload needs a regular, non-symlink file",
                ));
            }
            Ok(_) => (),
        }
    }
    let account = AccountOptions {
        account: payload.account.clone(),
        vault_passphrase: auth.vault_passphrase.clone(),
        mfa_code: auth.mfa_code.clone(),
    };
    let result = match item.kind {
        JobType::Download => super::download::execute(
            context,
            args::Download {
                urls: vec![payload.source.clone()],
                output: (!payload.destination.is_empty())
                    .then(|| PathBuf::from(&payload.destination)),
                workers: None,
                limit: None,
                password: payload.password.clone(),
                no_verify: false,
                overwrite: false,
                rename: None,
                proxy: None,
                input_file: None,
                elc_user: None,
                elc_api_key: None,
                parallel: Some(1),
                include: Vec::new(),
                exclude: Vec::new(),
                select: false,
                json: context.output.json,
                auth: account,
            },
            false,
        )?,
        JobType::Upload => super::upload::execute(
            context,
            args::Upload {
                paths: vec![PathBuf::from(&payload.source)],
                auth: account,
                workers: None,
                limit: None,
                rename: None,
                target: None,
                keep_structure: false,
                keep_going: false,
                auto_account: false,
                parallel: Some(1),
                share: false,
                share_password: None,
                json: context.output.json,
            },
            false,
            Some(&item.id),
        )?,
    };
    if result == 0 {
        Ok(())
    } else {
        Err(Error::protocol(
            "Queued transfer failed; its result was recorded without replaying it",
        ))
    }
}
