use std::path::Path;

use super::{args::Crypter, context::Context};
use crate::error::{Error, Result};
use crate::protocol::{link_services::Resolver, links};
use crate::services::{local_crypto, splitter, thumbnails};
use crate::terminal::{progress::format_bytes, prompts};

fn overwrite(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => prompts::confirmed("Replace the existing output file?", false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

pub fn split(
    context: &Context,
    source: &Path,
    part_size_mb: u64,
    output: Option<&Path>,
) -> Result<()> {
    let (_directory, input) = local_crypto::open_source(source)?;
    let layout = splitter::split_layout(source, input.metadata()?.len(), part_size_mb, output)?;
    let mut collision = false;
    for path in layout.parts.iter().chain(std::iter::once(&layout.checksum)) {
        match std::fs::symlink_metadata(path) {
            Ok(_) => collision = true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
    }
    let replace =
        collision && prompts::confirmed("Replace the existing split parts and checksum?", false)?;
    if collision && !replace {
        return Err(Error::Canceled);
    }
    drop(input);
    drop(_directory);
    let mut callback = |_: u64, _: u64| context.control.checkpoint();
    let result = splitter::split_file(source, part_size_mb, output, replace, Some(&mut callback))?;
    context.output.message(
        "SUCCESS",
        &format!(
            "Split {} into {} part(s)",
            format_bytes(result.total_bytes),
            result.parts.len()
        ),
    )?;
    for part in result.parts {
        context.output.message("INFO", &part.to_string_lossy())?;
    }
    context
        .output
        .message("INFO", &format!("SHA-1: {}", result.sha1))
}

pub fn merge(
    context: &Context,
    source: &Path,
    output: Option<&Path>,
    no_verify: bool,
    delete_parts: bool,
) -> Result<()> {
    let destination = splitter::merge_destination(source, output)?;
    let replace = overwrite(&destination)?;
    if !replace && destination.try_exists()? {
        return Err(Error::Canceled);
    }
    let mut callback = |_: u64, _: u64| context.control.checkpoint();
    let result = splitter::merge_parts(
        source,
        output,
        !no_verify,
        delete_parts,
        replace,
        Some(&mut callback),
    )?;
    context
        .output
        .message("SUCCESS", &format!("Merged to {}", result.display()))
}

pub fn thumbnail(context: &Context, source: &Path, destination: &Path) -> Result<()> {
    let replace = overwrite(destination)?;
    if !replace && destination.try_exists()? {
        return Err(Error::Canceled);
    }
    let ffmpeg = std::env::var_os("MEGABASTERD_FFMPEG")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| "ffmpeg".into());
    let result = thumbnails::create_thumbnail(
        source,
        destination,
        replace,
        Some(&ffmpeg),
        &context.control,
    )?;
    if let Some(warning) = result.warning {
        context.output.message("WARNING", &warning)?;
    }
    context.output.message(
        "SUCCESS",
        &format!(
            "Thumbnail written: {} ({}x{})",
            destination.display(),
            result.width,
            result.height
        ),
    )
}

pub fn crypter(context: &mut Context, command: Crypter) -> Result<()> {
    match command {
        Crypter::Encrypt {
            source,
            destination,
            password,
            chunk_size_kb,
        } => {
            let size = usize::try_from(chunk_size_kb)
                .ok()
                .and_then(|value| value.checked_mul(1024))
                .ok_or_else(|| Error::invalid("Encryption chunk size overflows"))?;
            let password = prompts::secret("Crypter passphrase:", password.as_deref())?;
            let replace = overwrite(&destination)?;
            if !replace && destination.try_exists()? {
                return Err(Error::Canceled);
            }
            let mut callback = |_: u64, _: u64| context.control.checkpoint();
            let result = local_crypto::encrypt_file(
                &source,
                &destination,
                &password,
                size,
                replace,
                Some(&mut callback),
            )?;
            context.output.message(
                "SUCCESS",
                &format!(
                    "Encrypted {} ({})",
                    result.path.display(),
                    format_bytes(result.bytes)
                ),
            )
        }
        Crypter::Decrypt {
            source,
            destination,
            password,
        } => {
            let password = prompts::secret("Crypter passphrase:", password.as_deref())?;
            let replace = overwrite(&destination)?;
            if !replace && destination.try_exists()? {
                return Err(Error::Canceled);
            }
            let mut callback = |_: u64, _: u64| context.control.checkpoint();
            let result = local_crypto::decrypt_file(
                &source,
                &destination,
                &password,
                replace,
                Some(&mut callback),
            )?;
            if let Some(warning) = result.warning {
                context.output.message("WARNING", warning)?;
            }
            context.output.message(
                "SUCCESS",
                &format!(
                    "Decrypted {} ({})",
                    result.path.display(),
                    format_bytes(result.bytes)
                ),
            )
        }
        Crypter::MakeLink {
            mega_url,
            server,
            password,
            description,
            no_expire,
            reverse,
            max_downloads,
        } => {
            links::parse_link(&mega_url)?;
            let server = server
                .as_deref()
                .or(context.config.megacrypter_server.as_deref())
                .ok_or_else(|| {
                    Error::invalid(
                        "No MegaCrypter server set; use --server or config set megacrypter_server",
                    )
                })?
                .to_owned();
            let api = context.api(None)?;
            let endpoint = links::parse_link(&format!("mc://{server}/registration"))?;
            let resolver = Resolver {
                transport: &api.transport,
                password: None,
                elc_user: None,
                elc_api_key: None,
                elc_accounts: &context.config.elc_accounts,
            };
            let mut body = serde_json::json!({"m":"add","link":mega_url});
            if let Some(password) = password {
                body["password"] = serde_json::json!(password);
                body["pass"] = body["password"].clone();
            }
            if let Some(description) = description {
                body["description"] = serde_json::json!(description);
            }
            if no_expire {
                body["noexpire"] = true.into();
                body["no_expire"] = true.into();
            }
            if reverse {
                body["reverse"] = true.into();
            }
            if let Some(limit) = max_downloads {
                body["max_downloads"] = limit.into();
            }
            let response = resolver.megacrypter_post(&endpoint, body)?;
            let url = ["link", "url", "mc_url"]
                .iter()
                .find_map(|key| response.get(*key).and_then(serde_json::Value::as_str))
                .ok_or_else(|| Error::protocol("MegaCrypter returned no created link"))?;
            links::parse_link(url)?;
            context.output.public_link(url)
        }
        Crypter::Resolve { mc_url, password } => {
            let api = context.api(None)?;
            let resolver = Resolver {
                transport: &api.transport,
                password: password.as_deref(),
                elc_user: None,
                elc_api_key: None,
                elc_accounts: &context.config.elc_accounts,
            };
            let parsed = links::parse_link(&mc_url)?;
            let url = resolver.megacrypter_resolve(&parsed)?;
            context.output.public_link(&url)
        }
        Crypter::ElcResolve {
            elc_url,
            user,
            api_key,
        } => {
            let api = context.api(None)?;
            let resolver = Resolver {
                transport: &api.transport,
                password: None,
                elc_user: user.as_deref(),
                elc_api_key: api_key.as_deref(),
                elc_accounts: &context.config.elc_accounts,
            };
            for link in resolver.elc(&links::parse_link(&elc_url)?)? {
                context.output.public_link(&link)?;
            }
            Ok(())
        }
        Crypter::DlcResolve { path } => {
            use std::io::Read;
            let (_directory, file) = local_crypto::open_source(&path)?;
            let mut bytes = Vec::new();
            file.take(8 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
            if bytes.len() > 8 * 1024 * 1024 {
                return Err(Error::invalid("DLC container exceeds 8 MiB"));
            }
            let text = std::str::from_utf8(&bytes)
                .map_err(|_| Error::invalid("DLC container is not UTF-8"))?;
            let api = context.api(None)?;
            let resolver = Resolver {
                transport: &api.transport,
                password: None,
                elc_user: None,
                elc_api_key: None,
                elc_accounts: &context.config.elc_accounts,
            };
            for link in resolver.dlc(text)? {
                context.output.public_link(&link)?;
            }
            Ok(())
        }
    }
}
