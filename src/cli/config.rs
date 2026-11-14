use super::{args::Config, context::Context};
use crate::error::{Error, Result};
use crate::terminal::{prompts, redaction::sanitize};

pub fn dispatch(context: &Context, command: Config) -> Result<()> {
    dispatch_with_confirmation(context, command, prompts::confirmed)
}

pub(super) fn dispatch_with_confirmation(
    context: &Context,
    command: Config,
    mut confirm: impl FnMut(&str, bool) -> Result<bool>,
) -> Result<()> {
    match command {
        Config::Path => context
            .output
            .value_line(&context.config_store.path().to_string_lossy()),
        Config::Show => {
            if let Some(error) = &context.config_error {
                context.output.message("WARNING", &error.to_string())?;
            }
            let settings = display_settings(context)?;
            let object = settings
                .as_object()
                .ok_or_else(|| Error::protocol("Configuration schema is invalid"))?;
            let rows = object
                .iter()
                .map(|(key, value)| vec![key.clone(), value.to_string()])
                .collect::<Vec<_>>();
            context.output.table(&["Key", "Value"], &rows)
        }
        Config::Get { key } => {
            if let Some(error) = &context.config_error {
                context.output.message("WARNING", &error.to_string())?;
            }
            let settings = display_settings(context)?;
            let value = settings
                .get(&key)
                .ok_or_else(|| Error::invalid("Unknown configuration setting"))?;
            let shown = match value {
                serde_json::Value::Null => "None".to_owned(),
                serde_json::Value::Bool(value) => if *value { "True" } else { "False" }.to_owned(),
                serde_json::Value::String(value) => value.clone(),
                value => value.to_string(),
            };
            context.output.value_line(&shown)
        }
        Config::Set { key, value } => {
            context.require_config()?;
            context.config_store.set(&key, &value)?;
            context
                .output
                .message("INFO", "Configuration setting saved.")
        }
        Config::Unset { key } => {
            context.require_config()?;
            context.config_store.unset(&key)?;
            context
                .output
                .message("INFO", "Configuration setting unset.")
        }
        Config::Reset => {
            context.require_config()?;
            if !confirm("Reset configuration to defaults?", false)? {
                return Ok(());
            }
            context.config_store.reset()?;
            context
                .output
                .message("INFO", "Configuration reset to defaults.")
        }
        Config::Recover { reset } => {
            if !reset {
                context.config_store.recover(false)?;
                return context
                    .output
                    .message("INFO", "Configuration is usable; no recovery needed.");
            }
            if !confirm(
                "Preserve the damaged configuration and reset to defaults?",
                false,
            )? {
                return Ok(());
            }
            let backup = context.config_store.recover(true)?;
            context.output.message(
                "INFO",
                if backup.is_some() {
                    "Original configuration was preserved and defaults restored."
                } else {
                    "Configuration is usable; no recovery needed."
                },
            )
        }
        Config::Migrate => {
            let removed = context.config_store.migrate()?;
            context.output.message(
                "INFO",
                &format!(
                    "Native configuration normalized; removed {} retired or unknown settings.",
                    removed.len()
                ),
            )
        }
    }
}

fn display_settings(context: &Context) -> Result<serde_json::Value> {
    let mut settings = context.config.value()?;
    settings["download_path"] = serde_json::json!(
        context
            .paths
            .download(&context.config.download_path)
            .to_string_lossy()
    );
    Ok(sanitize(&settings, false))
}
