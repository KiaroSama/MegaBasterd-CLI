//! CLI usage validation only; secure native opens revalidate at the I/O boundary.
use std::path::PathBuf;

use clap::builder::{PathBufValueParser, TypedValueParser};

fn path(value: PathBuf, exists: bool, files: bool, directories: bool) -> Result<PathBuf, String> {
    match std::fs::metadata(&value) {
        Ok(metadata) if (metadata.is_file() && files) || (metadata.is_dir() && directories) => {
            Ok(value)
        }
        Ok(_) => Err("Path has the wrong file/directory type".into()),
        Err(error) if !exists && error.kind() == std::io::ErrorKind::NotFound => Ok(value),
        Err(error) => Err(format!("Path is unavailable ({})", error.kind())),
    }
}

pub fn existing_file() -> impl TypedValueParser<Value = PathBuf> {
    PathBufValueParser::new().try_map(|value| path(value, true, true, false))
}

pub fn existing_path() -> impl TypedValueParser<Value = PathBuf> {
    PathBufValueParser::new().try_map(|value| path(value, true, true, true))
}

pub fn output_file() -> impl TypedValueParser<Value = PathBuf> {
    PathBufValueParser::new().try_map(|value| path(value, false, true, false))
}

pub fn output_directory() -> impl TypedValueParser<Value = PathBuf> {
    PathBufValueParser::new().try_map(|value| path(value, false, false, true))
}

pub fn watch_interval(value: &str) -> Result<f64, String> {
    let value = value
        .parse::<f64>()
        .map_err(|_| "Clipboard interval must be numeric")?;
    if !value.is_finite() || !(0.05..=3600.0).contains(&value) {
        return Err("Clipboard interval must be between 0.05 and 3600 seconds".into());
    }
    Ok(value)
}
