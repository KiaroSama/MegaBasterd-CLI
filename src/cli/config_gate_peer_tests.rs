//! Corrupt policy must stop parsed commands before any peer request or state mutation.
#![allow(clippy::unwrap_used)]

use std::{
    collections::BTreeMap,
    io::{self, Write},
    path::Path,
    sync::{Arc, Mutex},
};

use clap::Parser;

use super::{args::Cli, context::Context, dispatch};
use crate::{
    error::Error,
    protocol::{api::Api, test_peer},
    storage::files::Store,
    terminal::output::Output,
};

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut output = self.0.lock().unwrap();
        if bytes.len() > (64 * 1024usize).saturating_sub(output.len()) {
            return Err(io::Error::other(
                "Config gate fixture output bound exceeded",
            ));
        }
        output.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn snapshot(root: &Path) -> BTreeMap<std::path::PathBuf, Vec<u8>> {
    fn collect(root: &Path, directory: &Path, files: &mut BTreeMap<std::path::PathBuf, Vec<u8>>) {
        for entry in std::fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            let metadata = std::fs::symlink_metadata(&path).unwrap();
            assert!(!metadata.file_type().is_symlink());
            if metadata.is_dir() {
                collect(root, &path, files);
            } else {
                assert!(metadata.is_file());
                files.insert(
                    path.strip_prefix(root).unwrap().to_owned(),
                    std::fs::read(path).unwrap(),
                );
            }
        }
    }
    let mut files = BTreeMap::new();
    collect(root, root, &mut files);
    files
}

#[test]
fn config_recovery_report_reloads_current_file_instead_of_trusting_startup_status() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/config-report");
    std::fs::create_dir_all(&base).unwrap();
    let scratch = crate::test_support::tempdir_in(base).unwrap();
    let mut context = Context::test_context(scratch.path());
    let stdout = Capture::default();
    let stderr = Capture::default();
    context.output = Output::with_writers(false, false, stdout.clone(), stderr.clone());
    context.config_store.set("max_workers", "7").unwrap();
    let valid = std::fs::read(context.paths.config()).unwrap();
    let command = || {
        Cli::try_parse_from(["mb", "config", "recover"])
            .unwrap()
            .command
            .unwrap()
    };
    assert_eq!(dispatch(&mut context, command()).unwrap(), 0);
    let malformed = b"{\"connect_proxy_password\":\"synthetic-not-for-output\",,,";
    Store::new(context.paths.config())
        .lock()
        .unwrap()
        .write_bytes(malformed)
        .unwrap();
    let before = snapshot(scratch.path());
    assert!(matches!(
        dispatch(&mut context, command()),
        Err(Error::Corrupt(_))
    ));
    let mut after = snapshot(scratch.path());
    let added: Vec<_> = after
        .keys()
        .filter(|path| !before.contains_key(*path))
        .cloned()
        .collect();
    assert_eq!(added.len(), 1);
    assert!(
        added[0]
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("config.json.corrupt-")
    );
    assert_eq!(after.remove(&added[0]).unwrap(), malformed);
    assert_eq!(after, before);
    context.config_error = Some(Error::Corrupt("previous stale state".into()));
    Store::new(context.paths.config())
        .lock()
        .unwrap()
        .write_bytes(&valid)
        .unwrap();
    let before = snapshot(scratch.path());
    assert_eq!(dispatch(&mut context, command()).unwrap(), 0);
    assert_eq!(snapshot(scratch.path()), before);
    assert!(stdout.0.lock().unwrap().is_empty());
    let text = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
    assert!(!text.contains("synthetic-not-for-output") && !text.contains("previous stale state"));
}

#[test]
fn parsed_config_migrate_normalizes_current_native_settings_and_keeps_unsafe_documents_unchanged() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/config-normalization-cli");
    std::fs::create_dir_all(&base).unwrap();
    let scratch = crate::test_support::tempdir_in(base).unwrap();
    let mut context = Context::test_context(scratch.path());
    let stdout = Capture::default();
    let stderr = Capture::default();
    context.output = Output::with_writers(false, false, stdout.clone(), stderr.clone());
    Store::new(context.paths.config())
        .lock()
        .unwrap()
        .save(&serde_json::json!({
            "chunk_size_kb":2048,"smart_proxy_random":false,
            "unknown-secret-argument": "synthetic-private-value",
            "max_workers":4,"default_account":"a@example.com",
            "user_agent":"MegaBasterd-CLI/1.0"
        }))
        .unwrap();
    let command = || {
        Cli::try_parse_from(["mb", "config", "migrate"])
            .unwrap()
            .command
            .unwrap()
    };
    context.config_error = Some(Error::Corrupt("previous stale state".into()));
    assert_eq!(dispatch(&mut context, command()).unwrap(), 0);
    let normalized = std::fs::read(context.paths.config()).unwrap();
    let (settings, warnings) = context.config_store.load().unwrap();
    assert_eq!(settings.max_workers, 4);
    assert_eq!(settings.default_account.as_deref(), Some("a@example.com"));
    assert!(warnings.is_empty() && settings.user_agent.is_empty());
    context.config = settings;
    context.config_error = None;
    assert_eq!(
        context.api(None).unwrap().transport.user_agent,
        format!("MegaBasterd-CLI/{}", env!("CARGO_PKG_VERSION"))
    );
    context.config.user_agent = "custom-client/7.2".into();
    assert_eq!(
        context.api(None).unwrap().transport.user_agent,
        "custom-client/7.2"
    );
    assert_eq!(dispatch(&mut context, command()).unwrap(), 0);
    assert_eq!(std::fs::read(context.paths.config()).unwrap(), normalized);
    let text = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
    assert!(text.contains("removed 3") && text.contains("removed 0"));
    assert!(!text.contains("unknown-secret-argument") && !text.contains("synthetic-private-value"));
    assert!(stdout.0.lock().unwrap().is_empty());
    let before_errors = stderr.0.lock().unwrap().clone();
    for bytes in [
        b"{malformed".to_vec(),
        serde_json::to_vec(&serde_json::json!({
            "version":crate::storage::files::STORE_VERSION+1,"data":{"max_workers":7}
        }))
        .unwrap(),
    ] {
        Store::new(context.paths.config())
            .lock()
            .unwrap()
            .write_bytes(&bytes)
            .unwrap();
        assert!(matches!(
            dispatch(&mut context, command()),
            Err(Error::Corrupt(_))
        ));
        assert_eq!(std::fs::read(context.paths.config()).unwrap(), bytes);
        assert_eq!(*stderr.0.lock().unwrap(), before_errors);
    }
}

#[test]
fn parsed_commands_refuse_corrupt_policy_before_requests_prompts_or_state_changes() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/config-gate-peers");
    std::fs::create_dir_all(&base).unwrap();
    let scratch = crate::test_support::tempdir_in(base).unwrap();
    let stdout = Capture::default();
    let stderr = Capture::default();
    let (_, calls) = test_peer::with_peer(
        |_| panic!("A command contacted the peer despite corrupt configuration"),
        |address| {
            let mut context = Context::test_peer(
                scratch.path(),
                Api::test_peer(address).unwrap(),
                Output::with_writers(false, false, stdout.clone(), stderr.clone()),
            );
            let malformed = b"{\"force_smart_proxy\":true,\"smart_proxy_enabled\":true,,, BROKEN";
            Store::new(context.paths.config())
                .lock()
                .unwrap()
                .write_bytes(malformed)
                .unwrap();
            context.config_error = Some(context.config_store.load().err().unwrap());
            let before = snapshot(scratch.path());
            // Exact retained NETWORK_OR_MUTATING command variants, including missing credentials.
            for words in [
                vec!["download", "https://mega.nz/file/ABCD1234#KEYMATERIAL"],
                vec!["info", "https://mega.nz/file/ABCD1234#KEYMATERIAL"],
                vec!["stream", "https://mega.nz/file/ABCD1234#KEYMATERIAL"],
                vec!["upload", "."],
                vec!["ls"],
                vec!["search", "term"],
                vec!["mkdir", "folder"],
                vec!["rm", "handle"],
                vec!["mv", "handle", "target"],
                vec!["rename", "handle", "newname"],
                vec!["share", "handle"],
                vec!["import", "https://mega.nz/folder/ABCD1234#KEYMATERIAL"],
                vec!["account", "refresh-all"],
                vec!["account", "info"],
                vec!["proxy", "fetch"],
                vec!["queue", "run"],
                vec![
                    "queue",
                    "add-download",
                    "https://mega.nz/file/ABCD1234#KEYMATERIAL",
                ],
                vec!["watch"],
                vec!["crypter", "elc-resolve", "mega://elc?QQ=="],
            ] {
                let command =
                    Cli::try_parse_from(std::iter::once("mb").chain(words.iter().copied()))
                        .unwrap()
                        .command
                        .unwrap();
                let error = dispatch(&mut context, command).err().unwrap();
                assert!(matches!(error, Error::Corrupt(_)), "{words:?}: {error}");
                assert_eq!(error.exit_code(), 1);
                assert!(error.to_string().to_lowercase().contains("config"));
                assert!(!error.to_string().contains("BROKEN"));
                assert_eq!(std::fs::read(context.paths.config()).unwrap(), malformed);
                assert_eq!(snapshot(scratch.path()), before, "{words:?}");
            }
        },
    );
    assert!(calls.is_empty());
    assert!(stdout.0.lock().unwrap().is_empty());
    assert!(stderr.0.lock().unwrap().is_empty());
}
