//! Download exit outcomes observed through the same controller and selection reader.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::{
    cli::args::{Cli, Command},
    crypto::wire,
    protocol::test_peer::{self, Response},
    terminal::output::Output,
};
use clap::Parser;
use serde_json::Value;
use std::io::{self, Cursor, Write};
use std::sync::{Arc, OnceLock};

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);
impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut output = self.0.lock().unwrap();
        if bytes.len() > (8192usize).saturating_sub(output.len()) {
            return Err(io::Error::other(
                "Download outcome fixture output bound exceeded",
            ));
        }
        output.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Capture {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

fn command(link: &str, output: &Path, select: bool) -> Download {
    let mut arguments: Vec<std::ffi::OsString> = vec![
        "mb".into(),
        "-q".into(),
        "download".into(),
        link.into(),
        "--json".into(),
        "-w".into(),
        "1".into(),
        "-P".into(),
        "1".into(),
        "-o".into(),
        output.as_os_str().to_owned(),
    ];
    if select {
        arguments.push("--select".into());
    }
    match Cli::try_parse_from(arguments).unwrap().command.unwrap() {
        Command::Download(command) => command,
        _ => panic!("fixture did not parse a download command"),
    }
}

fn response(value: Value) -> Response {
    Response {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: serde_json::to_vec(&json!([value])).unwrap(),
    }
}

fn scratch() -> tempfile::TempDir {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/download-outcomes");
    std::fs::create_dir_all(&base).unwrap();
    tempfile::tempdir_in(base).unwrap()
}

fn key() -> Vec<u8> {
    let vectors: Value =
        serde_json::from_str(include_str!("../../tests/fixtures/transfers/vectors.json")).unwrap();
    hex::decode(vectors["vectors"][1]["raw_key"].as_str().unwrap()).unwrap()
}

#[test]
fn failed_file_returns_nonzero_and_marks_the_same_controller_row_failed_not_canceled() {
    let scratch = scratch();
    let output = scratch.path().join("output with spaces");
    let stdout = Capture::default();
    let stderr = Capture::default();
    let raw_key = key();
    let link = format!(
        "https://mega.nz/file/FILE0001#{}",
        wire::b64_url_encode(&raw_key)
    );
    let attrs =
        wire::encrypt_attributes(&json!({"n":"failed.bin"}), &(0u8..16).collect::<Vec<_>>())
            .unwrap();
    let cdn = OnceLock::new();
    let mut progress = Progress::new(false);
    let (code, calls) = test_peer::with_peer(
        |request| {
            if request.path.starts_with("/cs?") {
                assert_eq!(
                    serde_json::from_slice::<Value>(&request.body).unwrap(),
                    json!([{"a":"g","g":1,"ssl":2,"p":"FILE0001"}])
                );
                Some(response(
                    json!({"s":17,"at":wire::b64_url_encode(&attrs),"g":cdn.get().unwrap()}),
                ))
            } else {
                assert_eq!(request.method, "GET");
                assert_eq!(request.path, "/cdn");
                assert_eq!(request.headers["range"], "bytes=0-16");
                Some(Response {
                    status: 400,
                    headers: vec![],
                    body: vec![],
                })
            }
        },
        |address| {
            cdn.set(format!("https://testserver.com:{}/cdn", address.port()))
                .unwrap();
            let mut context = Context::test_peer(
                scratch.path(),
                Api::test_peer(address).unwrap(),
                Output::with_writers(true, true, stdout.clone(), stderr.clone()),
            );
            execute_with(
                &mut context,
                command(&link, &output, false),
                true,
                Some(&mut progress),
                |_, _| panic!("file download requested folder selection"),
            )
            .unwrap()
        },
    );
    assert_eq!(code, 1);
    assert_eq!(calls.len(), 2, "deterministic failure was retried");
    assert_eq!(progress.snapshot(0).unwrap().status, Status::Failed);
    let totals = progress.totals().unwrap();
    assert_eq!((totals.items, totals.finished, totals.failed), (1, 0, 1));
    assert_eq!(totals.completed, 0);
    assert!(
        !progress.close(true).unwrap(),
        "close cannot turn a failed row into success"
    );
    let record: Value = serde_json::from_str(&stdout.text()).unwrap();
    assert_eq!(record["status"], "failed");
    assert_eq!(record["error_code"], "transfer_failed");
    assert!(stderr.text().contains("Transfer failed"));
    assert!(!output.join("failed.bin").exists());
    for text in [stdout.text(), stderr.text()] {
        assert!(!text.contains(&wire::b64_url_encode(&raw_key)));
    }
}

#[test]
fn folder_selection_none_and_eof_are_successful_skips_without_rows_tickets_or_output() {
    let raw_key = key();
    let wrapping_key: Vec<u8> = (0..16).collect();
    let root_key = [7; 16];
    let root_attrs = wire::encrypt_attributes(&json!({"n":"album"}), &root_key).unwrap();
    let file_attrs = wire::encrypt_attributes(&json!({"n":"keep.bin"}), &wrapping_key).unwrap();
    let graph = json!({"f":[
        {"h":"ROOT0001","p":"outsideX","t":1,
         "k":format!("own:{}",wire::b64_url_encode(&wire::aes_key_wrap_encrypt(&root_key,&wrapping_key).unwrap())),
         "a":wire::b64_url_encode(&root_attrs)},
        {"h":"FILE0001","p":"ROOT0001","t":0,"s":17,
         "k":format!("own:{}",wire::b64_url_encode(&wire::aes_key_wrap_encrypt(&raw_key,&wrapping_key).unwrap())),
         "a":wire::b64_url_encode(&file_attrs)}
    ]});
    for answer in [b"none\n".as_slice(), b"".as_slice()] {
        let scratch = scratch();
        let output = scratch.path().join("no output");
        let stdout = Capture::default();
        let stderr = Capture::default();
        let mut progress = Progress::new(false);
        let mut selections = 0;
        let (code, calls) = test_peer::with_peer(
            |request| {
                assert_eq!(request.method, "POST");
                assert_eq!(
                    serde_json::from_slice::<Value>(&request.body).unwrap(),
                    json!([{"a":"f","c":1,"r":1,"ca":1}])
                );
                Some(response(graph.clone()))
            },
            |address| {
                let mut context = Context::test_peer(
                    scratch.path(),
                    Api::test_peer(address).unwrap(),
                    Output::with_writers(true, true, stdout.clone(), stderr.clone()),
                );
                let code = execute_with(
                    &mut context,
                    command(
                        "https://mega.nz/folder/SHARE123#AAECAwQFBgcICQoLDA0ODw",
                        &output,
                        true,
                    ),
                    true,
                    Some(&mut progress),
                    |output, count| {
                        selections += 1;
                        assert_eq!(count, 1);
                        output.select_files(count, &mut Cursor::new(answer))
                    },
                )
                .unwrap();
                assert!(!context.control.is_canceled());
                assert!(!context.paths.user.exists() && !context.paths.logs.exists());
                code
            },
        );
        assert_eq!(code, 0);
        assert_eq!(selections, 1);
        assert_eq!(calls.len(), 1, "selection skip reached ticket or CDN");
        assert_eq!(progress.totals().unwrap().items, 0);
        assert!(progress.close(true).unwrap());
        let record: Value = serde_json::from_str(&stdout.text()).unwrap();
        assert_eq!(record["event"], "result");
        assert_eq!(record["status"], "skipped");
        assert!(record.get("error_code").is_none());
        assert!(stderr.text().contains("Select files"));
        if answer.is_empty() {
            assert!(stderr.text().contains("end of input"));
        }
        assert!(!output.exists());
        assert!(std::fs::read_dir(scratch.path()).unwrap().next().is_none());
    }
}
