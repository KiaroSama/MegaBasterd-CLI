#![allow(clippy::unwrap_used)]

use megabasterd_cli::{
    error::Error,
    terminal::{output::Output, redaction::sanitize},
};
use serde_json::json;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);
impl Capture {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}
impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut output = self.0.lock().unwrap();
        if bytes.len() > 8192usize.saturating_sub(output.len()) {
            return Err(io::Error::other("Markup fixture output bound"));
        }
        output.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn remote_table_cells_and_account_labels_are_literal_even_with_unbalanced_markup() {
    let stdout = Capture::default();
    let stderr = Capture::default();
    let output = Output::with_writers(false, false, stdout.clone(), stderr.clone());
    output
        .table(
            &["Name", "Handle"],
            &[
                vec!["[bold red]x[/]".into(), "AAAAAAAA".into()],
                vec!["weird[name.mp4".into(), "abc[def".into()],
                vec!["holiday [/] clip.mp4".into(), "normal.mp4".into()],
                vec!["[bold red]evil[/bold red]".into(), "abc[def".into()],
                vec!["[bold red]label[/bold red]".into(), "Y".into()],
            ],
        )
        .unwrap();
    let text = stdout.text();
    for literal in [
        "[bold red]x[/]",
        "weird[name.mp4",
        "holiday [/] clip.mp4",
        "normal.mp4",
        "[bold red]evil[/bold red]",
        "abc[def",
        "[bold red]label[/bold red]",
    ] {
        assert!(text.contains(literal));
    }
    assert!(text.contains(" | Y\n"));
    assert!(!text.contains("[mb.success]") && !text.contains('\x1b'));
    assert!(stderr.text().is_empty());
}

#[test]
fn server_errors_are_literal_and_app_status_labels_remain_readable() {
    let stdout = Capture::default();
    let stderr = Capture::default();
    let output = Output::with_writers(false, false, stdout.clone(), stderr.clone());
    output
        .error(&Error::protocol(
            "Login failed: boom [bold red]pwned[/bold red] [/]",
        ))
        .unwrap();
    output
        .message("ERROR", "Lookup failed: bad token [oops")
        .unwrap();
    output.message("SUCCESS", "done").unwrap();
    output.message("INFO", "No items").unwrap();
    let text = stderr.text();
    assert!(text.contains("[bold red]pwned[/bold red]") && text.contains("[oops"));
    assert!(text.contains("[OK] done") && text.contains("No items"));
    assert!(!text.contains("[mb.success]") && !text.contains("[mb.dim]"));
    assert!(stdout.text().is_empty());
}

#[test]
fn source_folder_link_key_is_redacted_exactly_in_the_shared_console_consumer() {
    let link = "https://mega.nz/folder/PUBLICID0#FAKEKEYFAKEKEYFAKEKEY";
    let expected = "https://mega.nz/folder/PUBLICID0#<key>";
    assert_eq!(megabasterd_cli::terminal::redaction::text(link), expected);
    assert_eq!(megabasterd_cli::terminal::redaction::text("plain"), "plain");
    let stdout = Capture::default();
    let stderr = Capture::default();
    let output = Output::with_writers(false, false, stdout.clone(), stderr.clone());
    output.message("INFO", link).unwrap();
    output.message("INFO", "plain").unwrap();
    assert_eq!(stderr.text(), format!("[INFO] {expected}\n[INFO] plain\n"));
    assert!(stdout.text().is_empty());
    assert!(!stderr.text().contains("FAKEKEYFAKEKEYFAKEKEY"));
}

#[test]
fn display_values_mask_credentials_in_any_string_and_keep_existing_typed_special_cases() {
    let input = json!({
        "smart_proxy_url":"http://alice:hunter2@1.2.3.4:8080",
        "run_command":"curl -H \"Authorization: Bearer sk-abc123\"",
        "connect_proxy_password":"swordfish",
        "elc_accounts":{"h":{"password":"swordfish"}},
        "unset":null,"max_threads":4
    });
    let clean = sanitize(&input, false);
    assert!(
        !clean["smart_proxy_url"]
            .as_str()
            .unwrap()
            .contains("hunter2")
    );
    assert!(
        clean["smart_proxy_url"]
            .as_str()
            .unwrap()
            .contains("1.2.3.4:8080")
    );
    assert!(!clean["run_command"].as_str().unwrap().contains("sk-abc123"));
    assert_eq!(clean["connect_proxy_password"], "<redacted>");
    assert_eq!(
        clean["elc_accounts"],
        json!({"h":{"password":"<redacted>"}})
    );
    assert!(clean["unset"].is_null());
    assert_eq!(clean["max_threads"], 4);
}
