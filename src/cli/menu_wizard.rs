//! Shared source-compatible menu steps; command execution stays in the main dispatcher.

use std::{ffi::OsString, path::Path};

use zeroize::Zeroizing;

use super::menu::split_arguments;
use crate::error::Result;

#[cfg(test)]
#[path = "menu_wizard_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "menu_yes_no_tests.rs"]
mod yes_no_tests;

#[derive(Clone, Copy)]
pub(super) enum Wizard {
    Download,
    Upload,
    Info,
    Account,
    Elc,
    DownloadFolder,
    DownloadWorkers,
    SpeedLimit,
    Advanced,
}

pub(super) enum Outcome {
    Ready(Vec<OsString>),
    Back,
    Quit,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Text,
    Secret,
    YesNo,
}

struct Step {
    key: &'static str,
    label: &'static str,
    kind: Kind,
    default: &'static str,
    option: Option<&'static str>,
    required: bool,
    numeric: bool,
    raw: bool,
    zero_is_back: bool,
}

impl Step {
    fn text(key: &'static str, label: &'static str, option: Option<&'static str>) -> Self {
        Self {
            key,
            label,
            kind: Kind::Text,
            default: "",
            option,
            required: false,
            numeric: false,
            raw: false,
            zero_is_back: true,
        }
    }

    fn required(key: &'static str, label: &'static str) -> Self {
        Self {
            required: true,
            ..Self::text(key, label, None)
        }
    }

    fn secret(key: &'static str, label: &'static str, option: Option<&'static str>) -> Self {
        Self {
            kind: Kind::Secret,
            ..Self::text(key, label, option)
        }
    }

    fn numeric(
        key: &'static str,
        label: &'static str,
        default: &'static str,
        option: &'static str,
    ) -> Self {
        Self {
            default,
            numeric: true,
            zero_is_back: key != "limit",
            ..Self::text(key, label, Some(option))
        }
    }

    fn yes_no(
        key: &'static str,
        label: &'static str,
        default: bool,
        option: Option<&'static str>,
    ) -> Self {
        Self {
            kind: Kind::YesNo,
            default: if default { "yes" } else { "no" },
            ..Self::text(key, label, option)
        }
    }
}

fn steps(wizard: Wizard) -> Vec<Step> {
    match wizard {
        Wizard::Download => vec![
            Step::required("source", "MEGA link(s), or a text/DLC file path"),
            Step::text("output", "Output directory", Some("-o")),
            Step::numeric("workers", "Workers per file", "8", "-w"),
            Step::numeric("parallel", "Parallel files", "6", "-P"),
            Step::numeric("limit", "Speed limit KB/s (0 = unlimited)", "0", "-l"),
            Step::secret("password", "Link password [blank = skip]", Some("-p")),
            Step::text(
                "rename",
                "Rename single file [blank = original name]",
                Some("--rename"),
            ),
            Step::text("proxy", "Proxy URL [blank = configured]", Some("--proxy")),
            Step::yes_no(
                "no_verify",
                "Skip final integrity check? (not recommended)",
                false,
                Some("--no-verify"),
            ),
        ],
        Wizard::Upload => vec![
            Step::required("paths", "Local file/folder path(s)"),
            Step::text(
                "account",
                "Account email/label [blank = default]",
                Some("-a"),
            ),
            Step::text(
                "target",
                "Remote target folder [blank = account root]",
                Some("--target"),
            ),
            Step::numeric("workers", "Workers per file", "8", "-w"),
            Step::numeric("parallel", "Parallel files", "6", "-P"),
            Step::numeric(
                "limit",
                "Upload speed limit KB/s (0 = unlimited)",
                "0",
                "-l",
            ),
            Step::yes_no(
                "keep",
                "Keep folder structure?",
                true,
                Some("--keep-structure"),
            ),
            Step::yes_no(
                "auto",
                "Auto-pick account by free space?",
                false,
                Some("--auto-account"),
            ),
            Step::yes_no(
                "share",
                "Create public links after upload?",
                false,
                Some("--share"),
            ),
            Step::secret(
                "vault",
                "Vault passphrase [blank = prompt later]",
                Some("--vault-passphrase"),
            ),
            Step {
                raw: true,
                ..Step::text("extra", "Extra upload options [blank = none]", None)
            },
        ],
        Wizard::Info => vec![
            Step::required("url", "MEGA link"),
            Step::secret(
                "password",
                "Link password [blank = skip]",
                Some("--password"),
            ),
        ],
        Wizard::Account => vec![
            Step::required("email", "Account email"),
            Step::text("label", "Label [blank = none]", Some("--label")),
            Step::yes_no(
                "default",
                "Make this the default account?",
                true,
                Some("--default"),
            ),
            Step::yes_no("verify", "Verify login now?", true, None),
            Step::secret(
                "vault",
                "Vault passphrase [blank = prompt later]",
                Some("--vault-passphrase"),
            ),
        ],
        Wizard::Elc => vec![
            Step::required("host", "ELC host"),
            Step::required("user", "ELC user"),
            Step::secret("api_key", "ELC API key [blank = cancel]", None),
        ],
        Wizard::DownloadFolder => vec![Step::text("output", "Default download folder", None)],
        Wizard::DownloadWorkers => vec![Step {
            default: "8",
            ..Step::text("value", "Download workers", None)
        }],
        Wizard::SpeedLimit => vec![Step {
            default: "0",
            zero_is_back: false,
            ..Step::text("value", "Speed limit KB/s (0 = unlimited)", None)
        }],
        Wizard::Advanced => vec![Step {
            raw: true,
            ..Step::text("arguments", "Enter CLI arguments", None)
        }],
    }
}

pub(super) fn run_with(
    wizard: Wizard,
    output_directory: &Path,
    mut read: impl FnMut(&str, bool) -> Result<Option<Zeroizing<String>>>,
    mut notice: impl FnMut(&str) -> Result<()>,
) -> Result<Outcome> {
    let steps = steps(wizard);
    let mut values: Vec<_> = steps
        .iter()
        .map(|step| Zeroizing::new(step.default.to_owned()))
        .collect();
    let mut index = 0usize;
    while let Some(step) = steps.get(index) {
        let shown = if step.kind == Kind::Secret || step.raw {
            String::new()
        } else if step.key == "output" && values[index].is_empty() {
            format!(" [{}]", output_directory.display())
        } else if values[index].is_empty() {
            String::new()
        } else {
            format!(" [{}]", values[index].as_str())
        };
        let question = format!(
            "{}{shown} {{back={}, quit=exit}}:",
            step.label,
            if step.zero_is_back { "0" } else { "back" }
        );
        let Some(answer) = read(&question, step.kind == Kind::Secret)? else {
            return Ok(Outcome::Quit);
        };
        let trimmed = answer.trim();
        if trimmed.eq_ignore_ascii_case("exit") {
            return Ok(Outcome::Quit);
        }
        if trimmed.eq_ignore_ascii_case("back") || (step.zero_is_back && trimmed == "0") {
            if index == 0 {
                return Ok(Outcome::Back);
            }
            index -= 1;
            continue;
        }
        let value = if step.kind == Kind::Secret {
            answer
        } else if trimmed.is_empty() {
            values[index].clone()
        } else if step.kind == Kind::YesNo {
            Zeroizing::new(
                if trimmed.eq_ignore_ascii_case("y") || trimmed.eq_ignore_ascii_case("yes") {
                    "yes"
                } else {
                    "no"
                }
                .to_owned(),
            )
        } else {
            Zeroizing::new(trimmed.to_owned())
        };
        if step.required && value.trim().is_empty() {
            notice("This value is required.")?;
            continue;
        }
        let value = if step.numeric {
            let Some(number) = whole_number(&value) else {
                notice("Enter a whole number >= 0.")?;
                continue;
            };
            Zeroizing::new(number)
        } else {
            value
        };
        values[index] = value;
        index += 1;
    }
    let get = |key| {
        steps
            .iter()
            .position(|step| step.key == key)
            .map(|index| values[index].as_str())
            .unwrap_or("")
    };
    let mut arguments: Vec<OsString> = match wizard {
        Wizard::Download => {
            let source = get("source");
            let mut head = vec!["mb".into(), "download".into()];
            if Path::new(source).exists()
                && !["mega.nz/", "mega.co.nz/", "mc://", "mega://"]
                    .iter()
                    .any(|marker| source.contains(marker))
            {
                head.extend(["-i".into(), source.into()]);
            } else {
                head.extend(split_arguments(source).into_iter().map(OsString::from));
            }
            head
        }
        Wizard::Upload => std::iter::once("mb".into())
            .chain(std::iter::once("upload".into()))
            .chain(
                split_arguments(get("paths"))
                    .into_iter()
                    .map(OsString::from),
            )
            .collect(),
        Wizard::Info => vec!["mb".into(), "info".into(), get("url").into()],
        Wizard::Account => vec![
            "mb".into(),
            "account".into(),
            "add".into(),
            get("email").into(),
        ],
        Wizard::DownloadFolder | Wizard::DownloadWorkers | Wizard::SpeedLimit => {
            let (key, value) = match wizard {
                Wizard::DownloadFolder => (
                    "download_path",
                    if get("output").is_empty() {
                        output_directory.as_os_str().to_owned()
                    } else {
                        get("output").into()
                    },
                ),
                Wizard::DownloadWorkers => ("max_workers", get("value").into()),
                _ => ("speed_limit_kbps", get("value").into()),
            };
            return Ok(Outcome::Ready(vec![
                "mb".into(),
                "config".into(),
                "set".into(),
                key.into(),
                value,
            ]));
        }
        Wizard::Advanced => {
            let words = split_arguments(get("arguments"));
            if words.is_empty() {
                return Ok(Outcome::Back);
            }
            return Ok(Outcome::Ready(
                std::iter::once("mb".into())
                    .chain(words.into_iter().map(OsString::from))
                    .collect(),
            ));
        }
        Wizard::Elc => {
            if get("api_key").trim().is_empty() {
                return Ok(Outcome::Back);
            }
            let mut hosts = serde_json::Map::new();
            hosts.insert(
                get("host").to_owned(),
                serde_json::json!({"user":get("user"),"api_key":get("api_key")}),
            );
            return Ok(Outcome::Ready(vec![
                "mb".into(),
                "config".into(),
                "set".into(),
                "elc_accounts".into(),
                serde_json::to_string(&hosts)?.into(),
            ]));
        }
    };
    for (step, value) in steps.iter().zip(&values) {
        if step.raw {
            arguments.extend(split_arguments(value).into_iter().map(OsString::from));
        } else if let Some(option) = step.option {
            if step.kind == Kind::YesNo {
                if value.as_str() == "yes" {
                    arguments.push(option.into());
                }
            } else if step.key == "output" && value.is_empty() {
                arguments.extend([option.into(), output_directory.as_os_str().to_owned()]);
            } else if !value.trim().is_empty() {
                arguments.extend([option.into(), value.as_str().into()]);
            }
        }
    }
    if matches!(wizard, Wizard::Account) && get("verify") == "no" {
        arguments.push("--no-verify".into());
    }
    Ok(Outcome::Ready(arguments))
}

fn whole_number(text: &str) -> Option<String> {
    let negative = text.starts_with('-');
    let text = text.strip_prefix(['+', '-']).unwrap_or(text);
    let mut digit = false;
    let mut number = String::new();
    for character in text.chars() {
        if character == '_' && digit {
            digit = false;
            continue;
        }
        let value = crate::transfers::selection::decimal(character)?;
        number.push(char::from(b'0' + value as u8));
        digit = true;
    }
    if !digit || (negative && number.bytes().any(|byte| byte != b'0')) {
        return None;
    }
    let number = number.trim_start_matches('0');
    Some(if number.is_empty() { "0" } else { number }.to_owned())
}
