#![allow(clippy::unwrap_used)]

use std::collections::BTreeSet;

use clap::CommandFactory;
use megabasterd_cli::cli::args::Cli;
use serde_json::Value;

fn leaves(command: &clap::Command, prefix: &str, found: &mut BTreeSet<String>) {
    for child in command.get_subcommands() {
        let path = if prefix.is_empty() {
            child.get_name().to_owned()
        } else {
            format!("{prefix} {}", child.get_name())
        };
        if child.get_subcommands().next().is_none() {
            found.insert(path);
        } else {
            leaves(child, &path, found);
        }
    }
}

fn documented(text: &str) -> BTreeSet<String> {
    text.lines()
        .filter_map(|line| {
            let cell = line.strip_prefix("| `mb ")?.split('`').next()?;
            Some(
                cell.split_whitespace()
                    .take_while(|part| {
                        part.bytes()
                            .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
                    })
                    .collect::<Vec<_>>()
                    .join(" "),
            )
        })
        .filter(|name| !name.is_empty())
        .collect()
}

#[test]
fn readme_and_command_reference_list_every_actual_native_leaf_without_phantom_commands() {
    let mut command = Cli::command();
    command.build();
    let mut actual = BTreeSet::new();
    leaves(&command, "", &mut actual);
    let schema: Value = serde_json::from_str(include_str!("fixtures/cli-schema.json")).unwrap();
    let baseline: BTreeSet<_> = schema["commands"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|record| record["kind"] == "command")
        .map(|record| record["path"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(actual.len(), 55);
    assert_eq!(actual, baseline);
    assert_eq!(documented(include_str!("../README.md")), actual);
    let reference = include_str!("../docs/COMMANDS.md");
    // Root leaves with detailed fenced syntax are not repeated as table entries.
    let mut reference_commands = documented(reference);
    for line in reference.lines().filter(|line| line.starts_with("mb ")) {
        let name = line[3..]
            .split_whitespace()
            .take_while(|part| {
                part.bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
            })
            .collect::<Vec<_>>()
            .join(" ");
        if !name.is_empty() {
            reference_commands.insert(name);
        }
    }
    assert_eq!(reference_commands, actual);
}

#[test]
fn native_docs_do_not_claim_old_toolchain_or_unexecuted_platform_success() {
    for text in [
        include_str!("../README.md"),
        include_str!("../CONTRIBUTING.md"),
        include_str!("../docs/COMMANDS.md"),
        include_str!("../docs/USAGE.md"),
        include_str!("../docs/CONFIG.md"),
        include_str!("../docs/ARCHITECTURE.md"),
    ] {
        for obsolete in [
            "python -m pip",
            "python -m megabasterd_cli",
            "pip install -e",
            "License-MIT-green",
            "CI tests on every",
            "--chunk-size-mb",
            "pyperclip",
        ] {
            assert!(
                !text.contains(obsolete),
                "native docs retain obsolete command: {obsolete}"
            );
        }
    }
    let readme = include_str!("../README.md");
    assert!(readme.contains("Migration candidate, not a verified release"));
    assert!(readme.contains("Compilation, native CI"));
    assert!(readme.contains("User/native-v2/"));
    assert!(readme.contains("collision suffixes"));
    assert!(readme.contains("[LEVEL] [COMPONENT]"));
    assert!(readme.contains("GPL-3.0-or-later"));
    let badges = readme
        .split("<div align=\"center\">")
        .nth(1)
        .unwrap()
        .split("</div>")
        .next()
        .unwrap();
    assert!((12..=16).contains(&badges.matches("[![").count()));
    assert!(badges.starts_with("\n\n") && badges.ends_with("\n\n"));
    assert!(badges.contains("Support-donations-d04a9a)](#donate)"));
}
