#![allow(clippy::unwrap_used)]

use std::any::TypeId;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Arg, ArgAction, CommandFactory, Parser};
use megabasterd_cli::cli::args::{Cli, Command};
use megabasterd_cli::{platform::process, storage::config::Config, transfers::control::Control};
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/cli-schema.json")).unwrap()
}

fn schema() -> clap::Command {
    let mut command = Cli::command();
    command.build();
    command
}

fn commands<'a>(
    command: &'a clap::Command,
    path: String,
    all: &mut BTreeMap<String, &'a clap::Command>,
) {
    all.insert(path.clone(), command);
    for child in command.get_subcommands() {
        let path = format!("{path} {}", child.get_name()).trim().to_owned();
        commands(child, path, all);
    }
}

fn flags(argument: &Arg) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    if let Some(short) = argument.get_short() {
        names.insert(format!("-{short}"));
    }
    for short in argument.get_all_short_aliases().unwrap_or_default() {
        names.insert(format!("-{short}"));
    }
    if let Some(long) = argument.get_long() {
        names.insert(format!("--{long}"));
    }
    for long in argument.get_all_aliases().unwrap_or_default() {
        names.insert(format!("--{long}"));
    }
    names
}

fn strings(value: &Value) -> BTreeSet<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect()
}

fn defaults(argument: &Arg) -> Vec<String> {
    argument
        .get_default_values()
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect()
}

fn scalar(value: &Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), str::to_owned)
}

fn same_type(argument: &Arg, kind: &str) -> bool {
    let id = argument.get_value_parser().type_id();
    match kind {
        "integer" => [
            TypeId::of::<i32>(),
            TypeId::of::<i64>(),
            TypeId::of::<u16>(),
            TypeId::of::<u32>(),
            TypeId::of::<u64>(),
            TypeId::of::<usize>(),
        ]
        .into_iter()
        .any(|kind| id == kind),
        "float" => id == TypeId::of::<f64>(),
        "string" => id == TypeId::of::<String>(),
        "existing_file" | "existing_path" | "output_file" | "output_dir" => {
            id == TypeId::of::<PathBuf>() || id == TypeId::of::<OsString>()
        }
        "switch" => matches!(
            argument.get_action(),
            ArgAction::SetTrue | ArgAction::SetFalse | ArgAction::Set
        ),
        "count" => matches!(argument.get_action(), ArgAction::Count),
        "version" => matches!(argument.get_action(), ArgAction::Version),
        _ => false,
    }
}

fn option<'a>(command: &'a clap::Command, flag: &str) -> &'a Arg {
    command
        .get_arguments()
        .find(|arg| flags(arg).contains(flag))
        .unwrap_or_else(|| panic!("{} lacks {flag}", command.get_name()))
}

#[test]
fn complete_command_surface_has_fifty_five_leaves_and_short_help() {
    fn leaves(command: &clap::Command) -> usize {
        if command.get_subcommands().next().is_none() {
            1
        } else {
            command.get_subcommands().map(leaves).sum()
        }
    }
    let command = Cli::command();
    assert_eq!(leaves(&command), 55);
    assert_eq!(
        Cli::try_parse_from(["mb", "download", "-h"])
            .err()
            .unwrap()
            .exit_code(),
        0
    );
    let parsed = Cli::try_parse_from([
        "mb",
        "download",
        "--force",
        "https://mega.nz/file/ABCDEFGH#KEY",
    ])
    .unwrap();
    assert!(matches!(parsed.command, Some(Command::Download(args)) if args.overwrite));
    assert!(
        Cli::try_parse_from(["mb", "crypter", "encrypt", "a", "b", "--chunk-size-mb", "1"])
            .is_err()
    );
    assert!(Cli::try_parse_from(["mb", "config", "unset", "default_account"]).is_ok());
}

#[test]
fn every_baseline_command_group_position_and_option_matches_actual_clap_schema() {
    let data = fixture();
    let root = schema();
    let mut actual = BTreeMap::new();
    commands(&root, String::new(), &mut actual);
    let records = data["commands"].as_array().unwrap();
    let expected: BTreeSet<_> = records
        .iter()
        .map(|v| v["path"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(actual.keys().cloned().collect::<BTreeSet<_>>(), expected);
    assert_eq!(records.len(), 62);
    assert_eq!(
        records.iter().filter(|v| v["kind"] == "command").count(),
        55
    );
    assert_eq!(
        records
            .iter()
            .map(|v| v["options"].as_array().unwrap().len())
            .sum::<usize>(),
        131
    );
    let global_keys = ["verbose", "quiet", "logging"];
    for record in records {
        let path = record["path"].as_str().unwrap();
        let command = actual[path];
        assert_eq!(
            command.get_subcommands().next().is_some(),
            record["kind"] == "group",
            "{path}"
        );
        assert_eq!(
            command.get_all_aliases().count(),
            0,
            "unlisted command alias at {path}"
        );
        let mut wanted = strings(&data["help_flags"]);
        let mut keys: BTreeSet<_> = record["options"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        if let Some(extra) = data["approved_additions"]
            .get(path)
            .and_then(Value::as_array)
        {
            keys.extend(extra.iter().map(|v| v.as_str().unwrap()));
        }
        for key in keys {
            let spec = &data["options"][key];
            let expected_flags = strings(&spec["flags"]);
            wanted.extend(expected_flags.clone());
            if spec["pair"] == true {
                // The source pair is one semantic option; the target may use two booleans.
                for flag in expected_flags {
                    assert!(same_type(option(command, &flag), "switch"), "{path} {flag}");
                }
                continue;
            }
            let first = spec["flags"][0].as_str().unwrap();
            let argument = option(command, first);
            assert_eq!(flags(argument), expected_flags, "{path} {key} aliases");
            let kind = spec["type"].as_str().unwrap();
            assert!(same_type(argument, kind), "{path} {key} type");
            let num = argument.get_num_args().unwrap();
            let takes_value = !matches!(kind, "switch" | "count" | "version");
            assert_eq!(
                (num.min_values(), num.max_values()),
                if takes_value { (1, 1) } else { (0, 0) },
                "{path} {key} arity"
            );
            assert_eq!(
                matches!(argument.get_action(), ArgAction::Append),
                spec["multiple"] == true,
                "{path} {key} repetition"
            );
            assert!(
                !argument.is_required_set(),
                "{path} {key} unexpectedly required"
            );
            let expected_defaults = if spec["default"].is_null() || spec["default"].is_array() {
                Vec::new()
            } else {
                vec![scalar(&spec["default"])]
            };
            assert_eq!(
                defaults(argument),
                expected_defaults,
                "{path} {key} default"
            );
            let choices = argument
                .get_value_parser()
                .possible_values()
                .map(|values| {
                    values
                        .map(|v| v.get_name().to_owned())
                        .collect::<BTreeSet<_>>()
                })
                .unwrap_or_default();
            if let Some(expected) = spec.get("choices") {
                assert_eq!(choices, strings(expected), "{path} {key} choices");
            }
        }
        if path.is_empty() {
            for key in global_keys {
                for flag in data["options"][key]["flags"].as_array().unwrap() {
                    assert!(
                        !option(command, flag.as_str().unwrap()).is_global_set(),
                        "source root flag unexpectedly inherited"
                    );
                }
            }
        }
        let actual_flags: BTreeSet<_> = command.get_arguments().flat_map(flags).collect();
        assert_eq!(actual_flags, wanted, "{path} complete option spellings");
        let mut positions: Vec<_> = command
            .get_arguments()
            .filter(|a| a.get_index().is_some())
            .collect();
        positions.sort_by_key(|a| a.get_index());
        let expected_args = record["args"].as_array().unwrap();
        assert_eq!(positions.len(), expected_args.len(), "{path} positions");
        for (index, (argument, spec)) in positions.iter().zip(expected_args).enumerate() {
            assert_eq!(
                argument.get_id().as_str(),
                spec[0].as_str().unwrap(),
                "{path} positional name"
            );
            assert_eq!(
                argument.get_index(),
                Some(index + 1),
                "{path} positional order"
            );
            assert!(
                same_type(argument, spec[1].as_str().unwrap()),
                "{path} positional type"
            );
            assert_eq!(
                argument.is_required_set(),
                spec[2].as_u64().unwrap() > 0,
                "{path} positional required"
            );
            let num = argument.get_num_args().unwrap();
            assert_eq!(
                if argument.is_required_set() {
                    num.min_values().max(1)
                } else {
                    0
                },
                spec[2].as_u64().unwrap() as usize,
                "{path} positional minimum"
            );
            assert_eq!(
                num.max_values(),
                spec[3].as_u64().map_or(usize::MAX, |n| n as usize),
                "{path} positional maximum"
            );
            assert_eq!(
                defaults(argument),
                if spec[4].is_null() {
                    vec![]
                } else {
                    vec![scalar(&spec[4])]
                },
                "{path} positional default"
            );
        }
        for flag in ["-h", "--help"] {
            let mut args = vec!["mb".to_owned()];
            args.extend(path.split_whitespace().map(str::to_owned));
            args.push(flag.to_owned());
            assert_eq!(
                Cli::try_parse_from(args).err().unwrap().exit_code(),
                0,
                "{path} {flag}"
            );
        }
    }
}

#[test]
fn public_version_has_source_spelling_and_all_three_binary_entrypoints() {
    let data = fixture();
    assert_eq!(
        strings(&data["entry_aliases"]),
        BTreeSet::from(["mb".into(), "mbcli".into(), "megabasterd-cli".into()])
    );
    let root = schema();
    assert_eq!(root.get_version(), Some(env!("CARGO_PKG_VERSION")));
    assert_eq!(
        flags(option(&root, "--version")),
        BTreeSet::from(["--version".into()])
    );
    assert!(
        Cli::try_parse_from(["mb", "-V"])
            .err()
            .is_some_and(|error| error.exit_code() == 2)
    );
    for executable in [
        env!("CARGO_BIN_EXE_mb"),
        env!("CARGO_BIN_EXE_mbcli"),
        env!("CARGO_BIN_EXE_megabasterd-cli"),
    ] {
        let output = run_binary(executable, &["--version"]);
        assert!(output.status.success());
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .contains(env!("CARGO_PKG_VERSION"))
        );
    }
}

#[test]
fn paired_flags_and_repeated_scalar_options_follow_source_last_occurrence_semantics() {
    for (pair, prefix) in [
        (["--log-file", "--no-log-file"], vec![]),
        (
            ["--verify", "--no-verify"],
            vec!["account", "add", "fixture@example.invalid"],
        ),
        (["--config-urls", "--no-config-urls"], vec!["proxy", "list"]),
    ] {
        for reversed in [false, true] {
            let mut args = vec!["mb"];
            args.extend(prefix.iter().copied());
            args.extend(if reversed {
                pair.into_iter().rev().collect::<Vec<_>>()
            } else {
                pair.to_vec()
            });
            if prefix.is_empty() {
                args.extend(["config", "path"]);
            }
            assert!(
                Cli::try_parse_from(args).is_ok(),
                "paired flags must allow last occurrence"
            );
        }
    }
    let root = schema();
    for (path, prefix, positive, negative) in [
        ("", vec!["mb"], "log_file", "no_log_file"),
        (
            "account add",
            vec!["mb", "account", "add", "fixture@example.invalid"],
            "verify",
            "no_verify",
        ),
        (
            "proxy list",
            vec!["mb", "proxy", "list"],
            "config_urls",
            "no_config_urls",
        ),
    ] {
        let positive_flag = format!("--{}", positive.replace('_', "-"));
        let negative_flag = format!("--{}", negative.replace('_', "-"));
        for enabled in [false, true] {
            let mut argv: Vec<String> = prefix.iter().map(|s| s.to_string()).collect();
            argv.extend(if enabled {
                vec![negative_flag.clone(), positive_flag.clone()]
            } else {
                vec![positive_flag.clone(), negative_flag.clone()]
            });
            if path.is_empty() {
                argv.extend(["config".into(), "path".into()]);
            }
            let parsed = root.clone().try_get_matches_from(argv).unwrap();
            let mut current = &parsed;
            for _ in path.split_whitespace() {
                current = current.subcommand().unwrap().1;
            }
            assert_eq!(
                !current.get_flag(negative),
                enabled,
                "{path} paired effective value"
            );
        }
    }
    let repeated = Cli::try_parse_from(["mb", "download", "--json", "--json"]).unwrap();
    assert!(matches!(repeated.command, Some(Command::Download(args)) if args.json));
    let parsed = Cli::try_parse_from([
        "mb",
        "download",
        "--workers",
        "2",
        "--workers",
        "3",
        "--include",
        "one",
        "-I",
        "two",
    ])
    .unwrap();
    assert!(
        matches!(parsed.command,Some(Command::Download(args)) if args.workers==Some(3) && args.include==["one","two"])
    );
}

#[test]
fn semantic_defaults_and_local_short_flags_do_not_collide_with_global_flags() {
    let untouched = Cli::try_parse_from(["mb", "config", "path"]).unwrap();
    assert_eq!(untouched.verbose, 0);
    assert!(!untouched.quiet && !untouched.log_file && !untouched.no_log_file);
    let parsed = Cli::try_parse_from([
        "mb",
        "-vv",
        "-q",
        "--no-log-file",
        "download",
        "-p",
        "secret",
        "-P",
        "3",
    ])
    .unwrap();
    assert_eq!(parsed.verbose, 2);
    assert!(parsed.quiet && parsed.no_log_file);
    assert!(
        matches!(parsed.command,Some(Command::Download(args)) if args.password.as_deref()==Some("secret") && args.parallel==Some(3))
    );
    assert!(
        matches!(Cli::try_parse_from(["mb","stream","url","-p","8081","-H","127.0.0.1"]).unwrap().command,
        Some(Command::Stream(args)) if args.port==Some(8081) && args.host.as_deref()==Some("127.0.0.1"))
    );
    assert!(Cli::try_parse_from(["mb", "stream", "url", "-P", "2"]).is_err());
    for flag in [
        "-v",
        "--verbose",
        "-q",
        "--quiet",
        "--log-file",
        "--no-log-file",
    ] {
        assert!(
            Cli::try_parse_from(["mb", "info", "url", flag]).is_err(),
            "source root flag was accepted after subcommand: {flag}"
        );
    }
    let defaults = Config::default();
    let actual = serde_json::to_value(defaults).unwrap();
    for (key, expected) in fixture()["config_defaults"].as_object().unwrap() {
        if expected.is_number() {
            assert_eq!(
                actual[key].as_f64(),
                expected.as_f64(),
                "config-driven default {key}"
            );
        } else {
            assert_eq!(&actual[key], expected, "config-driven default {key}");
        }
    }
    let root = schema();
    for path in ["account add", "proxy list"] {
        let mut args = vec!["mb"];
        args.extend(path.split_whitespace());
        if path == "account add" {
            args.push("fixture@example.invalid");
        }
        let parsed = root.clone().try_get_matches_from(args).unwrap();
        let mut current = &parsed;
        while let Some((_, child)) = current.subcommand() {
            current = child;
        }
        let negative = if path == "account add" {
            "no_verify"
        } else {
            "no_config_urls"
        };
        assert!(
            !current.get_flag(negative),
            "source effective default is true"
        );
    }
}

#[test]
fn watch_interval_and_proxy_enum_reject_source_invalid_values_at_parse_boundary() {
    for interval in ["0", "-1", "0.01", "3600.01", "nan", "inf"] {
        assert!(
            Cli::try_parse_from(["mb", "watch", "--interval", interval]).is_err(),
            "accepted interval {interval}"
        );
    }
    for interval in ["0.05", "1.5", "3600"] {
        assert!(Cli::try_parse_from(["mb", "watch", "--interval", interval]).is_ok());
    }
    for protocol in ["http", "socks4", "socks5"] {
        assert!(Cli::try_parse_from(["mb", "proxy", "fetch", "--protocol", protocol]).is_ok());
    }
    assert!(Cli::try_parse_from(["mb", "proxy", "fetch", "--protocol", "HTTP"]).is_err());
}

fn positional_value(spec: &Value, file: &Path, directory: &Path) -> OsString {
    match spec[1].as_str().unwrap() {
        "existing_file" => file.as_os_str().to_owned(),
        "existing_path" | "output_dir" => directory.as_os_str().to_owned(),
        "output_file" => directory.join("new output.bin").into_os_string(),
        "integer" => "1".into(),
        _ => "synthetic".into(),
    }
}

#[test]
fn required_variadic_positions_and_source_path_validation_are_preserved() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/cli-schema");
    std::fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    let directory = scratch.path().join("directory with spaces");
    std::fs::create_dir(&directory).unwrap();
    let file = directory.join("existing.bin");
    std::fs::write(&file, b"fixture").unwrap();
    let data = fixture();
    for record in data["commands"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v["kind"] == "command")
    {
        let prefix: Vec<OsString> = std::iter::once("mb")
            .chain(record["path"].as_str().unwrap().split_whitespace())
            .map(OsString::from)
            .collect();
        let specs = record["args"].as_array().unwrap();
        let mut arguments = prefix.clone();
        arguments.extend(
            specs
                .iter()
                .map(|spec| positional_value(spec, &file, &directory)),
        );
        assert!(
            Cli::try_parse_from(arguments.clone()).is_ok(),
            "valid baseline arguments {}",
            record["path"]
        );
        let mut surplus = arguments.clone();
        surplus.extend([OsString::from("extra"), OsString::from("another")]);
        let variadic = specs.last().is_some_and(|spec| spec[3].is_null());
        if variadic {
            surplus[arguments.len()] = positional_value(specs.last().unwrap(), &file, &directory);
            surplus[arguments.len() + 1] = surplus[arguments.len()].clone();
        }
        assert_eq!(
            Cli::try_parse_from(surplus).is_ok(),
            variadic,
            "positional surplus {}",
            record["path"]
        );
        for (index, spec) in specs.iter().enumerate() {
            if spec[2].as_u64().unwrap() > 0 {
                let mut missing = arguments.clone();
                missing.remove(prefix.len() + index);
                assert!(
                    Cli::try_parse_from(missing).is_err(),
                    "missing required positional {}",
                    record["path"]
                );
            }
            if spec[1] == "existing_file" || spec[1] == "existing_path" {
                let mut missing = arguments.clone();
                missing[prefix.len() + index] = directory.join("absent.bin").into_os_string();
                assert!(
                    Cli::try_parse_from(missing).is_err(),
                    "nonexistent source {}",
                    record["path"]
                );
            }
            if spec[1] == "existing_file" || spec[1] == "output_file" {
                let mut wrong = arguments.clone();
                wrong[prefix.len() + index] = directory.clone().into_os_string();
                assert!(
                    Cli::try_parse_from(wrong).is_err(),
                    "directory used as file {}",
                    record["path"]
                );
            }
        }
        for key in record["options"].as_array().unwrap() {
            let option = &data["options"][key.as_str().unwrap()];
            let kind = option["type"].as_str().unwrap();
            if !matches!(kind, "existing_file" | "output_file" | "output_dir") {
                continue;
            }
            let flag = option["flags"][0].as_str().unwrap();
            let mut invalid = arguments.clone();
            invalid.extend([
                OsString::from(flag),
                match kind {
                    "output_dir" => file.clone().into_os_string(),
                    "output_file" => directory.clone().into_os_string(),
                    _ => directory.join("absent.bin").into_os_string(),
                },
            ]);
            assert!(
                Cli::try_parse_from(invalid).is_err(),
                "invalid option path {} {flag}",
                record["path"]
            );
        }
    }
}

fn run_binary(executable: &str, arguments: &[&str]) -> process::ProcessOutput {
    process::run(
        Path::new(executable),
        &arguments.iter().map(OsString::from).collect::<Vec<_>>(),
        Duration::from_secs(5),
        64 * 1024,
        64 * 1024,
        &Control::new(),
    )
    .unwrap()
}

#[test]
fn nested_binary_help_and_usage_errors_preserve_machine_stdout_without_runtime_setup() {
    for command in [
        vec!["queue", "run", "--help"],
        vec!["crypter", "encrypt", "-h"],
        vec!["trash", "empty", "--help"],
    ] {
        let output = run_binary(env!("CARGO_BIN_EXE_mb"), &command);
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(text.contains("Usage:") && text.contains("--help"));
    }
    for command in [
        vec!["download", "--json", "--not-a-real-option"],
        vec!["upload", "--json", "--not-a-real-option"],
        vec!["info", "--json", "--not-a-real-option"],
    ] {
        let output = run_binary(env!("CARGO_BIN_EXE_mb"), &command);
        assert_eq!(output.status.code(), Some(2));
        let text = String::from_utf8(output.stdout).unwrap();
        let records: Vec<_> = text
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["status"], "failed");
        assert_eq!(records[0]["error_code"], "invalid_input");
        assert!(!output.stderr.is_empty());
    }
}
