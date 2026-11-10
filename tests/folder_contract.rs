#![allow(clippy::unwrap_used)]
use megabasterd_cli::protocol::nodes::Node;
use megabasterd_cli::transfers::{
    folders,
    planner::{Filter, Job, filename},
};

#[test]
fn filenames_and_include_paths_keep_double_spaces_and_stay_single_component() {
    assert_eq!(filename("OAD -  09v2.mkv"), "OAD -  09v2.mkv");
    for hostile in ["..", "../escape", "CON.txt", "foo:bar", "", "... "] {
        let safe = filename(hostile);
        assert!(!safe.is_empty());
        assert!(!safe.contains(['/', '\\', ':']));
        assert_ne!(safe, "..");
    }
    let long = format!("{}.mkv", "測".repeat(120));
    let safe = filename(&long);
    assert!(safe.len() <= 240);
    assert!(safe.ends_with(".mkv"));
    let job = Job {
        relative: "Show/OAD -  09v2.mkv".into(),
        node: Node {
            handle: "file".into(),
            parent: "root".into(),
            node_type: 0,
            size: 12,
            timestamp: 0,
            name: "OAD -  09v2.mkv".into(),
            raw_key: None,
            encrypted_attrs: None,
            attrs: serde_json::json!({}),
        },
    };
    assert!(
        Filter::new(&["Show/OAD -  09v2.mkv".into()], &[])
            .unwrap()
            .accepts(&job)
    );
    assert!(
        !Filter::new(&["*.mkv".into()], &["*09v2*".into()])
            .unwrap()
            .accepts(&job)
    );
}

#[test]
fn filename_source_literals_preserve_valid_names_and_neutralize_unsafe_components() {
    assert_eq!(filename("a<b>c:d\"e/f\\g|h?i*j"), "a_b_c_d_e_f_g_h_i_j");
    assert!(filename("CON.txt").starts_with("_CON"));
    assert!(filename("LPT1.dat").starts_with("_LPT1"));
    assert_eq!(filename(""), "unnamed");
    for name in [".", "..", "...", "   ", "", ". .", " .. ", "....", "\t"] {
        let safe = filename(name);
        assert!(!safe.is_empty());
        assert!(!safe.chars().all(|character| character == '.'));
        assert!(!safe.contains(['/', '\\']));
        assert_ne!(safe, ".");
        assert_ne!(safe, "..");
    }
    assert!(!filename("a/b/c").contains('/'));
    assert!(!filename("a\\b\\c").contains('\\'));
    assert_eq!(filename(".gitignore"), ".gitignore");
    assert_eq!(filename("evil."), "evil");
    assert_eq!(filename("name "), "name");
    assert_eq!(filename("漢字.mkv"), "漢字.mkv");
    let unicode = "Película Año 2024 — épisode.mkv";
    assert_eq!(filename(unicode), unicode);
}

#[test]
fn filename_byte_limits_preserve_short_extensions_and_complete_utf8_characters() {
    for (name, extension) in [
        (format!("{}.mkv", "a".repeat(260)), ".mkv"),
        (format!("{}.mkv", "漢".repeat(300)), ".mkv"),
        (format!("{}.mp4", "😀".repeat(200)), ".mp4"),
    ] {
        let safe = filename(&name);
        assert!(safe.len() <= 240);
        assert!(safe.ends_with(extension));
        assert_eq!(std::str::from_utf8(safe.as_bytes()).unwrap(), safe);
        assert!(!safe.contains('\u{fffd}'));
    }
    for repeat in 60..130 {
        let safe = filename(&"é中😀".repeat(repeat));
        assert!(safe.len() <= 255);
        assert_eq!(std::str::from_utf8(safe.as_bytes()).unwrap(), safe);
    }
    let safe = filename(&format!("{}.{}", "漢".repeat(300), "x".repeat(60)));
    assert!(safe.len() <= 255);
    assert!(!safe.ends_with(&format!(".{}", "x".repeat(60))));
}

#[test]
fn filename_truncation_reapplies_trailing_and_empty_component_guards() {
    for pad in 230..246 {
        for tail in [".", " "] {
            let safe = filename(&format!("{}{tail}{}", "a".repeat(pad), "b".repeat(50)));
            assert!(!safe.ends_with([' ', '.']));
            assert!(!safe.is_empty());
            assert!(safe.len() <= 240);
        }
    }
    // A long extension is discarded, exposing an entirely dot-only truncated stem.
    assert_eq!(
        filename(&format!("{}{}", ".".repeat(240), "x".repeat(60))),
        "unnamed"
    );
}

fn job(name: &str, relative: &str) -> Job {
    Job {
        relative: relative.into(),
        node: Node {
            handle: format!("h-{name}"),
            parent: "root".into(),
            node_type: 0,
            size: 100,
            timestamp: 0,
            name: name.into(),
            raw_key: None,
            encrypted_attrs: None,
            attrs: serde_json::json!({"n":name}),
        },
    }
}

#[test]
fn exact_source_folder_filters_preserve_paths_case_separators_and_exclude_precedence() {
    let cases = [
        (
            vec![job("a.mkv", "Show/a.mkv"), job("a.srt", "Show/a.srt")],
            vec!["*.mkv"],
            vec![],
            vec!["a.mkv"],
        ),
        (
            vec![
                job("e1.mkv", "Show/Season 1/e1.mkv"),
                job("e2.mkv", "Show/Season 2/e2.mkv"),
            ],
            vec!["Show/Season 1/*"],
            vec![],
            vec!["e1.mkv"],
        ),
        (
            vec![
                job("e1.mkv", "Show/e1.mkv"),
                job("e1.sample.mkv", "Show/e1.sample.mkv"),
            ],
            vec!["*.mkv"],
            vec!["*sample*"],
            vec!["e1.mkv"],
        ),
        (
            vec![job("E1.MKV", "Show/Season 1/E1.MKV")],
            vec!["season 1/*.mkv"],
            vec![],
            vec!["E1.MKV"],
        ),
        (
            vec![job("e1.mkv", "Show/Season 1/e1.mkv")],
            vec!["Show\\Season 1\\*"],
            vec![],
            vec!["e1.mkv"],
        ),
        (
            vec![
                job("e1.mkv", "Show/e1.mkv"),
                job("readme.txt", "Show/readme.txt"),
            ],
            vec![],
            vec!["*.txt"],
            vec!["e1.mkv"],
        ),
    ];
    for (jobs, include, exclude, expected) in cases {
        let includes: Vec<_> = include.into_iter().map(String::from).collect();
        let excludes: Vec<_> = exclude.into_iter().map(String::from).collect();
        let selected = folders::select_jobs(jobs, &includes, &excludes, None).unwrap();
        assert_eq!(
            selected
                .iter()
                .map(|job| job.node.name.as_str())
                .collect::<Vec<_>>(),
            expected
        );
    }
    let jobs = vec![job("a.mkv", "Show/a.mkv"), job("a.srt", "Show/a.srt")];
    let selected = folders::select_jobs(jobs.clone(), &[], &[], None).unwrap();
    assert_eq!(
        selected
            .iter()
            .map(|job| job.node.name.as_str())
            .collect::<Vec<_>>(),
        vec!["a.mkv", "a.srt"]
    );
    assert!(
        jobs.iter()
            .all(|job| Filter::new(&[], &[]).unwrap().accepts(job))
    );
    let error = folders::select_jobs(jobs, &["*.iso".into()], &[], None)
        .err()
        .unwrap();
    assert!(error.to_string().contains("matched no files"));
    assert_eq!(error.code(), "transfer_failed");
    assert_eq!(error.exit_code(), 1);
}

#[test]
fn folder_filters_use_full_unicode_folding_scalar_wildcards_and_literal_braces() {
    for (name, pattern, expected) in [
        ("Straße.mkv", "STRASSE.*", true),
        ("Σ.mkv", "ς.*", true),
        ("Öş.mkv", "?Ş.*", true),
        ("Öş.mkv", "??.*", true),
        ("Öş.mkv", "???.*", false),
        ("ﬃ.mkv", "FFI.*", true),
        ("İ.mkv", "i\u{307}.*", true),
        ("𐐨.mkv", "𐐀.*", true),
        ("a.mkv", "{a,b}.mkv", false),
        ("{a,b}.mkv", "{a,b}.mkv", true),
        ("[abc.mkv", "[abc.*", true),
        ("^a.mkv", "[^b]a.*", true),
        ("a.mkv", "[z-a].*", false),
        ("a.mkv", "[!z-a].*", true),
        // Independent Python oracle: removing a reversed range can expose a negation marker.
        ("c", "[b-a!]", true),
        ("!", "[b-!!]", true),
        ("c", "[b-!!]", true),
    ] {
        let candidate = job(name, &format!("Show/{name}"));
        let include = Filter::new(&[pattern.into()], &[]).unwrap();
        assert_eq!(include.accepts(&candidate), expected, "{name} {pattern}");
    }
    let candidate = job("Straße.mkv", "Show/Straße.mkv");
    assert!(
        !Filter::new(&["*.mkv".into()], &["STRASSE.*".into()])
            .unwrap()
            .accepts(&candidate)
    );
    let sanitized = job("Straße.mkv", "Show/different.bin");
    assert!(
        Filter::new(&["STRASSE.*".into()], &[])
            .unwrap()
            .accepts(&sanitized)
    );
    assert!(Filter::new(&vec!["x".into(); 1025], &[]).is_err());
    assert!(Filter::new(&["x".repeat(64 * 1024 + 1)], &[]).is_err());
    let mut combined = vec!["x".repeat(64 * 1024); 16];
    combined.push("x".into());
    assert!(Filter::new(&combined, &[]).is_err());
    assert!(Filter::new(&[], &combined).is_err());
}
