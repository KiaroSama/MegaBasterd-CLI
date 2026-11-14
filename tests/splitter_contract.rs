use megabasterd_cli::{
    error::{Error, Result},
    services::splitter::{merge_parts, split_file},
};
use serde_json::Value;
use std::{fs, path::Path};

fn payload() -> Vec<u8> {
    let mut bytes: Vec<u8> = (0..=255u8).cycle().take(1024 * 1024).collect();
    bytes.extend_from_slice(b"odd tail");
    bytes
}

#[test]
fn source_part_names_sha1_newline_and_any_part_merge_are_preserved() -> Result<()> {
    let data: Value = serde_json::from_str(include_str!("fixtures/local_file_services.json"))?;
    let directory = private_tempfile::tempdir()?;
    let source = directory.path().join("split.bin");
    fs::write(&source, payload())?;
    let result = split_file(&source, 1, None, false, None)?;
    let names: Vec<_> = result
        .parts
        .iter()
        .map(|p| {
            p.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        })
        .collect();
    assert_eq!(serde_json::to_value(names)?, data["split"]["part_names"]);
    assert_eq!(result.total_bytes, 1048584);
    assert_eq!(
        fs::read_to_string(directory.path().join("split.bin.sha1"))?,
        data["split"]["sha1_file"].as_str().unwrap_or_default()
    );
    assert_eq!(result.sha1, "3ebb313d44ab7656d41cc3882700feccc7351379");
    let output = directory.path().join("merged");
    assert_eq!(
        merge_parts(&result.parts[1], Some(&output), true, false, false, None)?,
        output
    );
    assert_eq!(fs::read(output)?, payload());
    assert!(result.parts.iter().all(|p| p.exists()));
    Ok(())
}

#[test]
fn exact_four_part_roundtrip_and_late_interruption_keep_completed_parts_only() -> Result<()> {
    use sha1::{Digest, Sha1};
    let directory = private_tempfile::tempdir()?;
    let source = directory.path().join("data.bin");
    let bytes: Vec<_> = (0..3 * 1024 * 1024 + 17)
        .map(|index| (index % 251) as u8)
        .collect();
    fs::write(&source, &bytes)?;
    let complete = directory.path().join("complete");
    let split = split_file(&source, 1, Some(&complete), false, None)?;
    assert_eq!(split.parts.len(), 4);
    for (index, part) in split.parts.iter().enumerate() {
        assert_eq!(
            fs::metadata(part)?.len(),
            if index == 3 { 17 } else { 1024 * 1024 }
        );
    }
    assert_eq!(split.sha1, hex::encode(Sha1::digest(&bytes)));
    let merged = directory.path().join("merged.bin");
    merge_parts(&split.parts[0], Some(&merged), true, false, false, None)?;
    assert_eq!(fs::read(&merged)?, bytes);

    let interrupted = directory.path().join("interrupted");
    let mut observed = Vec::new();
    let mut stop = |done, total| {
        observed.push((done, total));
        if done > 1024 * 1024 {
            Err(Error::Canceled)
        } else {
            Ok(())
        }
    };
    assert!(matches!(
        split_file(&source, 1, Some(&interrupted), false, Some(&mut stop)),
        Err(Error::Canceled)
    ));
    assert_eq!(observed.len(), 2);
    assert_eq!(observed[0], (1024 * 1024, bytes.len() as u64));
    assert!(observed[1].0 > 1024 * 1024);
    assert_eq!(
        fs::read(interrupted.join("data.bin.part1-4"))?,
        bytes[..1024 * 1024]
    );
    for index in 2..=4 {
        assert!(!interrupted.join(format!("data.bin.part{index}-4")).exists());
    }
    assert!(!interrupted.join("data.bin.sha1").exists());
    assert_eq!(fs::read(source)?, bytes);
    no_staging(&complete)?;
    no_staging(&interrupted)?;
    no_staging(directory.path())?;
    Ok(())
}

#[test]
fn checksum_mismatch_missing_parts_and_bad_sidecar_preserve_target_and_parts() -> Result<()> {
    let directory = private_tempfile::tempdir()?;
    let source = directory.path().join("split.bin");
    fs::write(&source, payload())?;
    let result = split_file(&source, 1, None, false, None)?;
    let output = directory.path().join("precious");
    fs::write(&output, b"original")?;
    let checksum = directory.path().join("split.bin.sha1");
    for text in [
        "0000000000000000000000000000000000000000\n",
        "",
        "not a checksum",
    ] {
        fs::write(&checksum, text)?;
        assert!(merge_parts(&result.parts[0], Some(&output), true, true, true, None).is_err());
        assert_eq!(fs::read(&output)?, b"original");
        assert!(result.parts.iter().all(|p| p.exists()));
        no_staging(directory.path())?;
    }
    fs::write(&checksum, "3ebb313d44ab7656d41cc3882700feccc7351379\n")?;
    let mut mutate_stage = |done: u64, total: u64| -> Result<()> {
        if done == total {
            let stage = fs::read_dir(directory.path())?
                .find_map(|entry| {
                    let entry = entry.ok()?;
                    entry
                        .file_name()
                        .to_string_lossy()
                        .ends_with(".tmp")
                        .then(|| entry.path())
                })
                .ok_or_else(|| Error::invalid("Expected a live merge stage"))?;
            use std::io::Write;
            fs::OpenOptions::new()
                .write(true)
                .open(stage)?
                .write_all(b"X")?;
        }
        Ok(())
    };
    // A second disk pass must notice that accepted writes differ from persisted bytes.
    assert!(
        merge_parts(
            &result.parts[0],
            Some(&output),
            true,
            true,
            true,
            Some(&mut mutate_stage)
        )
        .is_err()
    );
    assert_eq!(fs::read(&output)?, b"original");
    assert!(result.parts.iter().all(|p| p.exists()));
    no_staging(directory.path())?;
    fs::remove_file(&result.parts[1])?;
    assert!(merge_parts(&result.parts[0], Some(&output), false, false, true, None).is_err());
    assert_eq!(fs::read(output)?, b"original");
    Ok(())
}

#[test]
fn exact_source_sha1_mismatches_preserve_absent_and_precious_destinations() -> Result<()> {
    let directory = private_tempfile::tempdir()?;
    let output = directory.path().join("out.bin");
    for (name, bytes, original) in [
        ("foo.bin", b"hello world ".repeat(1000), None),
        (
            "data.bin",
            b"abcdefgh".repeat(40_000),
            Some(b"precious".as_slice()),
        ),
    ] {
        let source = directory.path().join(name);
        fs::write(&source, &bytes)?;
        let split = split_file(&source, 1, None, false, None)?;
        let checksum = directory.path().join(format!("{name}.sha1"));
        let bad_checksum = b"0000000000000000000000000000000000000000\n";
        fs::write(&checksum, bad_checksum)?;
        if let Some(original) = original {
            fs::write(&output, original)?;
        }
        assert!(matches!(
            merge_parts(&split.parts[0], Some(&output), true, true, original.is_some(), None),
            Err(Error::Integrity(message)) if message.contains("SHA-1 mismatch")
        ));
        match original {
            Some(original) => assert_eq!(fs::read(&output)?, original),
            None => assert!(!output.exists()),
        }
        assert_eq!(fs::read(&source)?, bytes);
        assert_eq!(fs::read(&split.parts[0])?, bytes);
        assert_eq!(fs::read(&checksum)?, bad_checksum);
        no_staging(directory.path())?;
    }
    Ok(())
}

#[test]
fn deletion_requires_flag_and_happens_only_after_verified_success() -> Result<()> {
    let directory = private_tempfile::tempdir()?;
    let source = directory.path().join("source");
    fs::write(&source, b"known input")?;
    let result = split_file(&source, 1, None, false, None)?;
    let output = directory.path().join("output");
    merge_parts(&result.parts[0], Some(&output), true, false, false, None)?;
    assert!(result.parts[0].exists());
    merge_parts(&result.parts[0], Some(&output), true, true, true, None)?;
    assert_eq!(fs::read(output)?, b"known input");
    assert!(!result.parts[0].exists());
    assert!(!directory.path().join("source.sha1").exists());
    assert_eq!(fs::read(source)?, b"known input");
    Ok(())
}

#[test]
fn source_and_output_hardlink_aliases_are_refused_before_any_publication() -> Result<()> {
    let directory = private_tempfile::tempdir()?;
    let source = directory.path().join("source");
    fs::write(&source, b"known input")?;
    let parts = directory.path().join("parts");
    fs::create_dir(&parts)?;
    let alias = parts.join("source.part1-1");
    fs::hard_link(&source, &alias)?;
    assert!(split_file(&source, 1, Some(&parts), true, None).is_err());
    assert_eq!(fs::read(&source)?, b"known input");
    fs::remove_file(alias)?;
    let result = split_file(&source, 1, Some(&parts), false, None)?;
    assert!(
        merge_parts(
            &result.parts[0],
            Some(&result.parts[0]),
            true,
            false,
            true,
            None
        )
        .is_err()
    );
    let alias = directory.path().join("alias");
    fs::hard_link(&result.parts[0], &alias)?;
    assert!(merge_parts(&result.parts[0], Some(&alias), true, false, true, None).is_err());
    fs::remove_file(alias)?;
    let checksum = parts.join("source.sha1");
    let checksum_before = fs::read(&checksum)?;
    assert!(matches!(
        merge_parts(&result.parts[0], Some(&checksum), false, false, true, None),
        Err(Error::Invalid(message)) if message.contains("same file")
    ));
    assert_eq!(fs::read(checksum)?, checksum_before);
    no_staging(directory.path())?;
    no_staging(&parts)?;
    assert_eq!(fs::read(&result.parts[0])?, b"known input");
    Ok(())
}

#[test]
fn parent_traversal_spelling_of_a_later_input_part_is_refused_without_writes() -> Result<()> {
    let directory = private_tempfile::tempdir()?;
    let source = directory.path().join("data.bin");
    let bytes = b"abcdefgh".repeat(160_000);
    fs::write(&source, &bytes)?;
    let split = split_file(&source, 1, None, false, None)?;
    assert_eq!(split.parts.len(), 2);
    fs::create_dir(directory.path().join("sub"))?;
    let alias = directory.path().join("sub").join("..").join(
        split.parts[1]
            .file_name()
            .ok_or_else(|| Error::invalid("Part fixture needs a filename"))?,
    );
    let before = fs::read(&split.parts[1])?;
    let checksum = directory.path().join("data.bin.sha1");
    let checksum_before = fs::read(&checksum)?;
    let mut entered = false;
    let mut observe = |_, _| {
        entered = true;
        Ok(())
    };
    assert!(matches!(
        merge_parts(&split.parts[0], Some(&alias), true, true, true, Some(&mut observe)),
        Err(Error::Invalid(message)) if message.contains("parent traversal")
    ));
    assert!(!entered, "traversal must be refused before writing a stage");
    assert_eq!(fs::read(&split.parts[1])?, before);
    assert_eq!(fs::read(&split.parts[0])?, bytes[..1024 * 1024]);
    assert_eq!(fs::read(&source)?, bytes);
    assert_eq!(fs::read(&checksum)?, checksum_before);
    assert_eq!(fs::read_dir(directory.path().join("sub"))?.count(), 0);
    no_staging(directory.path())?;
    Ok(())
}

#[test]
fn cancellation_no_clobber_empty_and_overflow_do_not_publish_partial_outputs() -> Result<()> {
    let directory = private_tempfile::tempdir()?;
    let source = directory.path().join("source");
    fs::write(&source, payload())?;
    let mut canceled = |_, _| Err(Error::Canceled);
    assert!(matches!(
        split_file(&source, 1, None, false, Some(&mut canceled)),
        Err(Error::Canceled)
    ));
    assert!(!directory.path().join("source.part1-2").exists());
    no_staging(directory.path())?;
    let result = split_file(&source, 1, None, false, None)?;
    let absent = directory.path().join("absent");
    assert!(matches!(
        merge_parts(
            &result.parts[0],
            Some(&absent),
            true,
            false,
            false,
            Some(&mut canceled)
        ),
        Err(Error::Canceled)
    ));
    assert!(!absent.exists());
    no_staging(directory.path())?;
    let output = directory.path().join("precious");
    fs::write(&output, b"original")?;
    assert!(merge_parts(&result.parts[0], Some(&output), true, false, false, None).is_err());
    assert!(matches!(
        merge_parts(
            &result.parts[0],
            Some(&output),
            true,
            true,
            true,
            Some(&mut canceled)
        ),
        Err(Error::Canceled)
    ));
    assert_eq!(fs::read(output)?, b"original");
    assert!(result.parts.iter().all(|p| p.exists()));
    assert!(split_file(&source, u64::MAX, None, false, None).is_err());
    let empty = directory.path().join("empty");
    fs::write(&empty, [])?;
    assert!(split_file(&empty, 1, None, false, None).is_err());
    no_staging(directory.path())?;
    Ok(())
}

#[test]
fn explicit_no_verify_accepts_bad_checksum_but_malformed_part_numbers_are_refused() -> Result<()> {
    let directory = private_tempfile::tempdir()?;
    let part = directory.path().join("base.part1-1");
    fs::write(&part, b"content")?;
    fs::write(directory.path().join("base.sha1"), "not a checksum")?;
    let output = merge_parts(&part, None, false, false, false, None)?;
    assert_eq!(fs::read(&output)?, b"content");
    // Python's Unicode-decimal regex accepts this selector, then reconstructs ASCII sibling names.
    merge_parts(
        &directory.path().join("base.part١-١"),
        Some(&output),
        false,
        false,
        true,
        None,
    )?;
    assert_eq!(fs::read(output)?, b"content");
    for name in [
        "not-a-part.bin",
        "base.part0-1",
        "base.part2-1",
        "base.part1-0",
        "base.part1-18446744073709551615",
        "base.partx-1",
    ] {
        assert!(
            merge_parts(
                &directory.path().join(name),
                None,
                false,
                false,
                false,
                None
            )
            .is_err()
        );
    }
    Ok(())
}

fn no_staging(directory: &Path) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        assert!(!entry?.file_name().to_string_lossy().ends_with(".tmp"));
    }
    Ok(())
}

#[path = "common/private_tempfile.rs"]
mod private_tempfile;
