use std::{fs, path::Path};

use megabasterd_cli::{
    error::{Error, Result},
    services::local_crypto::{MAX_CHUNK_SIZE, decrypt_file, encrypt_file},
};
use serde_json::Value;

fn fixture() -> Result<Value> {
    Ok(serde_json::from_str(include_str!(
        "fixtures/local_file_services.json"
    ))?)
}

#[test]
fn reads_source_mbcr_v2_empty_multichunk_and_legacy_with_warning() -> Result<()> {
    let directory = private_tempfile::tempdir()?;
    for case in fixture()?["mbcr"]
        .as_array()
        .ok_or_else(|| Error::invalid("Fixture cases"))?
    {
        let input = directory.path().join("input.mbcr");
        let output = directory.path().join("output");
        fs::write(
            &input,
            hex::decode(case["blob_hex"].as_str().unwrap_or_default())
                .map_err(|_| Error::invalid("Fixture hex"))?,
        )?;
        let result = decrypt_file(
            &input,
            &output,
            case["password"].as_str().unwrap_or_default(),
            true,
            None,
        )?;
        assert_eq!(hex::encode(fs::read(&output)?), case["plaintext_hex"]);
        assert_eq!(
            u64::from(result.version),
            case["version"].as_u64().unwrap_or_default()
        );
        assert_eq!(result.warning.is_some(), result.version == 1);
        if let Some(warning) = result.warning {
            assert!(warning.contains("sequence") && warning.contains("legacy"));
        }
    }
    Ok(())
}

#[test]
fn v2_writer_preserves_empty_and_odd_tail_and_reports_plaintext_progress() -> Result<()> {
    let directory = private_tempfile::tempdir()?;
    for (bytes, chunk_size, password) in [
        (Vec::new(), 16, "synthetic"),
        (b"hello".to_vec(), 64 * 1024, "synthetic"),
        ((0..=72u8).collect(), 16, "synthetic"),
        (vec![0x5a; 300 * 1024], 64 * 1024, "synthetic"),
        (vec![0xa5; 300 * 1024 + 123], 64 * 1024, "synthetic"),
        (b"payload ".repeat(50), 64 * 1024, "pw"),
    ] {
        let input = directory.path().join("plain");
        let encrypted = directory.path().join("encrypted");
        let output = directory.path().join("recovered");
        fs::write(&input, &bytes)?;
        let mut progress = Vec::new();
        let mut callback = |done, total| {
            progress.push((done, total));
            Ok(())
        };
        let result = encrypt_file(
            &input,
            &encrypted,
            password,
            chunk_size,
            true,
            Some(&mut callback),
        )?;
        assert_eq!(result.bytes, bytes.len() as u64);
        assert_eq!(
            progress.last().copied(),
            Some((bytes.len() as u64, bytes.len() as u64))
        );
        let blob = fs::read(&encrypted)?;
        assert_eq!(&blob[..5], b"MBCR\x02");
        if bytes.is_empty() {
            assert_eq!(blob.len(), 66);
        }
        decrypt_file(&encrypted, &output, password, true, None)?;
        assert_eq!(fs::read(&output)?, bytes);
    }
    Ok(())
}

fn records(blob: &[u8]) -> Vec<Vec<u8>> {
    let mut offset = 33;
    let mut result = Vec::new();
    while offset < blob.len() {
        let length = u32::from_be_bytes(blob[offset + 1..offset + 5].try_into().unwrap_or_default())
            as usize;
        let next = offset + 5 + length;
        result.push(blob[offset..next].to_vec());
        offset = next;
    }
    result
}

#[test]
fn source_sequence_tampering_and_wrong_password_preserve_existing_destination() -> Result<()> {
    let data = fixture()?;
    let case = &data["mbcr"][1];
    let blob = hex::decode(case["blob_hex"].as_str().unwrap_or_default())
        .map_err(|_| Error::invalid("Fixture hex"))?;
    let chunks = records(&blob);
    let header = &blob[..33];
    let mut attacks = Vec::new();
    let mut reordered = chunks.clone();
    reordered.swap(0, 1);
    let mut duplicated = chunks.clone();
    duplicated.insert(1, duplicated[1].clone());
    let mut omitted = chunks.clone();
    omitted.remove(2);
    for parts in [
        reordered,
        duplicated,
        omitted,
        chunks[..chunks.len() - 1].to_vec(),
    ] {
        attacks.push([header.to_vec(), parts.concat()].concat());
    }
    let mut appended = blob.clone();
    appended.extend([1; 32]);
    attacks.push(appended);
    let mut salt = blob.clone();
    salt[6] ^= 0xff;
    attacks.push(salt);
    let mut final_flag = blob.clone();
    let index = blob.len() - chunks.last().map_or(0, Vec::len);
    final_flag[index] = 0;
    attacks.push(final_flag);
    let mut length = blob.clone();
    length[32] ^= 1;
    attacks.push(length);
    let mut impossible_length = blob.clone();
    impossible_length[25] ^= 0xff;
    attacks.push(impossible_length);
    let mut bitflip = blob.clone();
    bitflip[60] ^= 1;
    attacks.push(bitflip);
    attacks.push([header.to_vec(), chunks[0].clone(), vec![0; 5]].concat());
    let directory = private_tempfile::tempdir()?;
    let input = directory.path().join("input");
    let output = directory.path().join("precious");
    fs::write(&output, b"original")?;
    for attack in attacks {
        fs::write(&input, attack)?;
        assert!(
            decrypt_file(
                &input,
                &output,
                case["password"].as_str().unwrap_or_default(),
                true,
                None
            )
            .is_err()
        );
        assert_eq!(fs::read(&output)?, b"original");
        assert_no_staging(directory.path())?;
    }
    fs::write(&input, blob)?;
    let mut canceled = |_, _| Err(Error::Canceled);
    assert!(matches!(
        decrypt_file(
            &input,
            &output,
            case["password"].as_str().unwrap_or_default(),
            true,
            Some(&mut canceled)
        ),
        Err(Error::Canceled)
    ));
    assert_eq!(fs::read(&output)?, b"original");
    assert_no_staging(directory.path())?;
    assert!(matches!(
        decrypt_file(&input, &output, "incorrect", true, None),
        Err(Error::Integrity(_))
    ));
    assert_eq!(fs::read(&output)?, b"original");
    assert_no_staging(directory.path())?;
    Ok(())
}

#[test]
fn failed_legacy_authentication_preserves_exact_original_destination_without_staging() -> Result<()>
{
    let directory = private_tempfile::tempdir()?;
    let input = directory.path().join("legacy.mbcr");
    let output = directory.path().join("important.txt");
    let original = b"irreplaceable user data\n".repeat(40);
    let mut blob = b"MBCR\x01".to_vec();
    blob.extend([0; 16]);
    blob.extend(64u32.to_be_bytes());
    blob.extend(28u32.to_be_bytes());
    blob.extend([0; 28]);
    fs::write(&input, &blob)?;
    fs::write(&output, &original)?;
    assert!(matches!(
        decrypt_file(&input, &output, "correct horse battery staple", true, None),
        Err(Error::Integrity(_))
    ));
    assert_eq!(fs::read(&output)?, original);
    assert_eq!(fs::read(&input)?, blob);
    assert_no_staging(directory.path())?;
    Ok(())
}

#[test]
fn exact_small_default_chunk_roundtrip_keeps_source_payload_and_bounded_format_overhead()
-> Result<()> {
    let directory = private_tempfile::tempdir()?;
    let input = directory.path().join("input.bin");
    let encrypted = directory.path().join("input.enc");
    let output = directory.path().join("output.bin");
    let bytes = b"Hello, MegaBasterd CLI! ".repeat(100);
    fs::write(&input, &bytes)?;
    encrypt_file(
        &input,
        &encrypted,
        "secret-pass",
        megabasterd_cli::services::local_crypto::DEFAULT_CHUNK_SIZE,
        false,
        None,
    )?;
    let encrypted_size = fs::metadata(&encrypted)?.len();
    assert!(encrypted_size > bytes.len() as u64);
    assert!(encrypted_size < bytes.len() as u64 + 1024);
    fs::write(&output, b"irreplaceable user data\n".repeat(40))?;
    decrypt_file(&encrypted, &output, "secret-pass", true, None)?;
    assert_eq!(fs::read(&output)?, bytes);
    assert_no_staging(directory.path())?;
    Ok(())
}

#[test]
fn invalid_header_bounds_are_rejected_as_input_before_authentication() -> Result<()> {
    let directory = private_tempfile::tempdir()?;
    let input = directory.path().join("input");
    let output = directory.path().join("output");
    for (chunk, original) in [
        (0, 0),
        (MAX_CHUNK_SIZE + 1, 0),
        (16, 1 << 40),
        (16, u64::MAX),
    ] {
        let mut blob = b"MBCR\x02".to_vec();
        blob.extend([0; 16]);
        blob.extend((chunk as u32).to_be_bytes());
        blob.extend(original.to_be_bytes());
        fs::write(&input, blob)?;
        assert!(matches!(
            decrypt_file(&input, &output, "synthetic", false, None),
            Err(Error::Invalid(_))
        ));
        assert!(!output.exists());
    }
    for blob in [
        b"this is not a crypter blob".to_vec(),
        [b"MBCR\x63".to_vec(), vec![0; 40]].concat(),
    ] {
        fs::write(&input, &blob)?;
        let expected = if blob.starts_with(b"MBCR") {
            "version"
        } else {
            "magic"
        };
        assert!(matches!(
            decrypt_file(&input, &output, "synthetic", false, None),
            Err(Error::Invalid(message)) if message.contains(expected)
        ));
        assert!(!output.exists());
        assert_no_staging(directory.path())?;
    }
    for version in [1, 2] {
        let mut blob = b"MBCR".to_vec();
        blob.push(version);
        blob.extend([0; 16]);
        blob.extend(16u32.to_be_bytes());
        if version == 2 {
            blob.extend(0u64.to_be_bytes());
            blob.push(1);
        }
        blob.extend(u32::MAX.to_be_bytes());
        fs::write(&input, blob)?;
        assert!(matches!(
            decrypt_file(&input, &output, "synthetic", false, None),
            Err(Error::Integrity(message)) if message.contains("exceeds header chunk size")
        ));
        assert!(!output.exists());
        assert_no_staging(directory.path())?;
    }
    Ok(())
}

#[test]
fn aliases_no_clobber_and_callback_failure_never_damage_input_or_existing_output() -> Result<()> {
    let directory = private_tempfile::tempdir()?;
    let input = directory.path().join("input");
    let output = directory.path().join("output");
    fs::write(&input, b"source")?;
    fs::write(&output, b"precious")?;
    assert!(encrypt_file(&input, &input, "synthetic", 16, true, None).is_err());
    let alias = directory.path().join("hardlink");
    fs::hard_link(&input, &alias)?;
    assert!(encrypt_file(&input, &alias, "synthetic", 16, true, None).is_err());
    fs::remove_file(&alias)?;
    assert!(matches!(
        encrypt_file(&input, &output, "synthetic", 16, false, None),
        Err(Error::Invalid(message)) if message.contains("overwrite")
    ));
    let mut entered = false;
    let mut canceled = |_, _| {
        entered = true;
        Err(Error::Canceled)
    };
    assert!(matches!(
        encrypt_file(&input, &output, "synthetic", 16, true, Some(&mut canceled)),
        Err(Error::Canceled)
    ));
    assert!(entered, "encryption must reach the cancellation callback");
    assert_eq!(fs::read(&input)?, b"source");
    assert_eq!(fs::read(&output)?, b"precious");
    assert_no_staging(directory.path())?;
    Ok(())
}

fn assert_no_staging(directory: &Path) -> Result<()> {
    for file in fs::read_dir(directory)? {
        assert!(!file?.file_name().to_string_lossy().ends_with(".tmp"));
    }
    Ok(())
}

#[path = "common/private_tempfile.rs"]
mod private_tempfile;
