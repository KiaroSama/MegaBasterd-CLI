use image::GenericImageView;
use megabasterd_cli::{
    error::{Error, Result},
    services::thumbnails::{create_thumbnail, generate_thumbnail},
    transfers::control::Control,
};
use serde_json::Value;
use std::{fs, path::Path};

#[test]
fn synthetic_source_image_dimensions_rgb_jpeg_and_no_upscale_are_preserved() -> Result<()> {
    let data: Value = serde_json::from_str(include_str!("fixtures/local_file_services.json"))?;
    let directory = tempfile::tempdir()?;
    let control = Control::new();
    for case in data["images"]
        .as_array()
        .ok_or_else(|| Error::invalid("Image fixtures"))?
    {
        let source = directory.path().join("input.PNG");
        fs::write(
            &source,
            hex::decode(case["input_png_hex"].as_str().unwrap_or_default())
                .map_err(|_| Error::invalid("Fixture hex"))?,
        )?;
        let result = generate_thumbnail(&source, None, &control)?;
        let decoded = image::load_from_memory(&result.jpeg)
            .map_err(|_| Error::invalid("Invalid JPEG output"))?;
        assert_eq!(
            decoded.dimensions(),
            (
                case["width"].as_u64().unwrap_or_default() as u32,
                case["height"].as_u64().unwrap_or_default() as u32
            )
        );
        assert_eq!(decoded.color(), image::ColorType::Rgb8);
        assert!(result.jpeg.starts_with(&[0xff, 0xd8]));
        assert_eq!((result.width, result.height), decoded.dimensions());
        assert!(result.warning.is_none());
        // Encoders differ: dimensions, JPEG/RGB and representative colors are the public contract,
        // not Pillow's exact quantized file hash.
        if case["name"] != "tall" {
            let pixel = decoded
                .to_rgb8()
                .get_pixel(result.width / 2, result.height / 2)
                .0;
            for (actual, expected) in pixel.into_iter().zip([60u8, 120, 180]) {
                assert!(actual.abs_diff(expected) <= 4);
            }
        }
    }
    Ok(())
}

#[test]
fn publication_requires_overwrite_and_refuses_input_aliases() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let data: Value = serde_json::from_str(include_str!("fixtures/local_file_services.json"))?;
    let source = directory.path().join("input.png");
    fs::write(
        &source,
        hex::decode(
            data["images"][1]["input_png_hex"]
                .as_str()
                .unwrap_or_default(),
        )
        .map_err(|_| Error::invalid("Fixture hex"))?,
    )?;
    let before = fs::read(&source)?;
    let control = Control::new();
    assert!(create_thumbnail(&source, &source, true, None, &control).is_err());
    let alias = directory.path().join("alias.jpg");
    fs::hard_link(&source, &alias)?;
    assert!(create_thumbnail(&source, &alias, true, None, &control).is_err());
    let output = directory.path().join("thumbnail.jpg");
    fs::write(&output, b"precious")?;
    assert!(create_thumbnail(&source, &output, false, None, &control).is_err());
    assert_eq!(fs::read(&output)?, b"precious");
    let result = create_thumbnail(&source, &output, true, None, &control)?;
    assert_eq!(fs::read(output)?, result.jpeg);
    assert_eq!(fs::read(source)?, before);
    Ok(())
}

#[test]
fn unsupported_corrupt_and_missing_ffmpeg_are_errors_not_fake_thumbnail_success() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let control = Control::new();
    for name in ["unknown.txt", "corrupt.png"] {
        let source = directory.path().join(name);
        fs::write(&source, b"not media")?;
        assert!(generate_thumbnail(&source, None, &control).is_err());
    }
    let video = directory.path().join("movie.mp4");
    fs::write(&video, b"synthetic-not-a-real-codec-fixture")?;
    assert!(matches!(
        generate_thumbnail(&video, None, &control),
        Err(Error::MissingTool(_))
    ));
    let output = directory.path().join("precious.jpg");
    fs::write(&output, b"precious")?;
    assert!(create_thumbnail(&video, &output, true, None, &control).is_err());
    assert_eq!(fs::read(output)?, b"precious");
    Ok(())
}

#[test]
fn decoder_bounds_refuse_extreme_dimensions_before_large_allocation() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let source = directory.path().join("huge.bmp");
    let mut header = vec![0u8; 54];
    header[..2].copy_from_slice(b"BM");
    header[2..6].copy_from_slice(&54u32.to_le_bytes());
    header[10..14].copy_from_slice(&54u32.to_le_bytes());
    header[14..18].copy_from_slice(&40u32.to_le_bytes());
    header[18..22].copy_from_slice(&50000u32.to_le_bytes());
    header[22..26].copy_from_slice(&50000u32.to_le_bytes());
    header[26..28].copy_from_slice(&1u16.to_le_bytes());
    header[28..30].copy_from_slice(&24u16.to_le_bytes());
    fs::write(&source, header)?;
    assert!(generate_thumbnail(&source, None, &Control::new()).is_err());
    Ok(())
}

#[test]
fn pre_canceled_generator_does_not_publish_any_output() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let control = Control::new();
    control.cancel();
    let source = directory.path().join("input.png");
    fs::write(&source, b"not media")?;
    let output = directory.path().join("output.jpg");
    assert!(matches!(
        create_thumbnail(&source, &output, false, None, &control),
        Err(Error::Canceled)
    ));
    assert!(!output.exists());
    no_staging(directory.path())?;
    Ok(())
}

fn no_staging(directory: &Path) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        assert!(!entry?.file_name().to_string_lossy().ends_with(".tmp"));
    }
    Ok(())
}
