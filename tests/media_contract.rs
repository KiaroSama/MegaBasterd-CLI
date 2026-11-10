#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use image::GenericImageView;
use megabasterd_cli::{services::thumbnails::generate_thumbnail, transfers::control::Control};
use sha2::{Digest, Sha256};

#[test]
fn maintained_mp4_and_webm_decode_through_owned_seekable_input_and_produce_green_jpeg() {
    let ffmpeg = std::env::var_os("MEGABASTERD_FFMPEG")
        .map(PathBuf::from)
        .expect("Native media CI must supply its verified ffmpeg/ffprobe pair");
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(".ci-work/media-codecs");
    std::fs::create_dir_all(&root).unwrap();
    let scratch = private_tempfile::tempdir_in(root).unwrap();
    for (extension, bytes, hash) in [
        (
            "mp4",
            include_bytes!("fixtures/media/2x2-green.mp4").as_slice(),
            "f2923f95cb1653b6bb1b63a91b50940809d94708d68a2f2065bcad320aed0ff5",
        ),
        (
            "webm",
            include_bytes!("fixtures/media/2x2-green.webm").as_slice(),
            "aff421ce65673c73ebee67c1e4a7bd45843a490d4715717c3ed6760d88776634",
        ),
    ] {
        assert_eq!(hex::encode(Sha256::digest(bytes)), hash);
        let source = scratch
            .path()
            .join(format!("green with spaces.{extension}"));
        std::fs::write(&source, bytes).unwrap();
        let thumbnail = generate_thumbnail(&source, Some(&ffmpeg), &Control::new()).unwrap();
        assert_eq!((thumbnail.width, thumbnail.height), (2, 2));
        assert!(thumbnail.jpeg.starts_with(&[0xff, 0xd8]));
        let image = image::load_from_memory(&thumbnail.jpeg).unwrap();
        assert_eq!(image.dimensions(), (2, 2));
        assert_eq!(image.color(), image::ColorType::Rgb8);
        for pixel in image.to_rgb8().pixels() {
            assert!(
                pixel.0[0] <= 12 && pixel.0[1] >= 110 && pixel.0[2] <= 12,
                "real codec thumbnail did not preserve the green frame"
            );
        }
        assert_eq!(std::fs::read(source).unwrap(), bytes);
        // A hosted CPU run is codec/process evidence, not a GPU benchmark or universal codec claim.
        assert!(
            thumbnail
                .warning
                .as_deref()
                .is_some_and(|warning| warning.contains("hardware acceleration")
                    || warning.contains("CPU fallback"))
        );
    }
}

#[path = "common/private_tempfile.rs"]
mod private_tempfile;
