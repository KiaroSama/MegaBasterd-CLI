// SPDX-License-Identifier: GPL-3.0-or-later
//! Local JPEG generation. Upload encryption/attribute registration belongs to the caller.
use std::{
    ffi::OsString,
    fs::File,
    io::{BufRead, BufReader, Cursor, Seek, SeekFrom, Write},
    path::Path,
    time::{Duration, Instant},
};

use image::{
    DynamicImage, GenericImageView, ImageReader, Limits, codecs::jpeg::JpegEncoder,
    imageops::FilterType,
};
use serde_json::Value;

use super::local_crypto::{StagedOutput, open_source, require_unchanged};
use crate::{
    error::{Error, Result},
    platform::process,
    transfers::control::Control,
};

pub const THUMB_SIZE: u32 = 250;
const MAX_INPUT_BYTES: u64 = 128 * 1024 * 1024;
const MAX_PIXELS: u64 = 32 * 1024 * 1024;
const MAX_DECODE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_JPEG_BYTES: usize = 1024 * 1024;
const MEDIA_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub struct Thumbnail {
    pub jpeg: Vec<u8>,
    pub width: u32,
    pub height: u32,
    pub warning: Option<String>,
}

fn limits() -> Limits {
    let mut limits = Limits::default();
    limits.max_image_width = Some(32_768);
    limits.max_image_height = Some(32_768);
    limits.max_alloc = Some(MAX_DECODE_BYTES);
    limits
}

fn reader<R: BufRead + Seek>(input: R) -> Result<ImageReader<R>> {
    let mut reader = ImageReader::new(input).with_guessed_format()?;
    reader.limits(limits());
    Ok(reader)
}

fn dimensions(width: u32, height: u32) -> Result<()> {
    if width == 0
        || height == 0
        || u64::from(width) * u64::from(height) > MAX_PIXELS
        || width > 32_768
        || height > 32_768
    {
        return Err(Error::invalid(
            "Media dimensions exceed the thumbnail decoder resource limit",
        ));
    }
    Ok(())
}

fn decode<R: BufRead + Seek>(input: R) -> Result<DynamicImage> {
    reader(input)?
        .decode()
        .map_err(|_| Error::invalid("Image is corrupt, unsupported, or exceeds decoder limits"))
}

fn thumbnail_dimensions(width: u32, height: u32) -> (u32, u32) {
    if width <= THUMB_SIZE && height <= THUMB_SIZE {
        return (width, height);
    }
    let aspect = f64::from(width) / f64::from(height);
    let choose = |value: f64, width_axis: bool| {
        let (floor, ceil) = (value.floor().max(1.0), value.ceil().max(1.0));
        let error = |n: f64| {
            if width_axis {
                (aspect - n / f64::from(THUMB_SIZE)).abs()
            } else {
                (aspect - f64::from(THUMB_SIZE) / n).abs()
            }
        };
        if error(floor) <= error(ceil) {
            floor as u32
        } else {
            ceil as u32
        }
    };
    if width <= height {
        (choose(f64::from(THUMB_SIZE) * aspect, true), THUMB_SIZE)
    } else {
        (THUMB_SIZE, choose(f64::from(THUMB_SIZE) / aspect, false))
    }
}

fn from_image(image: DynamicImage, warning: Option<String>) -> Result<Thumbnail> {
    dimensions(image.width(), image.height())?;
    // Match Pillow's closest-aspect floor/ceil selection and never enlarge small input.
    let size = thumbnail_dimensions(image.width(), image.height());
    let image = if size != image.dimensions() {
        image.resize_exact(size.0, size.1, FilterType::CatmullRom)
    } else {
        image
    };
    let rgb = image.to_rgb8();
    let (width, height) = rgb.dimensions();
    let mut jpeg = Vec::new();
    JpegEncoder::new_with_quality(&mut jpeg, 85)
        .encode_image(&rgb)
        .map_err(|_| Error::protocol("JPEG thumbnail encoding failed"))?;
    if jpeg.is_empty() || jpeg.len() > MAX_JPEG_BYTES {
        return Err(Error::invalid("Encoded thumbnail exceeds its output limit"));
    }
    Ok(Thumbnail {
        jpeg,
        width,
        height,
        warning,
    })
}

pub fn square(thumbnail: &Thumbnail) -> Result<Vec<u8>> {
    let image = decode(Cursor::new(&thumbnail.jpeg))?;
    let edge = image.width().min(image.height());
    let image = image
        .crop_imm(
            (image.width() - edge) / 2,
            (image.height() - edge) / 2,
            edge,
            edge,
        )
        .to_rgb8();
    let mut jpeg = Vec::new();
    JpegEncoder::new_with_quality(&mut jpeg, 85)
        .encode_image(&image)
        .map_err(|_| Error::protocol("Square thumbnail encoding failed"))?;
    if jpeg.is_empty() || jpeg.len() > MAX_JPEG_BYTES {
        return Err(Error::invalid("Square thumbnail exceeds its output limit"));
    }
    Ok(jpeg)
}

fn image_thumbnail(input: &mut File, control: &Control) -> Result<Thumbnail> {
    if input.metadata()?.len() > MAX_INPUT_BYTES {
        return Err(Error::invalid(
            "Image source exceeds the 128 MiB encoded-input limit",
        ));
    }
    let (width, height) = reader(BufReader::new(&mut *input))?
        .into_dimensions()
        .map_err(|_| Error::invalid("Cannot read image dimensions within decoder limits"))?;
    dimensions(width, height)?;
    input.seek(SeekFrom::Start(0))?;
    control.checkpoint()?;
    let image = decode(BufReader::new(input))?;
    control.checkpoint()?;
    from_image(image, None)
}

fn extension(source: &Path) -> Result<String> {
    source
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase())
        .ok_or_else(|| Error::invalid("Unsupported thumbnail file extension"))
}

fn media_format(extension: &str) -> Result<(&'static str, bool)> {
    match extension {
        "mp4" | "m4v" | "mov" | "3gp" => Ok(("mov", true)),
        "mkv" | "webm" => Ok(("matroska", true)),
        "avi" => Ok(("avi", true)),
        "mpeg" | "mpg" | "vob" => Ok(("mpeg", true)),
        "ts" | "m2ts" => Ok(("mpegts", true)),
        "flv" => Ok(("flv", true)),
        "wmv" | "asf" => Ok(("asf", true)),
        "mp3" => Ok(("mp3", false)),
        "flac" => Ok(("flac", false)),
        "m4a" | "m4b" => Ok(("mov", false)),
        "ogg" | "opus" => Ok(("ogg", false)),
        "wav" => Ok(("wav", false)),
        "aif" | "aiff" => Ok(("aiff", false)),
        _ => Err(Error::invalid("Unsupported thumbnail media type")),
    }
}

fn args(values: &[&str]) -> Vec<OsString> {
    values.iter().map(|value| OsString::from(*value)).collect()
}

fn input_protocol() -> &'static str {
    "fd"
}

fn input_url() -> &'static str {
    // This is the child's inherited regular-file stdin, not an arbitrary parent CRT descriptor.
    "fd:"
}

fn remaining(deadline: Instant) -> Result<Duration> {
    let duration = deadline.saturating_duration_since(Instant::now());
    if duration.is_zero() {
        Err(Error::Timeout)
    } else {
        Ok(duration)
    }
}

fn rewind_clone(input: &mut File) -> Result<File> {
    input.seek(SeekFrom::Start(0))?;
    Ok(input.try_clone()?)
}

fn media_thumbnail(
    input: &mut File,
    extension: &str,
    ffmpeg: &Path,
    control: &Control,
) -> Result<Thumbnail> {
    let (format, video) = media_format(extension)?;
    let deadline = Instant::now() + MEDIA_TIMEOUT;
    let probe = ffmpeg.with_file_name(if cfg!(windows) {
        "ffprobe.exe"
    } else {
        "ffprobe"
    });
    let probe_args = args(&[
        "-v",
        "error",
        "-max_alloc",
        "67108864",
        "-protocol_whitelist",
        input_protocol(),
        "-f",
        format,
        "-show_entries",
        "format=duration:stream=index,codec_type,width,height:stream_disposition=attached_pic",
        "-of",
        "json",
        input_url(),
    ]);
    let probe_result = process::run_with_input(
        &probe,
        &probe_args,
        remaining(deadline)?,
        16 * 1024,
        64 * 1024,
        control,
        rewind_clone(input)?,
    )?;
    if !probe_result.status.success() {
        return Err(Error::protocol(
            "Media probe failed; seekable fd stdin support and a readable media stream are required",
        ));
    }
    let metadata: Value = serde_json::from_slice(&probe_result.stdout)
        .map_err(|_| Error::protocol("Media probe returned invalid metadata"))?;
    let streams = metadata["streams"]
        .as_array()
        .ok_or_else(|| Error::protocol("Media probe has no streams"))?;
    let stream = streams
        .iter()
        .find(|stream| {
            stream["codec_type"] == "video"
                && if video {
                    stream["disposition"]["attached_pic"].as_u64() != Some(1)
                } else {
                    stream["disposition"]["attached_pic"].as_u64() == Some(1)
                }
        })
        .ok_or_else(|| {
            Error::invalid(if video {
                "Media contains no video stream"
            } else {
                "Audio contains no embedded cover artwork"
            })
        })?;
    let width = stream["width"]
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| Error::protocol("Media probe has no valid frame width"))?;
    let height = stream["height"]
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| Error::protocol("Media probe has no valid frame height"))?;
    dimensions(width, height)?;
    let index = stream["index"]
        .as_u64()
        .filter(|index| *index <= 1024)
        .ok_or_else(|| Error::protocol("Media stream index is invalid"))?;
    let mapping = format!("0:{index}");
    let duration = metadata["format"]["duration"]
        .as_str()
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|n| n.is_finite() && *n >= 0.0 && *n <= 31_536_000.0);
    let (seek, mut warning) = if !video {
        (0.0, None)
    } else if let Some(duration) = duration {
        ((duration * 0.03).round(), None)
    } else {
        (0.0, Some("Video duration is unavailable; thumbnail uses the first frame instead of the 3% position.".to_owned()))
    };
    let mut attempt = |hardware: &str| -> Result<process::ProcessOutput> {
        let mut options = args(&[
            "-nostdin",
            "-hide_banner",
            "-loglevel",
            "error",
            "-max_alloc",
            "67108864",
            "-threads",
            "2",
            "-filter_threads",
            "1",
            "-protocol_whitelist",
            input_protocol(),
            "-f",
            format,
            "-hwaccel",
            hardware,
        ]);
        if video {
            options.extend(args(&["-ss", &format!("{seek:.3}")]));
        }
        options.extend(args(&[
            "-i",
            input_url(),
            "-map",
            &mapping,
            "-frames:v",
            "1",
            "-threads",
            "2",
            "-an",
            "-sn",
            "-dn",
            "-vf",
            "scale='min(250,iw)':'min(250,ih)':force_original_aspect_ratio=decrease",
            "-f",
            "image2pipe",
            "-vcodec",
            "mjpeg",
            "pipe:1",
        ]));
        process::run_with_input(
            ffmpeg,
            &options,
            remaining(deadline)?,
            MAX_JPEG_BYTES,
            64 * 1024,
            control,
            rewind_clone(input)?,
        )
    };
    let mut output = attempt("auto")?;
    // ffmpeg auto selects a supported device and may itself use CPU when none is usable.
    if !output.status.success() {
        output = attempt("none")?;
        let fallback = "GPU-assisted frame decode failed or is unsupported; thumbnail used the bounded CPU fallback.";
        warning = Some(match warning {
            Some(warning) => format!("{warning} {fallback}"),
            None => fallback.into(),
        });
    }
    if !output.status.success() || output.stdout.is_empty() {
        return Err(Error::protocol(
            "Media frame extraction failed; no thumbnail was produced",
        ));
    }
    if warning.is_none() && video {
        warning = Some("Frame decode requested automatic hardware acceleration; ffmpeg may use CPU when no supported device is available.".into());
    }
    let mut encoded = Cursor::new(output.stdout);
    let (width, height) = reader(&mut encoded)?
        .into_dimensions()
        .map_err(|_| Error::protocol("Media decoder returned invalid image bytes"))?;
    dimensions(width, height)?;
    if width > THUMB_SIZE || height > THUMB_SIZE {
        return Err(Error::protocol(
            "Media decoder ignored thumbnail size bounds",
        ));
    }
    encoded.set_position(0);
    from_image(decode(encoded)?, warning)
}

fn generate(
    input: &mut File,
    source: &Path,
    ffmpeg: Option<&Path>,
    control: &Control,
) -> Result<Thumbnail> {
    control.checkpoint()?;
    let extension = extension(source)?;
    let before = input.metadata()?;
    let thumbnail = match extension.as_str() {
        "jpg" | "jpeg" | "png" | "gif" | "bmp" | "webp" | "tiff" => {
            image_thumbnail(input, control)?
        }
        _ => {
            media_format(&extension)?;
            let executable = ffmpeg.ok_or_else(|| Error::MissingTool("ffmpeg/ffprobe are required for local video/audio thumbnails; no installation was attempted".into()))?;
            media_thumbnail(input, &extension, executable, control)?
        }
    };
    require_unchanged(input, &before)?;
    control.checkpoint()?;
    Ok(thumbnail)
}

/// Single format classification shared with automatic attachment; the previous
/// duplicated extension allowlist silently dropped m4v and 3gp.
pub fn supports(extension: &str) -> bool {
    matches!(
        extension,
        "jpg" | "jpeg" | "png" | "gif" | "bmp" | "webp" | "tiff"
    ) || media_format(extension).is_ok()
}

/// Local bytes only; the caller owns optional encrypted media attribute upload.
pub fn generate_thumbnail(
    source: &Path,
    ffmpeg: Option<&Path>,
    control: &Control,
) -> Result<Thumbnail> {
    control.checkpoint()?;
    let (_directory, mut input) = open_source(source)?;
    generate(&mut input, source, ffmpeg, control)
}

/// Publishes only after generation succeeds, with explicit overwrite consent and alias checks.
pub fn create_thumbnail(
    source: &Path,
    destination: &Path,
    overwrite: bool,
    ffmpeg: Option<&Path>,
    control: &Control,
) -> Result<Thumbnail> {
    control.checkpoint()?;
    let (_directory, mut input) = open_source(source)?;
    let mut output = StagedOutput::new(destination, overwrite, &[&input])?;
    let thumbnail = generate(&mut input, source, ffmpeg, control)?;
    output.writer()?.write_all(&thumbnail.jpeg)?;
    control.checkpoint()?;
    output.commit(&[&input])?;
    Ok(thumbnail)
}
