"""File operations: split / merge / thumbnail."""

from __future__ import annotations

from pathlib import Path

import click

from ..core.splitter import SplitterError, merge_parts, split_file
from ..core.thumbnail import THUMB_SIZE, create_thumbnail
from ..ui.prompts import print_error, print_info, print_success
from ..utils.helpers import format_bytes


@click.command("split", short_help="Split a large file into part files with SHA-1.")
@click.argument("source", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("part_size_mb", type=int)
@click.option(
    "-o",
    "--output-dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Directory to write parts in (default: alongside source).",
)
def split_cmd(source: Path, part_size_mb: int, output_dir: Path | None) -> None:
    """Split SOURCE into parts of PART_SIZE_MB MiB each.

    Produces filename.part1-N ... filename.partN-N plus filename.sha1 for
    integrity verification on merge.
    """
    try:
        result = split_file(source, part_size_mb, output_dir=output_dir)
    except SplitterError as exc:
        print_error(str(exc))
        return
    print_success(
        f"Split {source.name} ({format_bytes(result.total_bytes)}) "
        f"into {len(result.parts)} part(s)"
    )
    for p in result.parts:
        click.echo(f"  {p.name}")
    print_info(f"SHA-1: {result.sha1}")


@click.command("merge", short_help="Merge a set of *.partN-M files (with SHA-1 verify).")
@click.argument("any_part", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "-o",
    "--output",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Output filename (default: strip .partN-M).",
)
@click.option(
    "--no-verify",
    is_flag=True,
    help="Skip SHA-1 verification.",
)
@click.option(
    "--delete-parts",
    is_flag=True,
    help="Delete part files on success.",
)
def merge_cmd(any_part: Path, output: Path | None, no_verify: bool, delete_parts: bool) -> None:
    """Merge any *.part<n>-<total> file with its siblings back into the original."""
    try:
        out = merge_parts(
            any_part,
            output=output,
            verify_sha1=not no_verify,
            delete_parts=delete_parts,
        )
    except SplitterError as exc:
        print_error(str(exc))
        return
    print_success(f"Merged to {out} ({format_bytes(out.stat().st_size)})")


@click.command("thumbnail", short_help="Create a JPEG thumbnail from an image.")
@click.argument("source", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("destination", type=click.Path(dir_okay=False, path_type=Path))
def thumbnail_cmd(source: Path, destination: Path) -> None:
    """Generate a thumbnail (max 250x250) suitable for MEGA file previews."""
    if create_thumbnail(source, destination):
        print_success(f"Thumbnail written: {destination} (max {THUMB_SIZE}x{THUMB_SIZE})")
    else:
        print_error(
            f"Could not generate thumbnail for {source.name} "
            "(unsupported format or Pillow not installed)."
        )
