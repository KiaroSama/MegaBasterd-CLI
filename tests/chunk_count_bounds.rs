//! Counting hostile declared sizes does not construct a chunk plan or allocate proportional memory.
#![allow(clippy::unwrap_used)]

use megabasterd_cli::crypto::chunks::{MAX_CHUNKS, MAX_FILE_SIZE, chunk_count};

#[test]
fn range_selection_keeps_only_overlapping_chunks_and_the_full_range_keeps_every_chunk() {
    use megabasterd_cli::crypto::chunks::{Chunk, chunks_for_range, iter_chunks};

    let size = 10 * 1024 * 1024;
    let window = chunks_for_range(size, 200_000, 500_000).unwrap();
    assert_eq!(
        window,
        [
            Chunk {
                index: 1,
                offset: 131_072,
                size: 262_144,
            },
            Chunk {
                index: 2,
                offset: 393_216,
                size: 393_216,
            },
        ]
    );
    assert!(
        window
            .iter()
            .all(|chunk| chunk.end().unwrap() > 200_000 && chunk.offset < 500_000)
    );
    assert_eq!(
        chunks_for_range(size, 0, size).unwrap(),
        iter_chunks(size).unwrap().collect::<Vec<_>>()
    );
}

#[test]
fn direct_chunk_count_matches_independent_boundary_literals_and_refuses_hostile_sizes() {
    for (size, expected) in [
        (0, 0),
        (1, 1),
        (131072, 1),
        (131073, 2),
        (393216, 2),
        (393217, 3),
        (1_048_576, 4),
        (4_718_592, 8),
        (5_242_880, 9),
        (12_582_912, 16),
        (4_718_593, 9),
        (MAX_FILE_SIZE, MAX_CHUNKS),
    ] {
        assert_eq!(chunk_count(size).unwrap(), expected);
    }
    for size in [0, 1, 131_072, 1_048_576, 5_242_880, 12_582_912] {
        assert_eq!(
            chunk_count(size).unwrap(),
            megabasterd_cli::crypto::chunks::iter_chunks(size)
                .unwrap()
                .count()
        );
    }
    for hostile in [MAX_FILE_SIZE + 1, 1u64 << 50, u64::MAX] {
        assert!(chunk_count(hostile).is_err());
    }
    let implementation = include_str!("../src/crypto/chunks.rs");
    let count = implementation
        .split_once("pub fn chunk_count(file_size: u64) -> Result<usize> {")
        .unwrap()
        .1
        .split_once("pub struct Chunks {")
        .unwrap()
        .0;
    assert!(count.contains("validate_size(file_size)?;"));
    assert_eq!(count.matches("for ").count(), 1);
    assert!(count.contains("for size in CHUNK_SIZES_KB {"));
    assert!(count.contains(".div_ceil(MAX_CHUNK_SIZE)"));
    for enumeration in ["iter_chunks(", ".collect", "Vec", "while "] {
        assert!(!count.contains(enumeration));
    }
}
