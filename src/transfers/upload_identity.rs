//! Streaming upload content identity; the caller retains native file and metadata ownership.
use std::io::Read;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::control::Control;
use crate::error::Result;

pub(super) fn digest(reader: &mut impl Read, control: &Control) -> Result<[u8; 32]> {
    let mut sha = Sha256::new();
    let mut buffer = Zeroizing::new(vec![0; 1024 * 1024]);
    loop {
        control.checkpoint()?;
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        sha.update(&buffer[..count]);
    }
    Ok(sha.finalize().into())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::error::Error;
    use std::io;

    struct Source {
        remaining: usize,
        maximum: usize,
        reads: usize,
        short_reads: bool,
        cancel: Option<Control>,
    }

    impl Read for Source {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            assert!(!output.is_empty());
            self.maximum = self.maximum.max(output.len());
            assert!(
                output.len() <= 1024 * 1024,
                "hash read requested more than its bounded block"
            );
            self.reads += 1;
            let count = self.remaining.min(if self.short_reads {
                output.len() / 3
            } else {
                output.len()
            });
            output[..count].fill(0xab);
            self.remaining -= count;
            if let Some(control) = self.cancel.take() {
                control.cancel();
            }
            Ok(count)
        }
    }

    #[test]
    fn full_source_digest_uses_bounded_blocks_and_handles_short_reads() {
        for short_reads in [false, true] {
            let mut source = Source {
                remaining: 5 * 1024 * 1024,
                maximum: 0,
                reads: 0,
                short_reads,
                cancel: None,
            };
            let result = digest(&mut source, &Control::new()).unwrap();
            // Independently computed with CPython hashlib over the original source fixture.
            assert_eq!(
                hex::encode(result),
                "c0da77bb73f7fc617d3940f6ddd0cdb4e61f8a8beefadbcdad3f6d678eb4e3ab"
            );
            assert_eq!(source.remaining, 0);
            assert!(source.maximum > 0 && source.maximum <= 1024 * 1024);
            assert_eq!(source.reads, if short_reads { 17 } else { 6 });
        }
    }

    #[test]
    fn cancellation_between_hash_reads_and_local_failures_remain_typed() {
        let control = Control::new();
        let mut source = Source {
            remaining: 5 * 1024 * 1024,
            maximum: 0,
            reads: 0,
            short_reads: false,
            cancel: Some(control.clone()),
        };
        let error = digest(&mut source, &control).unwrap_err();
        assert!(matches!(error, Error::Canceled));
        assert_eq!(error.exit_code(), 130);
        assert_eq!(source.reads, 1, "hash read again after cancellation");
        assert_eq!(source.remaining, 4 * 1024 * 1024);
        struct Failure;
        impl Read for Failure {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "synthetic held-source read refusal",
                ))
            }
        }
        let error = digest(&mut Failure, &Control::new()).unwrap_err();
        assert!(
            matches!(&error,Error::Io(cause) if cause.kind() == io::ErrorKind::PermissionDenied)
        );
        assert!(!error.retryable_network());
    }
}
