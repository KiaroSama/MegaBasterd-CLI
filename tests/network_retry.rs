use megabasterd_cli::error::Error;
use std::io::{Error as IoError, ErrorKind};

#[test]
fn transfer_network_boundary_retries_transient_failures_but_not_protocol_or_local_errors() {
    for kind in [
        ErrorKind::TimedOut,
        ErrorKind::ConnectionReset,
        ErrorKind::ConnectionAborted,
        ErrorKind::ConnectionRefused,
        ErrorKind::BrokenPipe,
        ErrorKind::Interrupted,
    ] {
        assert!(Error::Io(IoError::new(kind, "synthetic network failure")).retryable_network());
    }
    assert!(Error::Timeout.retryable_network());
    for kind in [
        ErrorKind::UnexpectedEof,
        ErrorKind::InvalidData,
        ErrorKind::PermissionDenied,
        ErrorKind::NotFound,
        ErrorKind::AlreadyExists,
        ErrorKind::StorageFull,
    ] {
        assert!(
            !Error::Io(IoError::new(kind, "deterministic framing or local failure"))
                .retryable_network()
        );
    }
    for error in [
        Error::protocol("wrong Range or upload token"),
        Error::Transfer(Box::new(Error::protocol("unclassified transfer failure"))),
        Error::integrity("wrong MAC"),
        Error::Canceled,
        Error::AmbiguousMutation("p"),
        Error::mega(-11),
        Error::mega(-17),
        Error::Auth("TLS verification refused".into()),
        Error::Corrupt("preserve state".into()),
    ] {
        assert!(!error.retryable_network());
    }
}
