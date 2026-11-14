//! Retryability is an allowlist; typed cancellation/policy/integrity cannot become retries.
#![allow(clippy::unwrap_used)]

use megabasterd_cli::error::Error;

#[test]
fn deterministic_transfer_failures_are_final_but_network_reset_and_timeout_remain_retryable() {
    for (case, error, diagnostic) in [
        (
            "proxy-policy-refusal",
            Error::protocol("no proxy"),
            "Protocol error: no proxy",
        ),
        (
            "cancellation",
            Error::Canceled,
            "The operation was canceled.",
        ),
        (
            "protocol-violation",
            Error::protocol("range"),
            "Protocol error: range",
        ),
        (
            "integrity",
            Error::integrity("mac"),
            "Integrity check failed: mac",
        ),
        (
            "unclassified-base",
            Error::Transfer(Box::new(Error::protocol("unclassified"))),
            "Transfer failed: Protocol error: unclassified",
        ),
    ] {
        assert_eq!(
            error.to_string(),
            diagnostic,
            "source classifier case {case}"
        );
        assert!(!error.retryable_network(), "source classifier case {case}");
        assert!(
            !Error::transfer(error).retryable_network(),
            "reported source classifier case {case}"
        );
    }
    assert!(!Error::Unexpected.retryable_network());
    for kind in [
        std::io::ErrorKind::ConnectionReset,
        std::io::ErrorKind::ConnectionAborted,
        std::io::ErrorKind::TimedOut,
        std::io::ErrorKind::ConnectionRefused,
    ] {
        assert!(
            Error::Io(std::io::Error::new(kind, "controlled network failure")).retryable_network()
        );
    }
    assert!(Error::Timeout.retryable_network());
}
