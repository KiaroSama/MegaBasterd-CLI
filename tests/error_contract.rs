#![allow(clippy::unwrap_used)]

use std::error::Error as _;

use megabasterd_cli::error::Error;

#[test]
fn transfer_adapter_preserves_stable_machine_code_and_underlying_failure() {
    for original in [
        Error::protocol("CDN framing rejected"),
        Error::Timeout,
        Error::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "controlled reset",
        )),
    ] {
        let message = original.to_string();
        let wrapped = Error::transfer(original);
        assert_eq!(wrapped.code(), "transfer_failed");
        assert_eq!(wrapped.exit_code(), 1);
        assert!(wrapped.source().unwrap().to_string().contains(&message));
        assert!(
            !wrapped.retryable_network(),
            "adapter cannot introduce replay eligibility"
        );
        assert_eq!(Error::transfer(wrapped).code(), "transfer_failed");
    }
}

#[test]
fn stable_error_codes_include_the_unclassified_failure_fallback() {
    for (error, code) in [
        (Error::mega(-17), "quota_exceeded"),
        (
            Error::transfer(Error::protocol("controlled transfer failure")),
            "transfer_failed",
        ),
        (
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "controlled missing file",
            )),
            "local_file_missing",
        ),
        (Error::Unexpected, "error"),
    ] {
        assert_eq!(error.code(), code);
        assert_eq!(error.exit_code(), 1);
        assert!(!error.retryable_network());
    }
    assert_eq!(
        Error::Unexpected.to_string(),
        "Native command failed unexpectedly; diagnostic state was preserved"
    );
}

#[test]
fn transfer_reporting_keeps_specific_outcomes_and_does_not_turn_usage_into_transfer_failure() {
    for (error, code, exit) in [
        (Error::mega(-17), "quota_exceeded", 1),
        (Error::mega(-24), "quota_exceeded", 1),
        (Error::mega(-4), "rate_limited", 1),
        (Error::mega(-11), "mega_error", 1),
        (Error::Auth("controlled".into()), "auth_failed", 1),
        (Error::integrity("controlled"), "integrity_failed", 1),
        (Error::Canceled, "cancelled", 130),
        (Error::AmbiguousMutation("p"), "ambiguous_mutation", 1),
        (Error::invalid("controlled"), "invalid_input", 2),
        (Error::Corrupt("controlled".into()), "storage_corrupt", 1),
        (
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "controlled",
            )),
            "local_file_missing",
            1,
        ),
    ] {
        let reported = Error::transfer(error);
        assert_eq!(reported.code(), code);
        assert_eq!(reported.exit_code(), exit);
    }
    assert_eq!(
        Error::protocol("metadata response").code(),
        "protocol_error"
    );
    assert!(
        Error::mega(-24)
            .to_string()
            .contains("Not enough storage quota")
    );
    assert!(!Error::mega(-24).to_string().contains("Unknown"));
}
