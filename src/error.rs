use std::fmt;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid input: {0}")]
    Invalid(String),
    #[error("Protocol error: {0}")]
    Protocol(String),
    #[error("Integrity check failed: {0}")]
    Integrity(String),
    #[error("Transfer failed: {0}")]
    Transfer(#[source] Box<Error>),
    #[error("MEGA rejected the operation ({code}): {message}")]
    Mega { code: i64, message: &'static str },
    #[error("Authentication failed: {0}")]
    Auth(String),
    #[error("Saved data is unusable and was preserved: {0}")]
    Corrupt(String),
    #[error(
        "The operation ({0}) may have reached MEGA; it was not replayed. Recheck remote state."
    )]
    AmbiguousMutation(&'static str),
    #[error("The operation was canceled.")]
    Canceled,
    #[error("{0} is already in use.")]
    Busy(String),
    #[error("Required tool is unavailable: {0}")]
    MissingTool(String),
    #[error("The operation exceeded its time limit.")]
    Timeout,
    #[error("Native command failed unexpectedly; diagnostic state was preserved")]
    Unexpected,
    #[error("I/O operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("HTTP operation failed; check connectivity, TLS and configured routing.")]
    Http(#[from] reqwest::Error),
    #[error("Invalid JSON document: {0}")]
    Json(#[from] serde_json::Error),
}

impl Error {
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }

    pub fn protocol(message: impl Into<String>) -> Self {
        Self::Protocol(message.into())
    }

    pub fn integrity(message: impl Into<String>) -> Self {
        Self::Integrity(message.into())
    }

    pub fn mega(code: i64) -> Self {
        let message = match code {
            -1 => "Internal service error",
            -2 => "Invalid arguments",
            -3 => "Temporary service failure",
            -4 => "Rate limit exceeded",
            -5 => "Transfer failed",
            -6 => "Too many concurrent connections",
            -7 => "Out of range",
            -8 => "Transfer expired",
            -9 => "Object not found",
            -10 => "Circular reference",
            -11 => "Access denied",
            -12 => "Object already exists",
            -13 => "Incomplete operation",
            -14 => "Key error",
            -15 => "Session expired",
            -16 => "Account blocked",
            -17 => "Quota exceeded",
            -18 => "Temporarily unavailable",
            -19 => "Too many connections",
            -20 => "Write failed",
            -21 => "Read failed",
            -22 => "Invalid application key",
            -24 => "Not enough storage quota",
            -26 => "Two-factor authentication required",
            _ => "Unknown service error",
        };
        Self::Mega { code, message }
    }

    /// Apply only after a transfer worker failed, never before network retry classification.
    pub fn transfer(cause: Self) -> Self {
        match cause {
            Self::Protocol(_) | Self::Timeout => Self::Transfer(Box::new(cause)),
            Self::Io(ref error) if error.kind() != std::io::ErrorKind::NotFound => {
                Self::Transfer(Box::new(cause))
            }
            Self::Http(_) => Self::Transfer(Box::new(cause)),
            _ => cause,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "invalid_input",
            Self::Protocol(_) => "protocol_error",
            Self::Integrity(_) => "integrity_failed",
            Self::Transfer(_) => "transfer_failed",
            Self::Mega {
                code: -17 | -24, ..
            } => "quota_exceeded",
            Self::Mega { code: -4, .. } => "rate_limited",
            Self::Mega {
                code: -15 | -26, ..
            }
            | Self::Auth(_) => "auth_failed",
            Self::Mega { .. } => "mega_error",
            Self::Corrupt(_) => "storage_corrupt",
            Self::AmbiguousMutation(_) => "ambiguous_mutation",
            Self::Canceled => "cancelled",
            Self::Busy(_) => "resource_busy",
            Self::MissingTool(_) => "missing_tool",
            Self::Timeout => "timeout",
            Self::Unexpected => "error",
            Self::Io(error) if error.kind() == std::io::ErrorKind::NotFound => "local_file_missing",
            Self::Io(_) => "io_error",
            Self::Http(_) => "network_error",
            Self::Json(_) => "invalid_json",
        }
    }

    /// Only for errors obtained at a network send/read boundary, never local file I/O.
    pub fn retryable_network(&self) -> bool {
        match self {
            Self::Timeout => true,
            Self::Http(error) => retryable_http(error),
            Self::Io(error) => {
                matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::Interrupted
                ) || error
                    .get_ref()
                    .and_then(|cause| cause.downcast_ref::<reqwest::Error>())
                    .is_some_and(retryable_http)
            }
            _ => false,
        }
    }

    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Canceled => 130,
            Self::Invalid(_) => 2,
            _ => 1,
        }
    }
}

pub(crate) fn retryable_http(error: &reqwest::Error) -> bool {
    use std::error::Error as _;
    use std::io::ErrorKind;

    if error.is_timeout() || error.is_connect() {
        return true;
    }
    let mut source = error.source();
    for _ in 0..16 {
        let Some(cause) = source else { return false };
        if let Some(error) = cause.downcast_ref::<hyper::Error>() {
            if error.is_parse() || error.is_user() {
                return false;
            }
            if error.is_incomplete_message() || error.is_closed() || error.is_timeout() {
                return true;
            }
        }
        if let Some(error) = cause.downcast_ref::<std::io::Error>()
            && matches!(
                error.kind(),
                ErrorKind::UnexpectedEof
                    | ErrorKind::TimedOut
                    | ErrorKind::ConnectionReset
                    | ErrorKind::ConnectionAborted
                    | ErrorKind::ConnectionRefused
                    | ErrorKind::BrokenPipe
                    | ErrorKind::Interrupted
            )
        {
            return true;
        }
        source = cause.source();
    }
    false
}

pub fn poisoned<T>(_: std::sync::PoisonError<T>) -> Error {
    Error::protocol("Shared state was interrupted; refusing to continue")
}

pub fn context(what: &str, cause: impl fmt::Display) -> Error {
    Error::protocol(format!("{what}: {cause}"))
}
