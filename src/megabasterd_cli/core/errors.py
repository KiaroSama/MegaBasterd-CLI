"""MEGA API error codes and exception types."""

from __future__ import annotations

# MEGA API negative error codes (returned as integers from the API)
ERROR_CODES = {
    -1: ("EINTERNAL", "Internal error"),
    -2: ("EARGS", "Invalid arguments"),
    -3: ("EAGAIN", "Try again"),
    -4: ("ERATELIMIT", "Rate limit exceeded"),
    -5: ("EFAILED", "Transfer failed"),
    -6: ("ETOOMANY", "Too many concurrent connections"),
    -7: ("ERANGE", "Out of range"),
    -8: ("EEXPIRED", "Resource expired"),
    -9: ("ENOENT", "Resource does not exist"),
    -10: ("ECIRCULAR", "Circular linkage"),
    -11: ("EACCESS", "Access denied"),
    -12: ("EEXIST", "Resource already exists"),
    -13: ("EINCOMPLETE", "Incomplete request"),
    -14: ("EKEY", "Cryptographic error"),
    -15: ("ESID", "Bad session ID"),
    -16: ("EBLOCKED", "Resource blocked"),
    -17: ("EOVERQUOTA", "Quota exceeded"),
    -18: ("ETEMPUNAVAIL", "Resource temporarily unavailable"),
    -19: ("ETOOMANYCONNECTIONS", "Too many connections"),
    -20: ("EWRITE", "Write error"),
    -21: ("EREAD", "Read error"),
    -22: ("EAPPKEY", "Invalid application key"),
    -24: ("EGOINGOVERQUOTA", "Bandwidth quota about to be exceeded"),
    -26: ("EMFAREQUIRED", "Multi-factor authentication required"),
    -29: ("EMASTERONLY", "Operation requires master key"),
}


class MegaError(Exception):
    """Base class for MEGA-related errors."""

    def __init__(self, code: int | None = None, message: str | None = None):
        self.code = code
        if code is not None and code in ERROR_CODES:
            name, default_msg = ERROR_CODES[code]
            self.name = name
            super().__init__(message or f"{name} ({code}): {default_msg}")
        else:
            self.name = "UNKNOWN"
            super().__init__(message or f"MEGA error {code}")


class TransferError(MegaError):
    """Error during a download or upload."""


class TransferCancelled(TransferError):  # noqa: N818 - a decision, not a fault
    """The user (or the caller) stopped the transfer before it completed.

    A distinct type because cancellation must never be reported as success and
    must never be retried: it is a deliberate decision, not a fault.
    """


class AuthError(MegaError):
    """Authentication / session-related error."""


class QuotaError(MegaError):
    """Quota exceeded."""


class RateLimitError(MegaError):
    """Rate limited; retry with backoff."""


class IntegrityError(MegaError):
    """File integrity check failed (MAC mismatch)."""


def raise_for_code(code: int) -> None:
    """Raise the most appropriate MegaError subclass for an API error code."""
    if code >= 0:
        return
    if code in (-15,):
        raise AuthError(code)
    if code in (-4,):
        raise RateLimitError(code)
    if code in (-17, -24):
        raise QuotaError(code)
    raise MegaError(code)
