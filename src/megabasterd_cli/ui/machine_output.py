"""Machine-readable JSONL result output for `--json` mode.

In machine mode, stdout carries ONLY structured records (one JSON object per
line); every human-facing message and progress frame goes to stderr, so a
caller such as EVdlc can parse stdout without scraping UI text. Records never
contain passwords, keys, SIDs, vault passphrases, or unredacted link keys —
every field is passed through the central recursive sanitizer first.
"""

from __future__ import annotations

import json
import sys
import threading

from ..utils.redaction import sanitize

# Stable machine-readable error codes, so EVdlc can branch without parsing
# free-text messages. Mapped from the internal error class name.
_ERROR_CODES = {
    "QuotaError": "quota_exceeded",
    "AuthError": "auth_failed",
    "IntegrityError": "integrity_failed",
    "RateLimitError": "rate_limited",
    "TransferError": "transfer_failed",
    "MegaError": "mega_error",
    "FileNotFoundError": "local_file_missing",
    "SelectionCancelled": "selection_cancelled",
}


def error_code_for(exc: BaseException) -> str:
    """Map an exception to a stable machine-readable error code."""
    for cls in type(exc).__mro__:
        if cls.__name__ in _ERROR_CODES:
            return _ERROR_CODES[cls.__name__]
    return "error"


class MachineOutput:
    """Thread-safe JSONL emitter bound to the REAL stdout.

    Construct it BEFORE redirecting the command's stdout to stderr: the
    emitter keeps writing records to the original stream while all human
    output is routed away from it. Every record is sanitized (recursively)
    and written as one atomic ``dumps(...) + "\\n"`` under a lock, so
    concurrent download/upload workers can never interleave partial lines.
    """

    def __init__(self, enabled: bool):
        self.enabled = enabled
        self._stream = sys.stdout
        self._lock = threading.Lock()

    def emit(self, **record) -> None:
        if not self.enabled:
            return
        payload = {key: value for key, value in record.items() if value is not None}
        # Recursively redact secrets (nested dicts/lists too) BEFORE encoding.
        clean = sanitize(payload)
        line = json.dumps(clean, ensure_ascii=False) + "\n"
        # One complete line per lock hold: never split a record across writes.
        with self._lock:
            self._stream.write(line)
            self._stream.flush()
